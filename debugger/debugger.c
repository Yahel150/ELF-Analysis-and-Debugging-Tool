#define _POSIX_C_SOURCE 200809L

#include "debugger.h"

#ifndef __linux__
#error "xdbg debugger backend requires Linux"
#endif

#include "../dwarf/source_map.h"
#include "../tui/tui.h"
#include "live_got.h"
#include "memory.h"
#include "signals.h"
#include "singlestep.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void xdbg_got_check_watches(xdbg_session_t *session);

static void xdbg_session_init(xdbg_session_t *session) {
    memset(session, 0, sizeof(*session));
    session->pid = -1;
    session->state = XDBG_SESSION_IDLE;
    session->layout = XDBG_LAYOUT_ASM;
    session->program_base = 0;
    session->output_fd = -1;
    session->pending_signal = 0;
    xdbg_breakpoint_table_init(&session->breakpoints);
    snprintf(session->last_status, sizeof(session->last_status), "ready");
}

static void xdbg_append_program_output(xdbg_session_t *session, const char *data, size_t size) {
    size_t used;

    if (!session || !data || size == 0) return;
    used = strlen(session->program_output);
    if (size >= sizeof(session->program_output)) {
        data += size - (sizeof(session->program_output) - 1);
        size = sizeof(session->program_output) - 1;
        used = 0;
    } else if (used + size >= sizeof(session->program_output)) {
        size_t keep = sizeof(session->program_output) - size - 1;
        memmove(session->program_output, session->program_output + used - keep, keep);
        used = keep;
    }
    memcpy(session->program_output + used, data, size);
    session->program_output[used + size] = '\0';
}

static void xdbg_close_program_output(xdbg_session_t *session) {
    if (!session || session->output_fd < 0) return;
    close(session->output_fd);
    session->output_fd = -1;
}

static void xdbg_drain_program_output(xdbg_session_t *session) {
    char buffer[512];

    if (!session || session->output_fd < 0) return;
    while (1) {
        ssize_t n = read(session->output_fd, buffer, sizeof(buffer));
        if (n > 0) {
            xdbg_append_program_output(session, buffer, (size_t)n);
            if (!session->tui_enabled) {
                fwrite(buffer, 1, (size_t)n, stdout);
                fflush(stdout);
            }
            continue;
        }
        if (n == 0) {
            xdbg_close_program_output(session);
        }
        break;
    }
}

static void xdbg_close_loaded_elf(xdbg_session_t *session) {
    if (!session->has_elf) return;
    elf_close_file(&session->elf);
    session->has_elf = 0;
}

static int xdbg_load_program_elf(xdbg_session_t *session, const char *path) {
    xdbg_close_loaded_elf(session);
    if (!path || !path[0]) return -1;
    if (elf_open_file(path, &session->elf) != 0) return -1;
    session->has_elf = 1;
    snprintf(session->program_path, sizeof(session->program_path), "%s", path);
    return 0;
}

static uint64_t xdbg_module_bias(const xdbg_session_t *session) {
    if (!session || !session->has_elf) return 0;
    if (session->elf.ehdr && session->elf.ehdr->e_type == ET_DYN) {
        return session->program_base;
    }
    return 0;
}

static uint64_t xdbg_normalize_runtime_address(const xdbg_session_t *session, uint64_t address) {
    uint64_t bias = xdbg_module_bias(session);
    if (bias != 0 && address >= bias) return address - bias;
    return address;
}

static int xdbg_runtime_address_in_section(const xdbg_session_t *session,
                                           uint64_t address,
                                           const char *section_name) {
    const Elf64_Shdr *section;
    uint64_t normalized;

    if (!session || !session->has_elf || !section_name) return 0;
    section = elf_find_section_by_name(&session->elf, section_name);
    if (!section) return 0;
    normalized = xdbg_normalize_runtime_address(session, address);
    return normalized >= section->sh_addr && normalized < section->sh_addr + section->sh_size;
}

static int xdbg_runtime_address_in_user_text(const xdbg_session_t *session, uint64_t address) {
    return xdbg_runtime_address_in_section(session, address, ".text");
}

static int xdbg_runtime_address_in_plt(const xdbg_session_t *session, uint64_t address) {
    return xdbg_runtime_address_in_section(session, address, ".plt") ||
           xdbg_runtime_address_in_section(session, address, ".plt.got") ||
           xdbg_runtime_address_in_section(session, address, ".plt.sec");
}

static int xdbg_refresh_program_base(xdbg_session_t *session) {
    char maps_path[64];
    FILE *maps;
    char line[1024];

    if (!session || session->pid <= 0 || !session->program_path[0]) return -1;
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", session->pid);
    maps = fopen(maps_path, "r");
    if (!maps) return -1;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        unsigned long long offset = 0;
        char perms[8] = {0};
        char path[512] = {0};
        int fields = sscanf(line, "%llx-%llx %7s %llx %*s %*s %511s",
                            &start, &end, perms, &offset, path);
        (void)end;
        if (fields < 4) continue;
        if (fields < 5) continue;
        if (strstr(path, session->program_path) == NULL) continue;
        if (offset != 0) continue;
        session->program_base = (uint64_t)start;
        fclose(maps);
        return 0;
    }
    fclose(maps);
    return -1;
}

static int xdbg_refresh_program_path_and_elf(xdbg_session_t *session) {
    char exe_link[64];
    char resolved[260];
    ssize_t size;

    if (!session || session->pid <= 0) return -1;
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", session->pid);
    size = readlink(exe_link, resolved, sizeof(resolved) - 1);
    if (size <= 0) return -1;
    resolved[size] = '\0';
    return xdbg_load_program_elf(session, resolved);
}

static void xdbg_note_status(xdbg_session_t *session, const char *text) {
    if (!session || !text) return;
    snprintf(session->last_status, sizeof(session->last_status), "%s", text);
    if (session->tui_enabled) xdbg_tui_render(session);
}

static void xdbg_signal_forwarder(int signal_number, void *userdata) {
    xdbg_session_t *session = (xdbg_session_t *)userdata;

    if (session && session->pid > 0 && session->state == XDBG_SESSION_RUNNING) {
        kill(session->pid, signal_number);
    }
}

static int xdbg_fetch_instruction(xdbg_session_t *session) {
    uint8_t bytes[16];

    if (!session || session->pid <= 0) return -1;
    if (xdbg_get_registers(session->pid, &session->regs) != 0) return -1;
    if (xdbg_read_process_memory(session->pid, session->regs.rip, bytes, sizeof(bytes)) != 0) return -1;
    if (x86_decode_instruction(bytes, sizeof(bytes), session->regs.rip, &session->current_instruction) != 0) {
        memset(&session->current_instruction, 0, sizeof(session->current_instruction));
        session->current_instruction.address = session->regs.rip;
        snprintf(session->current_instruction.text, sizeof(session->current_instruction.text), "db ?");
    }
    xdbg_source_map_resolve(session, session->regs.rip, &session->current_source);
    return 0;
}

static void xdbg_print_prompt(const xdbg_session_t *session) {
    if (!session->tui_enabled) {
        printf("xdbg> ");
        fflush(stdout);
    }
}

static void xdbg_trim_command(char *buffer) {
    size_t len;

    if (!buffer) return;
    len = strlen(buffer);
    while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r' ||
                       buffer[len - 1] == ' ' || buffer[len - 1] == '\t')) {
        buffer[--len] = '\0';
    }
}

static const char *xdbg_command_history_at(const xdbg_session_t *session, size_t index) {
    size_t start;

    if (!session || index >= session->command_history_count) return "";
    start = (session->command_history_next + XDBG_COMMAND_HISTORY_SIZE - session->command_history_count) %
            XDBG_COMMAND_HISTORY_SIZE;
    return session->command_history[(start + index) % XDBG_COMMAND_HISTORY_SIZE];
}

static void xdbg_note_command_history(xdbg_session_t *session, const char *command_text) {
    char trimmed[256];

    if (!session || !command_text) return;
    snprintf(trimmed, sizeof(trimmed), "%s", command_text);
    xdbg_trim_command(trimmed);
    if (trimmed[0] == '\0') return;

    snprintf(session->command_history[session->command_history_next],
             sizeof(session->command_history[session->command_history_next]),
             "%s",
             trimmed);
    session->command_history_next = (session->command_history_next + 1) % XDBG_COMMAND_HISTORY_SIZE;
    if (session->command_history_count < XDBG_COMMAND_HISTORY_SIZE) {
        session->command_history_count += 1;
    }
}

static void xdbg_redraw_prompt_input(const char *buffer) {
    printf("\r\033[2Kxdbg> %s", buffer ? buffer : "");
    fflush(stdout);
}

static int xdbg_prompt_load_history(xdbg_session_t *session,
                                    size_t *history_cursor,
                                    int direction,
                                    char *buffer,
                                    size_t buffer_size,
                                    size_t *used) {
    const char *entry;

    if (!session || !history_cursor || !buffer || !used || session->command_history_count == 0) return 0;
    if (direction < 0) {
        if (*history_cursor > 0) *history_cursor -= 1;
    } else {
        if (*history_cursor + 1 < session->command_history_count) {
            *history_cursor += 1;
        } else {
            *history_cursor = session->command_history_count;
            buffer[0] = '\0';
            *used = 0;
            xdbg_redraw_prompt_input(buffer);
            return 1;
        }
    }

    entry = xdbg_command_history_at(session, *history_cursor);
    snprintf(buffer, buffer_size, "%s", entry);
    *used = strlen(buffer);
    if (*used >= buffer_size) *used = buffer_size - 1;
    xdbg_redraw_prompt_input(buffer);
    return 1;
}

static int xdbg_command_is(const char *command, const char *long_name, const char *short_name) {
    if (!command || !long_name) return 0;
    return strcmp(command, long_name) == 0 || (short_name && strcmp(command, short_name) == 0);
}

static void xdbg_print_debugger_help(void) {
    printf("Debugger commands:\n");
    printf("  run [program] [args...]        Start or restart the target program.\n");
    printf("  attach <pid>                   Attach to an existing Linux process.\n");
    printf("  break <addr|symbol>            Set a breakpoint.\n");
    printf("  tbreak <addr|symbol>           Set a temporary breakpoint.\n");
    printf("  delete <id>                    Delete a breakpoint.\n");
    printf("  enable <id> / disable <id>     Toggle a breakpoint.\n");
    printf("  continue | c                   Continue execution.\n");
    printf("  stepi | si                     Single-step one instruction.\n");
    printf("  nexti | ni                     Step over call-like instructions.\n");
    printf("  step | s                       Step to the next source line.\n");
    printf("  next | n                       Step source line, stepping over calls.\n");
    printf("  skip | sk                      Continue out of PLT/lib/no-source code.\n");
    printf("  finish | fin                   Run until the current function returns.\n");
    printf("  disassemble                    Decode instructions at RIP.\n");
    printf("  x[/fmt] <addr>                 Examine memory.\n");
    printf("  info regs|breakpoints          Show registers or breakpoints.\n");
    printf("  got <symbol>                   Read a live GOT slot.\n");
    printf("  got watch <symbol>             Report GOT slot changes after stops.\n");
    printf("  plt demo <symbol>              Step over a call and show lazy binding.\n");
    printf("  syscall                        Continue while stopping on syscalls.\n");
    printf("  bt                             Print a frame-pointer backtrace.\n");
    printf("  tui                            Enable the ncurses interface.\n");
    printf("  layout src|asm|split           Choose the TUI layout.\n");
    printf("  quit | q                       Leave the debugger.\n");
}

static int xdbg_install_all_breakpoints(xdbg_session_t *session) {
    size_t i;
    for (i = 0; i < session->breakpoints.count; ++i) {
        if (session->breakpoints.items[i].enabled &&
            xdbg_breakpoint_install(session->pid, &session->breakpoints.items[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int xdbg_wait_for_stop(xdbg_session_t *session) {
    int status = 0;
    int wait_result;

    wait_result = waitpid(session->pid, &status, 0);
    if (wait_result == -1) return -1;

    session->last_signal = 0;
    session->pending_signal = 0;
    if (WIFEXITED(status)) {
        session->state = XDBG_SESSION_EXITED;
        session->stop_reason = XDBG_STOP_EXITED;
        session->exited = 1;
        xdbg_drain_program_output(session);
        snprintf(session->last_status, sizeof(session->last_status),
                 "tracee exited with code %d", WEXITSTATUS(status));
        return 0;
    }
    if (WIFSIGNALED(status)) {
        session->state = XDBG_SESSION_EXITED;
        session->stop_reason = XDBG_STOP_EXITED;
        session->exited = 1;
        xdbg_drain_program_output(session);
        snprintf(session->last_status, sizeof(session->last_status),
                 "tracee terminated by signal %d", WTERMSIG(status));
        return 0;
    }
    if (WIFSTOPPED(status)) {
        uint64_t trap_address;
        xdbg_breakpoint_t *bp;

        session->state = XDBG_SESSION_STOPPED;
        session->last_signal = WSTOPSIG(status);
        session->stop_reason = XDBG_STOP_SIGNAL;
        session->pending_signal = session->last_signal;

        if (xdbg_get_registers(session->pid, &session->regs) == 0 && session->regs.rip > 0) {
            trap_address = session->regs.rip - 1;
            bp = NULL;
            if (session->last_signal == SIGTRAP || session->last_signal == (SIGTRAP | 0x80)) {
                bp = xdbg_breakpoint_find_by_address(&session->breakpoints, trap_address);
            }
            if (session->last_signal == SIGTRAP && bp && bp->installed) {
                session->stop_reason = XDBG_STOP_BREAKPOINT;
                xdbg_breakpoint_remove(session->pid, bp);
                session->regs.rip = trap_address;
                xdbg_set_registers(session->pid, &session->regs);
                xdbg_get_registers(session->pid, &session->regs);
                session->pending_signal = 0;
                snprintf(session->last_status, sizeof(session->last_status),
                         "hit breakpoint #%d at 0x%llx",
                         bp->id, (unsigned long long)bp->address);
                if (bp->temporary) {
                    size_t i;
                    for (i = 0; i < session->breakpoints.count; ++i) {
                        if (&session->breakpoints.items[i] == bp) {
                            xdbg_breakpoint_delete(&session->breakpoints, i);
                            break;
                        }
                    }
                }
            } else if (session->syscall_trace_enabled && session->last_signal == (SIGTRAP | 0x80)) {
                session->stop_reason = XDBG_STOP_SYSCALL;
                session->pending_signal = 0;
                snprintf(session->last_status, sizeof(session->last_status), "syscall stop");
            } else {
                if (session->last_signal == SIGTRAP) {
                    session->stop_reason = XDBG_STOP_STEP;
                    session->pending_signal = 0;
                } else {
                    session->stop_reason = XDBG_STOP_SIGNAL;
                }
                snprintf(session->last_status, sizeof(session->last_status),
                         "stopped by signal %d", session->last_signal);
            }
        }

        xdbg_fetch_instruction(session);
        xdbg_got_check_watches(session);
        xdbg_drain_program_output(session);
        return 0;
    }

    return -1;
}

static int xdbg_resume_after_breakpoint(xdbg_session_t *session) {
    size_t i;

    for (i = 0; i < session->breakpoints.count; ++i) {
        xdbg_breakpoint_t *bp = &session->breakpoints.items[i];
        if (!bp->enabled) continue;
        if (bp->address == session->regs.rip && !bp->installed) {
            if (xdbg_ptrace_singlestep(session->pid, 0) != 0) return -1;
            if (xdbg_wait_for_stop(session) != 0) return -1;
            if (!bp->temporary && bp->enabled) {
                if (xdbg_breakpoint_install(session->pid, bp) != 0) return -1;
            }
            break;
        }
    }
    return 0;
}

static int xdbg_continue_execution(xdbg_session_t *session) {
    int deliver_signal = 0;
    if (session->pid <= 0 || session->state == XDBG_SESSION_EXITED) return -1;
    if (xdbg_resume_after_breakpoint(session) != 0) return -1;
    session->state = XDBG_SESSION_RUNNING;
    deliver_signal = session->pending_signal;
    session->pending_signal = 0;
    if (session->syscall_trace_enabled) {
        if (xdbg_ptrace_syscall(session->pid, deliver_signal) != 0) return -1;
    } else {
        if (xdbg_ptrace_continue(session->pid, deliver_signal) != 0) return -1;
    }
    return xdbg_wait_for_stop(session);
}

static int xdbg_single_step(xdbg_session_t *session) {
    int deliver_signal = 0;
    if (session->pid <= 0 || session->state == XDBG_SESSION_EXITED) return -1;
    if (xdbg_resume_after_breakpoint(session) != 0) return -1;
    session->state = XDBG_SESSION_RUNNING;
    deliver_signal = session->pending_signal;
    session->pending_signal = 0;
    if (xdbg_ptrace_singlestep(session->pid, deliver_signal) != 0) return -1;
    return xdbg_wait_for_stop(session);
}

static int xdbg_decode_call_like(const x86_decoded_instruction_t *instruction) {
    return instruction && instruction->opcode == 0xE8;
}

static int xdbg_next_instruction(xdbg_session_t *session) {
    xdbg_breakpoint_t *temp_bp;
    uint64_t next_address;

    if (!session) return -1;
    if (!xdbg_decode_call_like(&session->current_instruction)) {
        return xdbg_single_step(session);
    }

    next_address = session->current_instruction.address + session->current_instruction.length;
    temp_bp = xdbg_breakpoint_add(&session->breakpoints, next_address, XDBG_BREAKPOINT_ADDRESS, "nexti-temp", 1);
    if (!temp_bp) return -1;
    if (xdbg_breakpoint_install(session->pid, temp_bp) != 0) return -1;
    return xdbg_continue_execution(session);
}

static int xdbg_set_temp_breakpoint_and_continue(xdbg_session_t *session,
                                                 uint64_t address,
                                                 const char *label) {
    xdbg_breakpoint_t *temp_bp;

    if (!session || address == 0) return -1;
    temp_bp = xdbg_breakpoint_add(&session->breakpoints,
                                  address,
                                  XDBG_BREAKPOINT_ADDRESS,
                                  label ? label : "temp",
                                  1);
    if (!temp_bp) return -1;
    if (xdbg_breakpoint_install(session->pid, temp_bp) != 0) return -1;
    return xdbg_continue_execution(session);
}

static int xdbg_read_stack_return_address(xdbg_session_t *session, uint64_t *return_address) {
    if (!session || !return_address || session->regs.rsp == 0) return -1;
    return xdbg_read_process_memory(session->pid,
                                    session->regs.rsp,
                                    (uint8_t *)return_address,
                                    sizeof(*return_address));
}

static int xdbg_read_frame_return_address(xdbg_session_t *session, uint64_t *return_address) {
    if (!session || !return_address || session->regs.rbp <= session->regs.rsp) return -1;
    return xdbg_read_process_memory(session->pid,
                                    session->regs.rbp + sizeof(uint64_t),
                                    (uint8_t *)return_address,
                                    sizeof(*return_address));
}

static int xdbg_is_user_source_location(const xdbg_source_location_t *location) {
    return location &&
           location->has_source_file &&
           location->line > 0 &&
           location->function[0] != '\0' &&
           strcmp(location->function, "??") != 0;
}

static int xdbg_finish_current_function(xdbg_session_t *session) {
    uint64_t return_address = 0;

    if (!session || session->pid <= 0 || session->state == XDBG_SESSION_EXITED) return -1;
    if ((xdbg_read_frame_return_address(session, &return_address) != 0 || return_address == 0) &&
        (xdbg_read_stack_return_address(session, &return_address) != 0 || return_address == 0)) {
        snprintf(session->last_status, sizeof(session->last_status), "unable to read return address");
        return -1;
    }
    return xdbg_set_temp_breakpoint_and_continue(session, return_address, "finish-temp");
}

static int xdbg_skip_to_user_code(xdbg_session_t *session) {
    int guard = 128;

    if (!session || session->pid <= 0 || session->state == XDBG_SESSION_EXITED) return -1;

    while (guard-- > 0 && session->state != XDBG_SESSION_EXITED) {
        uint64_t return_address = 0;

        if (xdbg_is_user_source_location(&session->current_source) &&
            !xdbg_runtime_address_in_plt(session, session->regs.rip)) {
            snprintf(session->last_status, sizeof(session->last_status), "stopped in user code");
            return 0;
        }

        if (xdbg_read_stack_return_address(session, &return_address) == 0 &&
            xdbg_runtime_address_in_user_text(session, return_address)) {
            if (xdbg_set_temp_breakpoint_and_continue(session, return_address, "skip-temp") != 0) {
                return -1;
            }
        } else {
            if (xdbg_single_step(session) != 0) return -1;
        }
    }

    if (session->state == XDBG_SESSION_EXITED) return 0;
    snprintf(session->last_status, sizeof(session->last_status), "skip stopped before finding source");
    return -1;
}

static int xdbg_step_source_line(xdbg_session_t *session, int step_over_calls) {
    int start_line = session->current_source.line;
    char start_file[260];
    int guard = 512;

    snprintf(start_file, sizeof(start_file), "%s", session->current_source.file);
    while (guard-- > 0 && session->state != XDBG_SESSION_EXITED) {
        if (step_over_calls) {
            if (xdbg_next_instruction(session) != 0) return -1;
        } else {
            if (xdbg_single_step(session) != 0) return -1;
        }

        if (session->current_source.has_location &&
            (session->current_source.line != start_line ||
             strcmp(session->current_source.file, start_file) != 0)) {
            break;
        }
    }
    return 0;
}

static int xdbg_parse_address(const char *text, uint64_t *address) {
    char *end = NULL;
    unsigned long long value;

    if (!text || !address) return -1;
    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno != 0 || !end || *end != '\0') return -1;
    *address = (uint64_t)value;
    return 0;
}

static int xdbg_got_slot_runtime_address(xdbg_session_t *session, const char *symbol, uint64_t *runtime_slot) {
    uint64_t slot = 0;
    if (!session || !symbol || !runtime_slot || !session->has_elf) return -1;
    if (xdbg_live_got_find_slot(&session->elf, symbol, &slot) != 0) return -1;
    *runtime_slot = slot + xdbg_module_bias(session);
    return 0;
}

static int xdbg_print_got_entry(xdbg_session_t *session, const char *symbol) {
    uint64_t slot_addr;
    uint64_t value;
    if (!session || session->pid <= 0 || !symbol) return -1;
    if (xdbg_got_slot_runtime_address(session, symbol, &slot_addr) != 0) {
        printf("unable to resolve GOT slot for symbol: %s\n", symbol);
        return -1;
    }
    if (xdbg_live_got_read_slot(session->pid, slot_addr, &value) != 0) {
        printf("failed reading GOT slot for symbol: %s\n", symbol);
        return -1;
    }
    printf("GOT[%s] @ 0x%llx = 0x%llx %s\n",
           symbol,
           (unsigned long long)slot_addr,
           (unsigned long long)value,
           xdbg_live_got_is_plt_address(&session->elf, value, xdbg_module_bias(session))
               ? "(unresolved -> .plt)"
               : "(resolved)");
    return 0;
}

static void xdbg_got_check_watches(xdbg_session_t *session) {
    size_t i;
    if (!session || session->pid <= 0 || !session->has_elf) return;
    for (i = 0; i < session->got_watch_count; ++i) {
        xdbg_got_watch_t *watch = &session->got_watches[i];
        uint64_t value = 0;
        if (!watch->active) continue;
        if (xdbg_live_got_read_slot(session->pid, watch->slot_address, &value) != 0) continue;
        if (value != watch->last_value) {
            printf("GOT[%s] changed: 0x%llx -> 0x%llx %s\n",
                   watch->symbol,
                   (unsigned long long)watch->last_value,
                   (unsigned long long)value,
                   xdbg_live_got_is_plt_address(&session->elf, value, xdbg_module_bias(session))
                       ? "(now unresolved)"
                       : "(now resolved)");
            watch->last_value = value;
        }
    }
}

static int xdbg_add_got_watch(xdbg_session_t *session, const char *symbol) {
    xdbg_got_watch_t *watch;
    uint64_t slot_addr;
    uint64_t value = 0;
    if (!session || !symbol) return -1;
    if (session->got_watch_count >= sizeof(session->got_watches) / sizeof(session->got_watches[0])) return -1;
    if (xdbg_got_slot_runtime_address(session, symbol, &slot_addr) != 0) return -1;
    if (xdbg_live_got_read_slot(session->pid, slot_addr, &value) != 0) return -1;
    watch = &session->got_watches[session->got_watch_count++];
    memset(watch, 0, sizeof(*watch));
    watch->active = 1;
    watch->slot_address = slot_addr;
    watch->last_value = value;
    snprintf(watch->symbol, sizeof(watch->symbol), "%s", symbol);
    printf("watching GOT[%s] @ 0x%llx (current 0x%llx)\n",
           watch->symbol,
           (unsigned long long)watch->slot_address,
           (unsigned long long)watch->last_value);
    return 0;
}

static int xdbg_demo_plt_lazy_binding(xdbg_session_t *session, const char *symbol) {
    if (!session || !symbol) return -1;
    printf("Before first call (current):\n");
    if (xdbg_print_got_entry(session, symbol) != 0) return -1;
    if (xdbg_next_instruction(session) != 0) return -1;
    printf("After stepping over call:\n");
    if (xdbg_print_got_entry(session, symbol) != 0) return -1;
    return 0;
}

static int xdbg_resolve_break_spec(xdbg_session_t *session, const char *spec, uint64_t *address, xdbg_breakpoint_kind_t *kind) {
    const Elf64_Sym *sym;

    if (!session || !spec || !address || !kind) return -1;
    if (xdbg_parse_address(spec, address) == 0) {
        *kind = XDBG_BREAKPOINT_ADDRESS;
        return 0;
    }

    if (strchr(spec, ':')) {
        *kind = XDBG_BREAKPOINT_FILE_LINE;
        return -1;
    }

    if (!session->has_elf && session->pid > 0) {
        xdbg_refresh_program_path_and_elf(session);
    }

    if (session->has_elf) {
        size_t i;
        sym = elf_find_symbol_by_name(&session->elf, spec, false);
        if (!sym) sym = elf_find_symbol_by_name(&session->elf, spec, true);
        if (!sym) {
            for (i = 0; i < session->elf.sym_count; ++i) {
                const Elf64_Sym *candidate = &session->elf.symtab[i];
                const char *name = elf_symbol_name(&session->elf, candidate, false);
                if (name && strcmp(name, spec) == 0 && candidate->st_value != 0) {
                    sym = candidate;
                    break;
                }
            }
        }
        if (sym) {
            *address = sym->st_value + xdbg_module_bias(session);
            *kind = XDBG_BREAKPOINT_SYMBOL;
            return 0;
        }
    }

    return -1;
}

static void xdbg_disassemble_around_pc(xdbg_session_t *session) {
    uint8_t bytes[256];
    size_t offset = 0;
    int count = 0;

    if (!session || session->pid <= 0) return;
    if (xdbg_read_process_memory(session->pid, session->regs.rip, bytes, sizeof(bytes)) != 0) {
        printf("unable to read memory for disassembly\n");
        return;
    }
    while (offset < sizeof(bytes) && count < 15) {
        x86_decoded_instruction_t instruction;
        char line[384];

        if (x86_decode_instruction(bytes + offset, sizeof(bytes) - offset,
                                   session->regs.rip + offset, &instruction) != 0 ||
            instruction.length == 0) {
            break;
        }
        x86_format_objdump_line(&instruction, line, sizeof(line));
        printf("%s\n", line);
        offset += instruction.length;
        count += 1;
    }
}

static void xdbg_print_backtrace(xdbg_session_t *session) {
    uint64_t frame = session->regs.rbp;
    uint64_t ret = session->regs.rip;
    int depth = 0;

    printf("#%d  0x%016llx %s\n", depth, (unsigned long long)ret,
           session->current_source.function[0] ? session->current_source.function : "(current)");
    depth += 1;

    while (frame && depth < 16) {
        uint64_t next_frame = 0;
        uint64_t return_address = 0;
        if (xdbg_read_process_memory(session->pid, frame, (uint8_t *)&next_frame, sizeof(next_frame)) != 0) break;
        if (xdbg_read_process_memory(session->pid, frame + sizeof(uint64_t), (uint8_t *)&return_address, sizeof(return_address)) != 0) break;
        printf("#%d  0x%016llx frame=0x%016llx\n", depth,
               (unsigned long long)return_address,
               (unsigned long long)frame);
        if (next_frame <= frame) break;
        frame = next_frame;
        depth += 1;
    }
}

static void xdbg_examine_memory(xdbg_session_t *session, const char *format_spec, const char *address_spec) {
    uint64_t address;
    size_t count = 64;
    size_t i;
    uint8_t buffer[128];

    if (xdbg_parse_address(address_spec, &address) != 0) {
        printf("usage: x/<fmt> <addr>\n");
        return;
    }
    if (format_spec && strchr(format_spec, 'g')) count = 64;
    if (format_spec && strchr(format_spec, 'b')) count = 32;
    if (count > sizeof(buffer)) count = sizeof(buffer);

    if (xdbg_read_process_memory(session->pid, address, buffer, count) != 0) {
        printf("failed to read process memory\n");
        return;
    }

    for (i = 0; i < count; ++i) {
        if (i % 16 == 0) printf("\n0x%016llx: ", (unsigned long long)(address + i));
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

static int xdbg_attach_to_pid(xdbg_session_t *session, int pid) {
    if (pid <= 0) return -1;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) return -1;
    session->pid = pid;
    session->attached = 1;
    session->exited = 0;
    session->syscall_trace_enabled = 0;
    xdbg_refresh_program_path_and_elf(session);
    if (xdbg_wait_for_stop(session) != 0) return -1;
    ptrace(PTRACE_SETOPTIONS, session->pid, NULL, (void *)(long)PTRACE_O_TRACESYSGOOD);
    xdbg_refresh_program_base(session);
    xdbg_install_all_breakpoints(session);
    return 0;
}

static int xdbg_launch_process(xdbg_session_t *session, const char *program, char **argv) {
    pid_t child;
    int output_pipe[2];

    if (pipe(output_pipe) != 0) return -1;
    if (fcntl(output_pipe[0], F_SETFL, fcntl(output_pipe[0], F_GETFL, 0) | O_NONBLOCK) == -1) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }

    child = fork();
    if (child == -1) {
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }
    if (child == 0) {
        close(output_pipe[0]);
        dup2(output_pipe[1], STDOUT_FILENO);
        dup2(output_pipe[1], STDERR_FILENO);
        close(output_pipe[1]);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) _exit(1);
        execv(program, argv);
        _exit(1);
    }

    close(output_pipe[1]);
    xdbg_close_program_output(session);
    session->output_fd = output_pipe[0];
    session->program_output[0] = '\0';
    session->pid = child;
    session->attached = 0;
    session->exited = 0;
    session->syscall_trace_enabled = 0;
    snprintf(session->program_path, sizeof(session->program_path), "%s", program);
    if (xdbg_wait_for_stop(session) != 0) return -1;
    ptrace(PTRACE_SETOPTIONS, session->pid, NULL, (void *)(long)(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC));
    xdbg_refresh_program_path_and_elf(session);
    xdbg_refresh_program_base(session);
    if (session->has_elf) {
        const Elf64_Sym *main_sym = elf_find_symbol_by_name(&session->elf, "main", false);
        if (!main_sym) main_sym = elf_find_symbol_by_name(&session->elf, "main", true);
        if (main_sym) {
            uint64_t main_address = main_sym->st_value + xdbg_module_bias(session);
            xdbg_breakpoint_t *entry_bp = xdbg_breakpoint_add(&session->breakpoints,
                                                              main_address,
                                                              XDBG_BREAKPOINT_SYMBOL,
                                                              "main",
                                                              true);
            if (entry_bp) {
                if (xdbg_breakpoint_install(session->pid, entry_bp) != 0) return -1;
                if (xdbg_ptrace_continue(session->pid, 0) != 0) return -1;
                if (xdbg_wait_for_stop(session) != 0) return -1;
            }
        }
    }
    if (xdbg_install_all_breakpoints(session) != 0) return -1;
    return 0;
}

static void xdbg_detach_if_needed(xdbg_session_t *session) {
    if (!session || session->pid <= 0 || session->state == XDBG_SESSION_EXITED) return;
    xdbg_close_program_output(session);
    if (session->attached) {
        ptrace(PTRACE_DETACH, session->pid, NULL, NULL);
    } else {
        kill(session->pid, SIGKILL);
        waitpid(session->pid, NULL, 0);
    }
}

static int xdbg_read_prompt_command(xdbg_session_t *session, char *buffer, size_t buffer_size) {
    struct termios original;
    struct termios raw;
    size_t used = 0;
    size_t history_cursor;

    if (!buffer || buffer_size < 2) return -1;
    buffer[0] = '\0';
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original) != 0) {
        return fgets(buffer, (int)buffer_size, stdin) ? 0 : -1;
    }

    raw = original;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
        return fgets(buffer, (int)buffer_size, stdin) ? 0 : -1;
    }

    history_cursor = session ? session->command_history_count : 0;
    while (1) {
        unsigned char ch;
        ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
            return -1;
        }

        if (ch == '\n' || ch == '\r') {
            buffer[used] = '\0';
            write(STDOUT_FILENO, "\n", 1);
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
            return 0;
        }
        if (ch == 4 && used == 0) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
            return -1;
        }
        if (ch == 127 || ch == '\b') {
            if (used > 0) {
                used -= 1;
                buffer[used] = '\0';
                xdbg_redraw_prompt_input(buffer);
            }
            continue;
        }
        if (ch == 27) {
            unsigned char seq[3] = {0, 0, 0};
            if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;
            if (seq[0] == '[' && seq[1] == 'A') {
                xdbg_prompt_load_history(session, &history_cursor, -1, buffer, buffer_size, &used);
                continue;
            }
            if (seq[0] == '[' && seq[1] == 'B') {
                xdbg_prompt_load_history(session, &history_cursor, 1, buffer, buffer_size, &used);
                continue;
            }
            if (seq[0] == '[' && seq[1] == '5') {
                read(STDIN_FILENO, &seq[2], 1);
                xdbg_prompt_load_history(session, &history_cursor, -1, buffer, buffer_size, &used);
                continue;
            }
            continue;
        }
        if (ch >= 32 && ch <= 126 && used + 1 < buffer_size) {
            buffer[used++] = (char)ch;
            buffer[used] = '\0';
            write(STDOUT_FILENO, &ch, 1);
        }
    }
}

static int xdbg_read_command_line(xdbg_session_t *session, char *buffer, size_t buffer_size) {
    if (session->tui_enabled) {
        if (xdbg_tui_read_command(session, buffer, (unsigned long)buffer_size) == 0) {
            return 0;
        }
        xdbg_note_status(session, "tui input unavailable, switched to prompt mode");
        session->tui_enabled = 0;
        xdbg_tui_shutdown();
    }
    return xdbg_read_prompt_command(session, buffer, buffer_size);
}

static int xdbg_handle_info_command(xdbg_session_t *session, const char *topic) {
    char breaks[1024];

    if (!topic) return -1;
    if (strcmp(topic, "regs") == 0 || strcmp(topic, "registers") == 0) {
        xdbg_print_registers(&session->regs);
        return 0;
    }
    if (strcmp(topic, "break") == 0 || strcmp(topic, "breakpoints") == 0) {
        xdbg_breakpoint_format_table(&session->breakpoints, breaks, sizeof(breaks));
        printf("%s", breaks);
        return 0;
    }
    return -1;
}

static int xdbg_handle_layout_command(xdbg_session_t *session, const char *mode) {
    if (!mode) return -1;
    if (strcmp(mode, "src") == 0) session->layout = XDBG_LAYOUT_SRC;
    else if (strcmp(mode, "asm") == 0) session->layout = XDBG_LAYOUT_ASM;
    else session->layout = XDBG_LAYOUT_SPLIT;
    if (session->tui_enabled) xdbg_tui_render(session);
    return 0;
}

static int xdbg_restart_target(xdbg_session_t *session, char *program, char **remaining_tokens) {
    char *argv_run[64];
    size_t argc_run = 0;

    if (session->pid > 0 && session->state != XDBG_SESSION_EXITED) {
        xdbg_detach_if_needed(session);
        session->pid = -1;
    }

    if (!program && session->program_path[0] == '\0') {
        printf("no program configured\n");
        return -1;
    }

    if (!program) {
        argv_run[argc_run++] = session->program_path;
    } else {
        argv_run[argc_run++] = program;
        snprintf(session->program_path, sizeof(session->program_path), "%s", program);
    }

    session->program_args_text[0] = '\0';
    while (remaining_tokens && *remaining_tokens && argc_run + 1 < sizeof(argv_run) / sizeof(argv_run[0])) {
        char *token = *remaining_tokens++;
        if (session->program_args_text[0] != '\0') {
            strncat(session->program_args_text,
                    " ",
                    sizeof(session->program_args_text) - strlen(session->program_args_text) - 1);
        }
        strncat(session->program_args_text,
                token,
                sizeof(session->program_args_text) - strlen(session->program_args_text) - 1);
        argv_run[argc_run++] = token;
    }

    argv_run[argc_run] = NULL;
    return xdbg_launch_process(session, argv_run[0], argv_run);
}

static int xdbg_handle_run_command(xdbg_session_t *session, char *program) {
    char *tokens[64];
    size_t count = 0;
    char *token;

    while ((token = strtok(NULL, " \t\r\n")) != NULL && count + 1 < sizeof(tokens) / sizeof(tokens[0])) {
        tokens[count++] = token;
    }
    tokens[count] = NULL;
    return xdbg_restart_target(session, program, tokens);
}

static int xdbg_handle_break_command(xdbg_session_t *session, const char *command, const char *spec) {
    uint64_t address;
    xdbg_breakpoint_kind_t kind;
    xdbg_breakpoint_t *bp;

    if (!spec || xdbg_resolve_break_spec(session, spec, &address, &kind) != 0) {
        printf("unable to resolve breakpoint spec: %s\n", spec ? spec : "(null)");
        return -1;
    }

    bp = xdbg_breakpoint_add(&session->breakpoints,
                             address,
                             kind,
                             spec,
                             strcmp(command, "tbreak") == 0);
    if (!bp) return -1;

    if (session->pid > 0 && session->state != XDBG_SESSION_EXITED &&
        xdbg_breakpoint_install(session->pid, bp) != 0) {
        return -1;
    }

    snprintf(session->last_status, sizeof(session->last_status),
             "breakpoint #%d at 0x%llx", bp->id, (unsigned long long)bp->address);
    return 0;
}

static int xdbg_delete_breakpoint_by_id(xdbg_session_t *session, const char *id_text) {
    uint64_t id_value;
    size_t i;

    if (!id_text || xdbg_parse_address(id_text, &id_value) != 0) {
        printf("usage: delete <id>\n");
        return -1;
    }

    for (i = 0; i < session->breakpoints.count; ++i) {
        if (session->breakpoints.items[i].id == (int)id_value) {
            xdbg_breakpoint_remove(session->pid, &session->breakpoints.items[i]);
            xdbg_breakpoint_delete(&session->breakpoints, i);
            return 0;
        }
    }

    printf("breakpoint not found: %s\n", id_text);
    return -1;
}

static int xdbg_set_breakpoint_enabled(xdbg_session_t *session, const char *id_text, int enabled) {
    xdbg_breakpoint_t *bp;
    uint64_t id_value;

    if (!id_text || xdbg_parse_address(id_text, &id_value) != 0) {
        printf("usage: %s <id>\n", enabled ? "enable" : "disable");
        return -1;
    }

    bp = xdbg_breakpoint_find_by_id(&session->breakpoints, (int)id_value);
    if (!bp) {
        printf("breakpoint not found: %s\n", id_text);
        return -1;
    }

    return enabled ? xdbg_breakpoint_enable(session->pid, bp) : xdbg_breakpoint_disable(session->pid, bp);
}

static int xdbg_handle_command(xdbg_session_t *session, char *line) {
    char *command;
    char *arg1;
    char *slash;

    command = strtok(line, " \t\r\n");
    arg1 = strtok(NULL, " \t\r\n");
    if (!command) return 0;

    if (xdbg_command_is(command, "help", "h")) {
        xdbg_print_debugger_help();
        return 0;
    }
    if (xdbg_command_is(command, "quit", "q")) {
        session->should_quit = 1;
        return 0;
    }
    if (xdbg_command_is(command, "continue", "c")) {
        return xdbg_continue_execution(session);
    }
    if (xdbg_command_is(command, "stepi", "si")) {
        return xdbg_single_step(session);
    }
    if (xdbg_command_is(command, "nexti", "ni")) {
        return xdbg_next_instruction(session);
    }
    if (xdbg_command_is(command, "step", "s")) {
        return xdbg_step_source_line(session, 0);
    }
    if (xdbg_command_is(command, "next", "n")) {
        return xdbg_step_source_line(session, 1);
    }
    if (xdbg_command_is(command, "skip", "sk")) {
        return xdbg_skip_to_user_code(session);
    }
    if (xdbg_command_is(command, "finish", "fin")) {
        return xdbg_finish_current_function(session);
    }
    if (strcmp(command, "disassemble") == 0) {
        xdbg_disassemble_around_pc(session);
        return 0;
    }
    if (strcmp(command, "bt") == 0) {
        xdbg_print_backtrace(session);
        return 0;
    }
    if (strcmp(command, "layout") == 0) {
        return xdbg_handle_layout_command(session, arg1 ? arg1 : "split");
    }
    if (strcmp(command, "tui") == 0) {
        session->tui_enabled = 1;
        if (xdbg_tui_init(session) != 0) {
            session->tui_enabled = 0;
            printf("failed to initialize tui\n");
            return -1;
        }
        xdbg_tui_render(session);
        return 0;
    }
    if (strcmp(command, "run") == 0) {
        return xdbg_handle_run_command(session, arg1);
    }
    if (strcmp(command, "attach") == 0) {
        uint64_t pid_value;
        if (!arg1 || xdbg_parse_address(arg1, &pid_value) != 0) {
            printf("usage: attach <pid>\n");
            return -1;
        }
        return xdbg_attach_to_pid(session, (int)pid_value);
    }
    if (strcmp(command, "break") == 0 || strcmp(command, "tbreak") == 0) {
        return xdbg_handle_break_command(session, command, arg1);
    }
    if (strcmp(command, "delete") == 0) {
        return xdbg_delete_breakpoint_by_id(session, arg1);
    }
    if (strcmp(command, "disable") == 0 || strcmp(command, "enable") == 0) {
        return xdbg_set_breakpoint_enabled(session, arg1, strcmp(command, "enable") == 0);
    }
    if (strcmp(command, "info") == 0) {
        return xdbg_handle_info_command(session, arg1);
    }
    if (strcmp(command, "syscall") == 0) {
        session->syscall_trace_enabled = 1;
        return xdbg_continue_execution(session);
    }
    if (strcmp(command, "got") == 0) {
        if (!arg1) {
            printf("usage: got <symbol> | got watch <symbol>\n");
            return -1;
        }
        if (strcmp(arg1, "watch") == 0) {
            char *symbol = strtok(NULL, " \t\r\n");
            if (!symbol) {
                printf("usage: got watch <symbol>\n");
                return -1;
            }
            return xdbg_add_got_watch(session, symbol);
        }
        return xdbg_print_got_entry(session, arg1);
    }
    if (strcmp(command, "plt") == 0) {
        if (!arg1 || strcmp(arg1, "demo") != 0) {
            printf("usage: plt demo <symbol>\n");
            return -1;
        }
        {
            char *symbol = strtok(NULL, " \t\r\n");
            if (!symbol) {
                printf("usage: plt demo <symbol>\n");
                return -1;
            }
            return xdbg_demo_plt_lazy_binding(session, symbol);
        }
    }

    slash = strchr(command, '/');
    if (strcmp(command, "x") == 0 || (slash && strncmp(command, "x/", 2) == 0)) {
        const char *fmt = slash ? slash + 1 : "";
        xdbg_examine_memory(session, fmt, arg1);
        return 0;
    }

    if (session->tui_enabled) {
        char status[256];
        snprintf(status, sizeof(status), "unknown command: %s", command);
        xdbg_note_status(session, status);
    } else {
        printf("unknown command: %s\n", command);
    }
    return -1;
}

static int xdbg_repl(xdbg_session_t *session) {
    char line[512];
    char original_line[512];
    char previous_status[256];

    while (!session->should_quit) {
        if (session->tui_enabled) xdbg_tui_render(session);
        xdbg_print_prompt(session);
        if (xdbg_read_command_line(session, line, sizeof(line)) != 0) break;
        snprintf(original_line, sizeof(original_line), "%s", line);
        xdbg_note_command_history(session, original_line);
        snprintf(previous_status, sizeof(previous_status), "%s", session->last_status);
        if (xdbg_handle_command(session, line) != 0) {
            if (strcmp(previous_status, session->last_status) == 0) {
                xdbg_note_status(session, "command failed");
            }
        } else if (session->pid > 0 && session->state != XDBG_SESSION_EXITED) {
            xdbg_fetch_instruction(session);
        }
    }
    return 0;
}

int xdbg_session_refresh_stop_state(xdbg_session_t *session) {
    return xdbg_fetch_instruction(session);
}

int xdbg_run_debugger(int argc, char **argv) {
    xdbg_session_t session;
    int result = 0;

    xdbg_session_init(&session);

    if (xdbg_signals_install(xdbg_signal_forwarder, &session) != 0) {
        perror("signal setup");
    }

    if (argc >= 3) {
        char *launch_argv[64];
        int i;
        int launch_argc = 0;

        for (i = 2; i < argc && launch_argc + 1 < (int)(sizeof(launch_argv) / sizeof(launch_argv[0])); ++i) {
            launch_argv[launch_argc++] = argv[i];
        }
        launch_argv[launch_argc] = NULL;
        session.program_args_text[0] = '\0';
        if (argc > 3) {
            for (i = 3; i < argc; ++i) {
                if (session.program_args_text[0] != '\0') {
                    strncat(session.program_args_text, " ", sizeof(session.program_args_text) - strlen(session.program_args_text) - 1);
                }
                strncat(session.program_args_text, argv[i], sizeof(session.program_args_text) - strlen(session.program_args_text) - 1);
            }
        }
        if (launch_argc > 0) {
            if (xdbg_launch_process(&session, launch_argv[0], launch_argv) != 0) {
                fprintf(stderr, "failed to launch %s\n", launch_argv[0]);
                result = 1;
                goto cleanup;
            }
        }
    }

    session.tui_enabled = 0;
    if (session.pid > 0) xdbg_fetch_instruction(&session);
    xdbg_repl(&session);

cleanup:
    xdbg_tui_shutdown();
    xdbg_detach_if_needed(&session);
    xdbg_close_program_output(&session);
    xdbg_signals_uninstall();
    xdbg_close_loaded_elf(&session);
    return result;
}
