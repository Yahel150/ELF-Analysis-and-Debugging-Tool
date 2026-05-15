#include "tui.h"
#include "../dwarf/source_map.h"
#include "../debugger/memory.h"

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <ncurses.h>

#define XDBG_COLOR_NORMAL 1
#define XDBG_COLOR_TITLE 2
#define XDBG_COLOR_CURRENT 3
#define XDBG_COLOR_STATUS 4

static int g_tui_initialized = 0;
static int g_tui_has_color = 0;

static const char *session_state_text(xdbg_session_state_t state) {
    switch (state) {
        case XDBG_SESSION_RUNNING: return "running";
        case XDBG_SESSION_STOPPED: return "stopped";
        case XDBG_SESSION_EXITED: return "exited";
        case XDBG_SESSION_IDLE:
        default: return "idle";
    }
}

static int clamp_positive_width(int width) {
    return width > 0 ? width : 1;
}

static void tui_attr_on(WINDOW *win, int color_pair, int attrs) {
    if (g_tui_has_color) wattron(win, COLOR_PAIR(color_pair));
    if (attrs) wattron(win, attrs);
}

static void tui_attr_off(WINDOW *win, int color_pair, int attrs) {
    if (attrs) wattroff(win, attrs);
    if (g_tui_has_color) wattroff(win, COLOR_PAIR(color_pair));
}

static void draw_title(WINDOW *win, const char *title) {
    box(win, 0, 0);
    tui_attr_on(win, XDBG_COLOR_TITLE, A_BOLD);
    mvwprintw(win, 0, 2, " %s ", title ? title : "");
    tui_attr_off(win, XDBG_COLOR_TITLE, A_BOLD);
}

static void draw_boxed_text(WINDOW *win, const char *title, const char *text) {
    int row = 1;
    int content_width;
    char line[512];
    const char *cursor = text ? text : "";
    size_t len;
    size_t i;

    werase(win);
    draw_title(win, title);

    content_width = clamp_positive_width(getmaxx(win) - 2);
    len = strlen(cursor);
    for (i = 0; i <= len && row < getmaxy(win) - 1; ++i) {
        size_t j = 0;
        while (cursor[i] != '\n' && cursor[i] != '\0' && j + 1 < sizeof(line)) {
            line[j++] = cursor[i++];
        }
        line[j] = '\0';
        mvwprintw(win, row++, 1, "%.*s", content_width, line);
        if (cursor[i] == '\0') break;
    }
    wrefresh(win);
}

static void draw_register_line(WINDOW *win,
                               int row,
                               int col,
                               const char *name,
                               uint64_t value,
                               int width) {
    int digits = width > 4 ? width - 4 : 1;
    if (digits > 16) digits = 16;
    mvwprintw(win, row, col, "%s %.*llx",
              name,
              digits,
              (unsigned long long)value);
}

static void draw_registers(WINDOW *win, const xdbg_registers_t *regs) {
    static const char *names[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "FLG"
    };
    uint64_t values[18];
    int width;
    int max_row;
    int two_columns;
    int col_width;
    size_t i;

    werase(win);
    draw_title(win, "Registers");
    if (!regs) {
        wrefresh(win);
        return;
    }

    values[0] = regs->rax;
    values[1] = regs->rbx;
    values[2] = regs->rcx;
    values[3] = regs->rdx;
    values[4] = regs->rsi;
    values[5] = regs->rdi;
    values[6] = regs->rbp;
    values[7] = regs->rsp;
    values[8] = regs->r8;
    values[9] = regs->r9;
    values[10] = regs->r10;
    values[11] = regs->r11;
    values[12] = regs->r12;
    values[13] = regs->r13;
    values[14] = regs->r14;
    values[15] = regs->r15;
    values[16] = regs->rip;
    values[17] = regs->rflags;

    width = clamp_positive_width(getmaxx(win) - 2);
    max_row = getmaxy(win) - 1;
    two_columns = width >= 43 && max_row >= 10;
    col_width = two_columns ? width / 2 : width;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        int target_row;
        int target_col = 1;

        if (two_columns) {
            target_row = 1 + (int)(i / 2);
            target_col = (i % 2) ? 1 + col_width : 1;
        } else {
            target_row = 1 + (int)i;
        }

        if (target_row >= max_row) break;
        draw_register_line(win, target_row, target_col, names[i], values[i], col_width - 1);
    }

    wrefresh(win);
}

static void append_text(char *buffer, size_t buffer_size, const char *text) {
    size_t used;

    if (!buffer || !text || buffer_size == 0) return;
    used = strlen(buffer);
    if (used >= buffer_size) return;
    snprintf(buffer + used, buffer_size - used, "%s", text);
}

static const char *command_history_at(const xdbg_session_t *session, size_t index) {
    size_t start;

    if (!session || index >= session->command_history_count) return "";
    start = (session->command_history_next + XDBG_COMMAND_HISTORY_SIZE - session->command_history_count) %
            XDBG_COMMAND_HISTORY_SIZE;
    return session->command_history[(start + index) % XDBG_COMMAND_HISTORY_SIZE];
}

static void append_command_history(char *buffer, size_t buffer_size, const xdbg_session_t *session) {
    size_t start;
    size_t i;

    append_text(buffer, buffer_size, "\nRecent commands:\n");
    if (!session || session->command_history_count == 0) {
        append_text(buffer, buffer_size, "(none)\n");
        return;
    }

    start = (session->command_history_next + XDBG_COMMAND_HISTORY_SIZE - session->command_history_count) %
            XDBG_COMMAND_HISTORY_SIZE;
    for (i = 0; i < session->command_history_count; ++i) {
        char line[320];
        const char *command = session->command_history[(start + i) % XDBG_COMMAND_HISTORY_SIZE];
        snprintf(line, sizeof(line), "  %s\n", command);
        append_text(buffer, buffer_size, line);
    }
}

static void draw_source_context(WINDOW *win, const xdbg_source_location_t *location) {
    FILE *file;
    char line[512];
    int row = 1;
    int current_line = 0;
    int start_line;
    int end_line;
    int width;

    werase(win);
    draw_title(win, "Source");
    width = clamp_positive_width(getmaxx(win) - 2);

    if (!location || !location->has_source_file || location->line <= 0) {
        mvwprintw(win, row++, 1, "%.*s", width, "No source for the current address.");
        mvwprintw(win, row++, 1, "%.*s", width, "This is normal in PLT/libc/startup code or code without debug info.");
        mvwprintw(win, row++, 1, "%.*s", width, "Use skip to return to source, or nexti before calls.");
        wrefresh(win);
        return;
    }

    file = fopen(location->file, "r");
    if (!file) {
        mvwprintw(win, row++, 1, "Source file not found:");
        mvwprintw(win, row++, 1, "%.*s", width, location->file);
        wrefresh(win);
        return;
    }

    start_line = location->line - 5;
    end_line = location->line + 5;
    if (start_line < 1) start_line = 1;

    while (fgets(line, sizeof(line), file) && row < getmaxy(win) - 1) {
        size_t len;
        current_line += 1;
        if (current_line < start_line) continue;
        if (current_line > end_line) break;

        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (current_line == location->line) {
            tui_attr_on(win, XDBG_COLOR_CURRENT, A_REVERSE | A_BOLD);
            mvwprintw(win, row, 1, "> %4d  %.*s", current_line, width - 8, line);
            tui_attr_off(win, XDBG_COLOR_CURRENT, A_REVERSE | A_BOLD);
        } else {
            mvwprintw(win, row, 1, "  %4d  %.*s", current_line, width - 8, line);
        }
        row += 1;
    }

    fclose(file);
    wrefresh(win);
}

static int runtime_function_range(const xdbg_session_t *session, uint64_t *start_out, uint64_t *end_out) {
    size_t i;
    uint64_t best = 0;
    uint64_t best_end = 0;

    if (!session || !session->has_elf || !start_out || !end_out) return 0;
    for (i = 0; i < session->elf.sym_count; ++i) {
        const Elf64_Sym *symbol = &session->elf.symtab[i];
        uint64_t start;
        uint64_t end;

        if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC || symbol->st_value == 0) continue;
        start = symbol->st_value;
        if (session->elf.ehdr && session->elf.ehdr->e_type == ET_DYN) {
            start += session->program_base;
        }
        end = start + (symbol->st_size ? symbol->st_size : 512);
        if (session->regs.rip >= start && session->regs.rip < end) {
            *start_out = start;
            *end_out = end;
            return 1;
        }
        if (start < session->regs.rip && start > best) {
            best = start;
            best_end = end;
        }
    }
    if (best != 0 && session->regs.rip - best <= 4096) {
        *start_out = best;
        *end_out = best_end > session->regs.rip ? best_end : best + 1024;
        return 1;
    }
    return 0;
}

static int draw_wrapped_text(WINDOW *win,
                             int row,
                             const char *prefix,
                             const char *text,
                             int width,
                             int max_row) {
    int prefix_width = (int)strlen(prefix);
    int chunk_width = width - prefix_width;
    const char *safe_text = text ? text : "";
    const char *cursor = safe_text;

    if (prefix_width >= width && row < max_row) {
        mvwprintw(win, row++, 1, "%.*s", width, prefix);
        prefix = "    ";
        prefix_width = 4;
        chunk_width = width - prefix_width;
    }
    if (chunk_width < 8) chunk_width = width;
    while (*cursor && row < max_row) {
        int count = (int)strlen(cursor);
        if (count > chunk_width) count = chunk_width;
        mvwprintw(win, row++, 1, "%s%.*s", prefix, count, cursor);
        cursor += count;
        prefix = "    ";
        prefix_width = 4;
        chunk_width = width - prefix_width;
        if (chunk_width < 8) chunk_width = width;
    }
    if (!*safe_text && row < max_row) {
        mvwprintw(win, row++, 1, "%s", prefix);
    }
    return row;
}

static int draw_instruction(WINDOW *win,
                            int row,
                            const x86_decoded_instruction_t *instruction,
                            int current,
                            int width) {
    char bytes[64];
    char header[64];
    int max_row = getmaxy(win) - 1;

    if (!instruction || row >= max_row) return row;

    snprintf(header, sizeof(header), "%c 0x%016llx: ",
             current ? '>' : ' ',
             (unsigned long long)instruction->address);

    if (current) tui_attr_on(win, XDBG_COLOR_CURRENT, A_REVERSE | A_BOLD);
    row = draw_wrapped_text(win, row, header, instruction->text, width, max_row);
    if (current) tui_attr_off(win, XDBG_COLOR_CURRENT, A_REVERSE | A_BOLD);

    if (row < max_row) {
        x86_format_bytes(instruction, bytes, sizeof(bytes));
        row = draw_wrapped_text(win, row, "    bytes: ", bytes, width, max_row);
    }

    return row;
}

static void draw_assembly_context(WINDOW *win, const xdbg_session_t *session) {
    x86_decoded_instruction_t instructions[128];
    uint64_t start;
    uint64_t end;
    uint64_t address;
    int instruction_count = 0;
    int current_index = -1;
    int visible_count;
    int first;
    int i;
    int row = 1;
    int width;
    int max_row;

    werase(win);
    draw_title(win, "Assembly");
    width = clamp_positive_width(getmaxx(win) - 2);
    max_row = getmaxy(win) - 1;

    if (!session || session->current_instruction.length == 0) {
        mvwprintw(win, 1, 1, "%.*s", width, "Instruction unavailable");
        wrefresh(win);
        return;
    }

    if (!runtime_function_range(session, &start, &end) ||
        start == 0 || start > session->regs.rip || session->regs.rip - start > 4096) {
        start = session->regs.rip;
        end = start + 1024;
    }

    address = start;
    while (address < end && instruction_count < (int)(sizeof(instructions) / sizeof(instructions[0]))) {
        uint8_t bytes[16];
        x86_decoded_instruction_t instruction;

        if (xdbg_read_process_memory(session->pid, address, bytes, sizeof(bytes)) != 0 ||
            x86_decode_instruction(bytes, sizeof(bytes), address, &instruction) != 0 ||
            instruction.length == 0) {
            break;
        }
        instructions[instruction_count] = instruction;
        if (address == session->regs.rip) current_index = instruction_count;
        instruction_count += 1;
        address += instruction.length;
        if (current_index >= 0 && address > session->regs.rip + 256) break;
    }

    if (current_index < 0) {
        instructions[0] = session->current_instruction;
        instruction_count = 1;
        current_index = 0;
    }

    visible_count = (max_row - 1) / 2;
    if (visible_count < 1) visible_count = 1;
    first = current_index - (visible_count / 2);
    if (first < 0) first = 0;
    if (first + visible_count > instruction_count) {
        first = instruction_count - visible_count;
        if (first < 0) first = 0;
    }

    for (i = first; i < instruction_count && row < max_row; ++i) {
        row = draw_instruction(win, row, &instructions[i], i == current_index, width);
    }

    wrefresh(win);
}

int xdbg_tui_init(xdbg_session_t *session) {
    (void)session;
    if (g_tui_initialized) return 0;
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(XDBG_COLOR_NORMAL, -1, -1);
        init_pair(XDBG_COLOR_TITLE, COLOR_CYAN, -1);
        init_pair(XDBG_COLOR_CURRENT, COLOR_BLACK, COLOR_YELLOW);
        init_pair(XDBG_COLOR_STATUS, COLOR_GREEN, -1);
        g_tui_has_color = 1;
    }
    g_tui_initialized = 1;
    return 0;
}

void xdbg_tui_shutdown(void) {
    if (!g_tui_initialized) return;
    endwin();
    g_tui_initialized = 0;
}

static void redraw_command_input(WINDOW *cmd_win,
                                 const char *buffer,
                                 unsigned long cursor,
                                 int cols) {
    int input_width = cols - 9;

    if (input_width < 1) input_width = 1;
    mvwprintw(cmd_win, 1, 7, "%*s", input_width, "");
    mvwprintw(cmd_win, 1, 7, "%.*s", input_width, buffer ? buffer : "");
    wmove(cmd_win, 1, 7 + (int)cursor);
    wrefresh(cmd_win);
}

int xdbg_tui_read_command(xdbg_session_t *session, char *buffer, unsigned long buffer_size) {
    int rows;
    int cols;
    unsigned long used = 0;
    unsigned long cursor = 0;
    size_t history_cursor;
    WINDOW *cmd_win;

    if (!g_tui_initialized || !buffer || buffer_size < 2) return -1;
    buffer[0] = '\0';
    history_cursor = session ? session->command_history_count : 0;

    getmaxyx(stdscr, rows, cols);
    if (rows < 3 || cols < 16) return -1;

    cmd_win = newwin(3, cols, rows - 3, 0);
    if (!cmd_win) return -1;
    keypad(cmd_win, TRUE);

    werase(cmd_win);
    draw_title(cmd_win, "Command");
    tui_attr_on(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    mvwprintw(cmd_win, 1, 1, "xdbg> ");
    tui_attr_off(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    wrefresh(cmd_win);
    curs_set(1);

    while (1) {
        int ch = wgetch(cmd_win);

        if (ch == ERR) continue;
        if (ch == KEY_RESIZE) {
            buffer[0] = '\0';
            curs_set(0);
            delwin(cmd_win);
            return 0;
        }
        if (ch == '\n' || ch == '\r') {
            buffer[used] = '\0';
            break;
        }
        if (ch == 4) {
            curs_set(0);
            delwin(cmd_win);
            return -1;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
            if (cursor > 0) {
                memmove(buffer + cursor - 1, buffer + cursor, used - cursor + 1);
                cursor -= 1;
                used -= 1;
                buffer[used] = '\0';
                redraw_command_input(cmd_win, buffer, cursor, cols);
            }
            continue;
        }
        if (ch == KEY_LEFT) {
            if (cursor > 0) {
                cursor -= 1;
                wmove(cmd_win, 1, 7 + (int)cursor);
                wrefresh(cmd_win);
            }
            continue;
        }
        if (ch == KEY_RIGHT) {
            if (cursor < used) {
                cursor += 1;
                wmove(cmd_win, 1, 7 + (int)cursor);
                wrefresh(cmd_win);
            }
            continue;
        }
        if ((ch == KEY_UP || ch == KEY_PPAGE) && session && session->command_history_count > 0) {
            const char *entry;
            if (history_cursor > 0) history_cursor -= 1;
            entry = command_history_at(session, history_cursor);
            snprintf(buffer, (size_t)buffer_size, "%s", entry);
            used = strlen(buffer);
            if (used >= buffer_size) used = buffer_size - 1;
            cursor = used;
            redraw_command_input(cmd_win, buffer, cursor, cols);
            continue;
        }
        if (ch == KEY_DOWN && session && session->command_history_count > 0) {
            if (history_cursor + 1 < session->command_history_count) {
                const char *entry;
                history_cursor += 1;
                entry = command_history_at(session, history_cursor);
                snprintf(buffer, (size_t)buffer_size, "%s", entry);
            } else {
                history_cursor = session->command_history_count;
                buffer[0] = '\0';
            }
            used = strlen(buffer);
            if (used >= buffer_size) used = buffer_size - 1;
            cursor = used;
            redraw_command_input(cmd_win, buffer, cursor, cols);
            continue;
        }
        if (ch >= 32 && ch <= 126 && used + 1 < buffer_size) {
            memmove(buffer + cursor + 1, buffer + cursor, used - cursor + 1);
            buffer[cursor] = (char)ch;
            cursor += 1;
            used += 1;
            buffer[used] = '\0';
            redraw_command_input(cmd_win, buffer, cursor, cols);
        }
        if ((int)(7 + cursor) >= cols - 1) {
            buffer[used] = '\0';
            break;
        }
    }

    curs_set(0);
    delwin(cmd_win);
    return 0;
}

void xdbg_tui_render(const xdbg_session_t *session) {
    int rows;
    int cols;
    int top_height;
    int bottom_height;
    int left_width;
    WINDOW *src_win = NULL;
    WINDOW *asm_win = NULL;
    WINDOW *regs_win = NULL;
    WINDOW *status_win = NULL;
    WINDOW *cmd_win = NULL;
    char status_text[4096];

    if (!g_tui_initialized || !session) return;

    getmaxyx(stdscr, rows, cols);
    if (rows < 10 || cols < 40) {
        erase();
        mvprintw(0, 0, "Terminal too small for xdbg TUI (%dx%d).", cols, rows);
        refresh();
        return;
    }

    if (session->layout == XDBG_LAYOUT_ASM) {
        bottom_height = rows >= 24 ? 12 : rows / 2;
        top_height = rows - bottom_height - 3;
        if (top_height < 6) {
            top_height = rows / 2;
            bottom_height = rows - top_height - 3;
        }
        left_width = cols >= 80 ? (cols * 3) / 5 : cols / 2;
        asm_win = newwin(top_height, cols, 0, 0);
        regs_win = newwin(bottom_height, left_width, top_height, 0);
        status_win = newwin(bottom_height, cols - left_width, top_height, left_width);
    } else {
        bottom_height = rows >= 24 ? 12 : rows / 2;
        top_height = rows - bottom_height - 3;
        if (top_height < 6) {
            top_height = rows / 2;
            bottom_height = rows - top_height - 3;
        }
        left_width = cols >= 80 ? (cols * 3) / 5 : cols / 2;
        src_win = newwin(top_height, cols / 2, 0, 0);
        asm_win = newwin(top_height, cols - (cols / 2), 0, cols / 2);
        regs_win = newwin(bottom_height, left_width, top_height, 0);
        status_win = newwin(bottom_height, cols - left_width, top_height, left_width);
    }
    cmd_win = newwin(3, cols, rows - 3, 0);
    if (!asm_win || !regs_win || !status_win || !cmd_win ||
        (session->layout != XDBG_LAYOUT_ASM && !src_win)) {
        erase();
        mvprintw(0, 0, "Unable to allocate xdbg TUI windows.");
        refresh();
        goto cleanup;
    }

    snprintf(status_text, sizeof(status_text),
             "State : %s\nStop  : %s\nSignal: %d\nFunc  : %s\nFile  : %s:%d\n",
             session_state_text(session->state),
             session->last_status,
             session->last_signal,
             session->current_source.function[0] ? session->current_source.function : "(unknown)",
             session->current_source.file[0] ? session->current_source.file : "(no source)",
             session->current_source.line);
    append_text(status_text, sizeof(status_text), "\nProgram output:\n");
    append_text(status_text,
                sizeof(status_text),
                session->program_output[0] ? session->program_output : "(none)");
    if (!session->program_output[0] ||
        session->program_output[strlen(session->program_output) - 1] != '\n') {
        append_text(status_text, sizeof(status_text), "\n");
    }
    append_command_history(status_text, sizeof(status_text), session);
    append_text(status_text, sizeof(status_text), "Breakpoints:\n");
    xdbg_breakpoint_format_table(&session->breakpoints,
                                 status_text + strlen(status_text),
                                 sizeof(status_text) - (unsigned long)strlen(status_text));

    erase();
    if (session->layout == XDBG_LAYOUT_SRC) {
        draw_source_context(src_win, &session->current_source);
        draw_boxed_text(asm_win, "Assembly", "");
    } else if (session->layout == XDBG_LAYOUT_ASM) {
        draw_assembly_context(asm_win, session);
    } else {
        draw_source_context(src_win, &session->current_source);
        draw_assembly_context(asm_win, session);
    }
    draw_registers(regs_win, &session->regs);
    draw_boxed_text(status_win, "Status / Output", status_text);
    werase(cmd_win);
    draw_title(cmd_win, "Command");
    tui_attr_on(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    mvwprintw(cmd_win, 1, 1, "xdbg> ");
    tui_attr_off(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    wrefresh(cmd_win);

cleanup:
    if (src_win) delwin(src_win);
    if (asm_win) delwin(asm_win);
    if (regs_win) delwin(regs_win);
    if (status_win) delwin(status_win);
    if (cmd_win) delwin(cmd_win);
}

#else

int xdbg_tui_init(xdbg_session_t *session) {
    (void)session;
    return -1;
}

void xdbg_tui_shutdown(void) {
}

void xdbg_tui_render(const xdbg_session_t *session) {
    (void)session;
}

int xdbg_tui_read_command(xdbg_session_t *session, char *buffer, unsigned long buffer_size) {
    (void)session;
    (void)buffer;
    (void)buffer_size;
    return -1;
}

#endif
