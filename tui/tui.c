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
static char g_last_command[256];

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

static uint64_t runtime_function_start(const xdbg_session_t *session) {
    size_t i;
    uint64_t best = 0;

    if (!session || !session->has_elf) return 0;
    for (i = 0; i < session->elf.sym_count; ++i) {
        const Elf64_Sym *symbol = &session->elf.symtab[i];
        uint64_t start;
        uint64_t end;

        if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC || symbol->st_value == 0) continue;
        start = symbol->st_value;
        if (session->elf.ehdr && session->elf.ehdr->e_type == ET_DYN) {
            start += session->program_base;
        }
        end = start + (symbol->st_size ? symbol->st_size : 1);
        if (session->regs.rip >= start && session->regs.rip < end) {
            return start;
        }
        if (start < session->regs.rip && start > best) {
            best = start;
        }
    }
    return best;
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
    x86_decoded_instruction_t previous[4];
    x86_decoded_instruction_t current;
    uint64_t start;
    uint64_t address;
    int previous_count = 0;
    int found_current = 0;
    int row = 1;
    int width;

    werase(win);
    draw_title(win, "Assembly");
    width = clamp_positive_width(getmaxx(win) - 2);

    if (!session || session->current_instruction.length == 0) {
        mvwprintw(win, 1, 1, "%.*s", width, "Instruction unavailable");
        wrefresh(win);
        return;
    }

    start = runtime_function_start(session);
    if (start == 0 || start > session->regs.rip || session->regs.rip - start > 256) {
        start = session->regs.rip;
    }

    address = start;
    while (address <= session->regs.rip) {
        uint8_t bytes[16];
        x86_decoded_instruction_t instruction;

        if (xdbg_read_process_memory(session->pid, address, bytes, sizeof(bytes)) != 0 ||
            x86_decode_instruction(bytes, sizeof(bytes), address, &instruction) != 0 ||
            instruction.length == 0) {
            break;
        }
        if (address == session->regs.rip) {
            current = instruction;
            found_current = 1;
            break;
        }
        previous[previous_count % (int)(sizeof(previous) / sizeof(previous[0]))] = instruction;
        previous_count += 1;
        address += instruction.length;
    }

    if (!found_current) {
        current = session->current_instruction;
    }

    {
        int available_previous = previous_count < 4 ? previous_count : 4;
        int first = previous_count - available_previous;
        int i;

        for (i = 0; i < available_previous && row < getmaxy(win) - 1; ++i) {
            x86_decoded_instruction_t *instruction = &previous[(first + i) % 4];
            row = draw_instruction(win, row, instruction, 0, width);
        }
    }

    if (row < getmaxy(win) - 1) {
        row = draw_instruction(win, row, &current, 1, width);
    }

    address = current.address + current.length;
    while (row < getmaxy(win) - 1) {
        uint8_t bytes[16];
        x86_decoded_instruction_t instruction;

        if (xdbg_read_process_memory(session->pid, address, bytes, sizeof(bytes)) != 0 ||
            x86_decode_instruction(bytes, sizeof(bytes), address, &instruction) != 0 ||
            instruction.length == 0) {
            break;
        }
        row = draw_instruction(win, row, &instruction, 0, width);
        address += instruction.length;
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
    g_last_command[0] = '\0';
    return 0;
}

void xdbg_tui_shutdown(void) {
    if (!g_tui_initialized) return;
    endwin();
    g_tui_initialized = 0;
}

void xdbg_tui_note_command(const char *command_text) {
    if (!command_text) return;
    snprintf(g_last_command, sizeof(g_last_command), "%s", command_text);
}

int xdbg_tui_read_command(char *buffer, unsigned long buffer_size) {
    int rows;
    int cols;
    unsigned long used = 0;
    WINDOW *cmd_win;

    if (!g_tui_initialized || !buffer || buffer_size < 2) return -1;
    buffer[0] = '\0';

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
            if (used > 0) {
                used -= 1;
                buffer[used] = '\0';
                mvwaddch(cmd_win, 1, 7 + (int)used, ' ');
                wmove(cmd_win, 1, 7 + (int)used);
                wrefresh(cmd_win);
            }
            continue;
        }
        if (ch >= 32 && ch <= 126 && used + 1 < buffer_size) {
            buffer[used++] = (char)ch;
            waddch(cmd_win, ch);
            wrefresh(cmd_win);
        }
        if ((int)(7 + used) >= cols - 1) {
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
    char regs_text[1024];
    char status_text[4096];

    if (!g_tui_initialized || !session) return;

    getmaxyx(stdscr, rows, cols);
    if (rows < 10 || cols < 40) {
        erase();
        mvprintw(0, 0, "Terminal too small for xdbg TUI (%dx%d).", cols, rows);
        refresh();
        return;
    }

    top_height = rows / 2;
    bottom_height = rows - top_height - 3;
    left_width = cols / 2;

    src_win = newwin(top_height, left_width, 0, 0);
    asm_win = newwin(top_height, cols - left_width, 0, left_width);
    regs_win = newwin(bottom_height, left_width, top_height, 0);
    status_win = newwin(bottom_height, cols - left_width, top_height, left_width);
    cmd_win = newwin(3, cols, rows - 3, 0);
    if (!src_win || !asm_win || !regs_win || !status_win || !cmd_win) {
        erase();
        mvprintw(0, 0, "Unable to allocate xdbg TUI windows.");
        refresh();
        goto cleanup;
    }

    xdbg_format_registers(&session->regs, regs_text, sizeof(regs_text));
    snprintf(status_text, sizeof(status_text),
             "State : %s\nStop  : %s\nSignal: %d\nFunc  : %s\nFile  : %s:%d\n\nProgram output:\n%s%s\nBreakpoints:\n",
             session_state_text(session->state),
             session->last_status,
             session->last_signal,
             session->current_source.function[0] ? session->current_source.function : "(unknown)",
             session->current_source.file[0] ? session->current_source.file : "(no source)",
             session->current_source.line,
             session->program_output[0] ? session->program_output : "(none)",
             session->program_output[0] && session->program_output[strlen(session->program_output) - 1] == '\n' ? "" : "\n");
    xdbg_breakpoint_format_table(&session->breakpoints,
                                 status_text + strlen(status_text),
                                 sizeof(status_text) - (unsigned long)strlen(status_text));

    erase();
    if (session->layout == XDBG_LAYOUT_SRC) {
        draw_source_context(src_win, &session->current_source);
        draw_boxed_text(asm_win, "Assembly", "");
    } else if (session->layout == XDBG_LAYOUT_ASM) {
        draw_boxed_text(src_win, "Source", "");
        draw_assembly_context(asm_win, session);
    } else {
        draw_source_context(src_win, &session->current_source);
        draw_assembly_context(asm_win, session);
    }
    draw_boxed_text(regs_win, "Registers", regs_text);
    draw_boxed_text(status_win, "Status / Output", status_text);
    werase(cmd_win);
    draw_title(cmd_win, "Command");
    tui_attr_on(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    mvwprintw(cmd_win, 1, 1, "xdbg> ");
    tui_attr_off(cmd_win, XDBG_COLOR_STATUS, A_BOLD);
    mvwprintw(cmd_win, 1, 7, "%.*s", cols - 9, g_last_command[0] ? g_last_command : session->last_status);
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

void xdbg_tui_note_command(const char *command_text) {
    (void)command_text;
}

int xdbg_tui_read_command(char *buffer, unsigned long buffer_size) {
    (void)buffer;
    (void)buffer_size;
    return -1;
}

#endif
