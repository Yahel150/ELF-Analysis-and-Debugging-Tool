#ifndef XDBG_DEBUGGER_H
#define XDBG_DEBUGGER_H

#include "../decoder/decode.h"
#include "../elf/elf_parser.h"
#include "breakpoint.h"
#include "registers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum xdbg_layout_mode {
    XDBG_LAYOUT_SRC = 0,
    XDBG_LAYOUT_ASM,
    XDBG_LAYOUT_SPLIT
} xdbg_layout_mode_t;

typedef enum xdbg_stop_reason {
    XDBG_STOP_NONE = 0,
    XDBG_STOP_SIGNAL,
    XDBG_STOP_BREAKPOINT,
    XDBG_STOP_STEP,
    XDBG_STOP_SYSCALL,
    XDBG_STOP_EXITED
} xdbg_stop_reason_t;

typedef enum xdbg_session_state {
    XDBG_SESSION_IDLE = 0,
    XDBG_SESSION_RUNNING,
    XDBG_SESSION_STOPPED,
    XDBG_SESSION_EXITED
} xdbg_session_state_t;

typedef struct xdbg_source_location {
    char function[128];
    char file[260];
    int line;
    int has_location;
    int has_source_file;
} xdbg_source_location_t;

typedef struct xdbg_got_watch {
    int active;
    char symbol[64];
    uint64_t slot_address;
    uint64_t last_value;
} xdbg_got_watch_t;

typedef struct xdbg_session {
    int pid;
    int attached;
    int exited;
    int last_signal;
    int should_quit;
    xdbg_session_state_t state;
    xdbg_stop_reason_t stop_reason;
    xdbg_layout_mode_t layout;
    char program_path[260];
    char program_args_text[512];
    char last_status[256];
    char program_output[2048];
    uint64_t program_base;
    int output_fd;
    int pending_signal;
    elf_file_t elf;
    int has_elf;
    xdbg_registers_t regs;
    x86_decoded_instruction_t current_instruction;
    xdbg_source_location_t current_source;
    xdbg_breakpoint_table_t breakpoints;
    xdbg_got_watch_t got_watches[16];
    size_t got_watch_count;
    int tui_enabled;
    int syscall_trace_enabled;
} xdbg_session_t;

int xdbg_run_debugger(int argc, char **argv);
int xdbg_session_refresh_stop_state(xdbg_session_t *session);

#endif
