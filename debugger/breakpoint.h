#ifndef XDBG_DEBUGGER_BREAKPOINT_H
#define XDBG_DEBUGGER_BREAKPOINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum xdbg_breakpoint_kind {
    XDBG_BREAKPOINT_ADDRESS = 0,
    XDBG_BREAKPOINT_SYMBOL,
    XDBG_BREAKPOINT_FILE_LINE
} xdbg_breakpoint_kind_t;

typedef struct xdbg_breakpoint {
    int id;
    uint64_t address;
    uint8_t original_byte;
    bool enabled;
    bool temporary;
    bool installed;
    xdbg_breakpoint_kind_t kind;
    char spec[128];
} xdbg_breakpoint_t;

typedef struct xdbg_breakpoint_table {
    xdbg_breakpoint_t items[128];
    size_t count;
    int next_id;
} xdbg_breakpoint_table_t;

void xdbg_breakpoint_table_init(xdbg_breakpoint_table_t *table);
xdbg_breakpoint_t *xdbg_breakpoint_add(xdbg_breakpoint_table_t *table,
                                       uint64_t address,
                                       xdbg_breakpoint_kind_t kind,
                                       const char *spec,
                                       bool temporary);
xdbg_breakpoint_t *xdbg_breakpoint_find_by_id(xdbg_breakpoint_table_t *table, int id);
xdbg_breakpoint_t *xdbg_breakpoint_find_by_address(xdbg_breakpoint_table_t *table, uint64_t address);
int xdbg_breakpoint_install(int pid, xdbg_breakpoint_t *bp);
int xdbg_breakpoint_remove(int pid, xdbg_breakpoint_t *bp);
int xdbg_breakpoint_enable(int pid, xdbg_breakpoint_t *bp);
int xdbg_breakpoint_disable(int pid, xdbg_breakpoint_t *bp);
void xdbg_breakpoint_delete(xdbg_breakpoint_table_t *table, size_t index);
void xdbg_breakpoint_format_table(const xdbg_breakpoint_table_t *table, char *buffer, unsigned long buffer_size);

#endif
