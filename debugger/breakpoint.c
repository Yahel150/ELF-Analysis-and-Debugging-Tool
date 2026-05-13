#include "breakpoint.h"
#include "memory.h"

#include <stdio.h>
#include <string.h>

void xdbg_breakpoint_table_init(xdbg_breakpoint_table_t *table) {
    if (!table) return;
    memset(table, 0, sizeof(*table));
    table->next_id = 1;
}

xdbg_breakpoint_t *xdbg_breakpoint_add(xdbg_breakpoint_table_t *table,
                                       uint64_t address,
                                       xdbg_breakpoint_kind_t kind,
                                       const char *spec,
                                       bool temporary) {
    xdbg_breakpoint_t *bp;

    if (!table || table->count >= sizeof(table->items) / sizeof(table->items[0])) return NULL;
    bp = &table->items[table->count++];
    memset(bp, 0, sizeof(*bp));
    bp->id = table->next_id++;
    bp->address = address;
    bp->enabled = true;
    bp->temporary = temporary;
    bp->kind = kind;
    if (spec) snprintf(bp->spec, sizeof(bp->spec), "%s", spec);
    return bp;
}

xdbg_breakpoint_t *xdbg_breakpoint_find_by_id(xdbg_breakpoint_table_t *table, int id) {
    size_t i;
    if (!table) return NULL;
    for (i = 0; i < table->count; ++i) {
        if (table->items[i].id == id) return &table->items[i];
    }
    return NULL;
}

xdbg_breakpoint_t *xdbg_breakpoint_find_by_address(xdbg_breakpoint_table_t *table, uint64_t address) {
    size_t i;
    if (!table) return NULL;
    for (i = 0; i < table->count; ++i) {
        if (table->items[i].address == address) return &table->items[i];
    }
    return NULL;
}

int xdbg_breakpoint_install(int pid, xdbg_breakpoint_t *bp) {
    uint64_t word = 0;

    if (!bp || !bp->enabled || bp->installed) return 0;
    if (xdbg_peek_text_word(pid, bp->address, &word) != 0) return -1;
    bp->original_byte = (uint8_t)(word & 0xFFu);
    word = (word & ~0xFFull) | 0xCCu;
    if (xdbg_poke_text_word(pid, bp->address, word) != 0) return -1;
    bp->installed = true;
    return 0;
}

int xdbg_breakpoint_remove(int pid, xdbg_breakpoint_t *bp) {
    uint64_t word = 0;

    if (!bp || !bp->installed) return 0;
    if (xdbg_peek_text_word(pid, bp->address, &word) != 0) return -1;
    word = (word & ~0xFFull) | bp->original_byte;
    if (xdbg_poke_text_word(pid, bp->address, word) != 0) return -1;
    bp->installed = false;
    return 0;
}

int xdbg_breakpoint_enable(int pid, xdbg_breakpoint_t *bp) {
    if (!bp) return -1;
    bp->enabled = true;
    if (pid <= 0) return 0;
    return xdbg_breakpoint_install(pid, bp);
}

int xdbg_breakpoint_disable(int pid, xdbg_breakpoint_t *bp) {
    if (!bp) return -1;
    bp->enabled = false;
    if (pid <= 0) {
        bp->installed = false;
        return 0;
    }
    return xdbg_breakpoint_remove(pid, bp);
}

void xdbg_breakpoint_delete(xdbg_breakpoint_table_t *table, size_t index) {
    size_t i;
    if (!table || index >= table->count) return;
    for (i = index; i + 1 < table->count; ++i) {
        table->items[i] = table->items[i + 1];
    }
    table->count -= 1;
}

void xdbg_breakpoint_format_table(const xdbg_breakpoint_table_t *table, char *buffer, unsigned long buffer_size) {
    size_t i;
    size_t used = 0;

    if (!buffer || buffer_size == 0) return;
    buffer[0] = '\0';
    if (!table || table->count == 0) {
        snprintf(buffer, (size_t)buffer_size, "No breakpoints\n");
        return;
    }

    for (i = 0; i < table->count && used < buffer_size; ++i) {
        const xdbg_breakpoint_t *bp = &table->items[i];
        int written = snprintf(buffer + used, (size_t)buffer_size - used,
                               "#%d %s %s @ 0x%llx %s\n",
                               bp->id,
                               bp->enabled ? "enabled " : "disabled",
                               bp->temporary ? "temp" : "perm",
                               (unsigned long long)bp->address,
                               bp->spec[0] ? bp->spec : "(address)");
        if (written < 0 || (unsigned long)written >= buffer_size - used) break;
        used += (size_t)written;
    }
}
