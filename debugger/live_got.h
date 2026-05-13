#ifndef XDBG_DEBUGGER_LIVE_GOT_H
#define XDBG_DEBUGGER_LIVE_GOT_H

#include "../elf/elf_parser.h"

#include <stdint.h>

int xdbg_live_got_find_slot(const elf_file_t *elf, const char *symbol_name, uint64_t *slot_address);
int xdbg_live_got_read_slot(int pid, uint64_t slot_address, uint64_t *slot_value);
int xdbg_live_got_is_plt_address(const elf_file_t *elf, uint64_t runtime_address, uint64_t module_bias);

#endif
