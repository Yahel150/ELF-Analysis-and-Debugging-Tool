#ifndef XDBG_DEBUGGER_MEMORY_H
#define XDBG_DEBUGGER_MEMORY_H

#include <stddef.h>
#include <stdint.h>

int xdbg_peek_text_word(int pid, uint64_t address, uint64_t *word);
int xdbg_poke_text_word(int pid, uint64_t address, uint64_t word);
int xdbg_read_process_memory(int pid, uint64_t address, uint8_t *buffer, size_t size);

#endif
