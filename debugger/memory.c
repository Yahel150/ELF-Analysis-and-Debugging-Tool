#include "memory.h"

#ifndef __linux__
#error "xdbg process memory access requires Linux ptrace"
#endif

#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>

int xdbg_peek_text_word(int pid, uint64_t address, uint64_t *word) {
    long value;

    if (!word) return -1;
    errno = 0;
    value = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)address, NULL);
    if (value == -1 && errno != 0) return -1;
    *word = (uint64_t)(unsigned long)value;
    return 0;
}

int xdbg_poke_text_word(int pid, uint64_t address, uint64_t word) {
    return ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)address, (void *)(uintptr_t)word) == -1 ? -1 : 0;
}

int xdbg_read_process_memory(int pid, uint64_t address, uint8_t *buffer, size_t size) {
    size_t offset = 0;

    if (!buffer) return -1;
    while (offset < size) {
        uint64_t word = 0;
        size_t chunk = sizeof(word);

        if (xdbg_peek_text_word(pid, address + offset, &word) != 0) return -1;
        if (chunk > size - offset) chunk = size - offset;
        memcpy(buffer + offset, &word, chunk);
        offset += chunk;
    }
    return 0;
}
