#ifndef XDBG_DEBUGGER_REGISTERS_H
#define XDBG_DEBUGGER_REGISTERS_H

#include <stdint.h>

typedef struct xdbg_registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
} xdbg_registers_t;

int xdbg_get_registers(int pid, xdbg_registers_t *out);
int xdbg_set_registers(int pid, const xdbg_registers_t *in);
void xdbg_format_registers(const xdbg_registers_t *regs, char *buffer, unsigned long buffer_size);
void xdbg_print_registers(const xdbg_registers_t *regs);

#endif
