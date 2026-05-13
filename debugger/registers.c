#include "registers.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error "xdbg register access requires Linux on x86-64"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int xdbg_get_registers(int pid, xdbg_registers_t *out) {
    struct user_regs_struct native_regs;

    if (!out) return -1;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &native_regs) == -1) return -1;

    memset(out, 0, sizeof(*out));
    out->rax = native_regs.rax;
    out->rbx = native_regs.rbx;
    out->rcx = native_regs.rcx;
    out->rdx = native_regs.rdx;
    out->rsi = native_regs.rsi;
    out->rdi = native_regs.rdi;
    out->rbp = native_regs.rbp;
    out->rsp = native_regs.rsp;
    out->r8 = native_regs.r8;
    out->r9 = native_regs.r9;
    out->r10 = native_regs.r10;
    out->r11 = native_regs.r11;
    out->r12 = native_regs.r12;
    out->r13 = native_regs.r13;
    out->r14 = native_regs.r14;
    out->r15 = native_regs.r15;
    out->rip = native_regs.rip;
    out->rflags = native_regs.eflags;
    return 0;
}

int xdbg_set_registers(int pid, const xdbg_registers_t *in) {
    struct user_regs_struct native_regs;

    if (!in) return -1;
    memset(&native_regs, 0, sizeof(native_regs));
    native_regs.rax = in->rax;
    native_regs.rbx = in->rbx;
    native_regs.rcx = in->rcx;
    native_regs.rdx = in->rdx;
    native_regs.rsi = in->rsi;
    native_regs.rdi = in->rdi;
    native_regs.rbp = in->rbp;
    native_regs.rsp = in->rsp;
    native_regs.r8 = in->r8;
    native_regs.r9 = in->r9;
    native_regs.r10 = in->r10;
    native_regs.r11 = in->r11;
    native_regs.r12 = in->r12;
    native_regs.r13 = in->r13;
    native_regs.r14 = in->r14;
    native_regs.r15 = in->r15;
    native_regs.rip = in->rip;
    native_regs.eflags = in->rflags;
    return ptrace(PTRACE_SETREGS, pid, NULL, &native_regs) == -1 ? -1 : 0;
}

void xdbg_format_registers(const xdbg_registers_t *regs, char *buffer, unsigned long buffer_size) {
    if (!regs || !buffer || buffer_size == 0) return;
    snprintf(buffer, (size_t)buffer_size,
             "RAX=%016llx RBX=%016llx RCX=%016llx RDX=%016llx\n"
             "RSI=%016llx RDI=%016llx RBP=%016llx RSP=%016llx\n"
             "R8 =%016llx R9 =%016llx R10=%016llx R11=%016llx\n"
             "R12=%016llx R13=%016llx R14=%016llx R15=%016llx\n"
             "RIP=%016llx RFLAGS=%016llx\n",
             (unsigned long long)regs->rax, (unsigned long long)regs->rbx,
             (unsigned long long)regs->rcx, (unsigned long long)regs->rdx,
             (unsigned long long)regs->rsi, (unsigned long long)regs->rdi,
             (unsigned long long)regs->rbp, (unsigned long long)regs->rsp,
             (unsigned long long)regs->r8, (unsigned long long)regs->r9,
             (unsigned long long)regs->r10, (unsigned long long)regs->r11,
             (unsigned long long)regs->r12, (unsigned long long)regs->r13,
             (unsigned long long)regs->r14, (unsigned long long)regs->r15,
             (unsigned long long)regs->rip, (unsigned long long)regs->rflags);
}

void xdbg_print_registers(const xdbg_registers_t *regs) {
    char buffer[512];

    xdbg_format_registers(regs, buffer, sizeof(buffer));
    printf("%s", buffer);
}
