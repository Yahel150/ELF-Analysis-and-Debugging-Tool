#include "singlestep.h"

#if !defined(__linux__) || !defined(__x86_64__)
#error "xdbg ptrace stepping requires Linux on x86-64"
#endif

#include <stddef.h>
#include <sys/ptrace.h>

int xdbg_ptrace_continue(int pid, int signal_number) {
    return ptrace(PTRACE_CONT, pid, NULL, (void *)(long)signal_number) == -1 ? -1 : 0;
}

int xdbg_ptrace_singlestep(int pid, int signal_number) {
    return ptrace(PTRACE_SINGLESTEP, pid, NULL, (void *)(long)signal_number) == -1 ? -1 : 0;
}

int xdbg_ptrace_syscall(int pid, int signal_number) {
    return ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)signal_number) == -1 ? -1 : 0;
}

uint64_t xdbg_read_rflags_local(void) {
    uint64_t flags = 0;
    __asm__ volatile("pushfq\n\tpopq %0" : "=r"(flags));
    return flags;
}

void xdbg_write_tf_local(int enabled) {
    uint64_t flags = xdbg_read_rflags_local();
    if (enabled) flags |= (1ull << 8);
    else flags &= ~(1ull << 8);
    __asm__ volatile("pushq %0\n\tpopfq" : : "r"(flags) : "cc");
}
