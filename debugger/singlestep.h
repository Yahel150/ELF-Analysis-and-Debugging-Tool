#ifndef XDBG_DEBUGGER_SINGLESTEP_H
#define XDBG_DEBUGGER_SINGLESTEP_H

#include <stdint.h>

int xdbg_ptrace_continue(int pid, int signal_number);
int xdbg_ptrace_singlestep(int pid, int signal_number);
int xdbg_ptrace_syscall(int pid, int signal_number);
uint64_t xdbg_read_rflags_local(void);
void xdbg_write_tf_local(int enabled);

#endif
