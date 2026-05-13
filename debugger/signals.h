#ifndef XDBG_DEBUGGER_SIGNALS_H
#define XDBG_DEBUGGER_SIGNALS_H

typedef void (*xdbg_signal_callback_t)(int signal_number, void *userdata);

int xdbg_signals_install(xdbg_signal_callback_t callback, void *userdata);
void xdbg_signals_uninstall(void);

#endif
