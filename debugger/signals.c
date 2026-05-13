#define _POSIX_C_SOURCE 200809L

#include "signals.h"

#ifdef __linux__
#include <signal.h>
#include <string.h>
#endif

typedef struct xdbg_signal_state {
    xdbg_signal_callback_t callback;
    void *userdata;
} xdbg_signal_state_t;

static xdbg_signal_state_t g_signal_state;

#ifdef __linux__
static void xdbg_signal_handler(int signal_number) {
    if (g_signal_state.callback) {
        g_signal_state.callback(signal_number, g_signal_state.userdata);
    }
}
#endif

int xdbg_signals_install(xdbg_signal_callback_t callback, void *userdata) {
    g_signal_state.callback = callback;
    g_signal_state.userdata = userdata;
#ifdef __linux__
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = xdbg_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGINT, &sa, NULL) != 0) return -1;
        if (sigaction(SIGTERM, &sa, NULL) != 0) return -1;
    }
#endif
    return 0;
}

void xdbg_signals_uninstall(void) {
    g_signal_state.callback = 0;
    g_signal_state.userdata = 0;
}
