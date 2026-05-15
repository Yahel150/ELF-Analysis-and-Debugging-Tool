#ifndef XDBG_TUI_H
#define XDBG_TUI_H

#include "../debugger/debugger.h"

int xdbg_tui_init(xdbg_session_t *session);
void xdbg_tui_shutdown(void);
void xdbg_tui_render(const xdbg_session_t *session);
int xdbg_tui_read_command(xdbg_session_t *session, char *buffer, unsigned long buffer_size);

#endif
