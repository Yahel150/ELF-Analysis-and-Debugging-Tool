#ifndef XDBG_REMOTE_IPC_H
#define XDBG_REMOTE_IPC_H

#include <stdint.h>

typedef enum xdbg_ipc_message_type {
    XDBG_IPC_CMD_EXEC = 1,
    XDBG_IPC_CMD_SHUTDOWN = 2,
    XDBG_IPC_EVT_OUTPUT = 101,
    XDBG_IPC_EVT_EXITED = 102
} xdbg_ipc_message_type_t;

int xdbg_ipc_send_message(int fd, uint32_t type, const char *payload, uint32_t size);
int xdbg_ipc_recv_message(int fd, uint32_t *type, char *payload, uint32_t payload_capacity, uint32_t *payload_size);
int xdbg_ipc_write_all(int fd, const char *data, unsigned long size);
int xdbg_ipc_read_all(int fd, char *data, unsigned long size);

#endif
