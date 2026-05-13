#define _POSIX_C_SOURCE 200809L

#include "remote_ipc.h"

#include <stddef.h>
#include <unistd.h>

typedef struct xdbg_ipc_header {
    uint32_t type;
    uint32_t size;
} xdbg_ipc_header_t;

int xdbg_ipc_write_all(int fd, const char *data, unsigned long size) {
    unsigned long written = 0;
    while (written < size) {
        ssize_t n = write(fd, data + written, size - written);
        if (n <= 0) return -1;
        written += (unsigned long)n;
    }
    return 0;
}

int xdbg_ipc_read_all(int fd, char *data, unsigned long size) {
    unsigned long used = 0;
    while (used < size) {
        ssize_t n = read(fd, data + used, size - used);
        if (n <= 0) return -1;
        used += (unsigned long)n;
    }
    return 0;
}

int xdbg_ipc_send_message(int fd, uint32_t type, const char *payload, uint32_t size) {
    xdbg_ipc_header_t header;
    header.type = type;
    header.size = size;
    if (xdbg_ipc_write_all(fd, (const char *)&header, sizeof(header)) != 0) return -1;
    if (size > 0 && payload) {
        if (xdbg_ipc_write_all(fd, payload, size) != 0) return -1;
    }
    return 0;
}

int xdbg_ipc_recv_message(int fd, uint32_t *type, char *payload, uint32_t payload_capacity, uint32_t *payload_size) {
    xdbg_ipc_header_t header;
    if (!type || !payload_size) return -1;
    if (xdbg_ipc_read_all(fd, (char *)&header, sizeof(header)) != 0) return -1;
    *type = header.type;
    *payload_size = header.size;
    if (header.size == 0) return 0;
    if (!payload || header.size > payload_capacity) {
        char discard[256];
        uint32_t left = header.size;
        while (left > 0) {
            uint32_t chunk = left > sizeof(discard) ? (uint32_t)sizeof(discard) : left;
            if (xdbg_ipc_read_all(fd, discard, chunk) != 0) return -1;
            left -= chunk;
        }
        return -1;
    }
    return xdbg_ipc_read_all(fd, payload, header.size);
}
