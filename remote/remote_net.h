#ifndef XDBG_REMOTE_NET_H
#define XDBG_REMOTE_NET_H

#include <stddef.h>

int xdbg_remote_create_listen_socket(const char *endpoint);
int xdbg_remote_create_client_socket(const char *endpoint);
int xdbg_remote_send_all(int fd, const char *data, size_t size);
int xdbg_remote_recv_line(int fd, char *buffer, size_t buffer_size);

#endif
