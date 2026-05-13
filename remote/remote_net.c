#define _POSIX_C_SOURCE 200809L

#include "remote_net.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int split_endpoint(const char *endpoint, char *host, size_t host_size, char *port, size_t port_size) {
    const char *colon;
    size_t host_len;
    if (!endpoint || !host || !port || host_size == 0 || port_size == 0) return -1;
    colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint || *(colon + 1) == '\0') return -1;
    host_len = (size_t)(colon - endpoint);
    if (host_len >= host_size) return -1;
    memcpy(host, endpoint, host_len);
    host[host_len] = '\0';
    if (snprintf(port, port_size, "%s", colon + 1) >= (int)port_size) return -1;
    return 0;
}

int xdbg_remote_create_listen_socket(const char *endpoint) {
    char host[128];
    char port[32];
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *it;
    int fd = -1;
    int on = 1;
    if (split_endpoint(endpoint, host, sizeof(host), port, sizeof(port)) != 0) return -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(host, port, &hints, &results) != 0) return -1;
    for (it = results; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (bind(fd, it->ai_addr, it->ai_addrlen) == 0 && listen(fd, 1) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}

int xdbg_remote_create_client_socket(const char *endpoint) {
    char host[128];
    char port[32];
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *it;
    int fd = -1;
    if (split_endpoint(endpoint, host, sizeof(host), port, sizeof(port)) != 0) return -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &results) != 0) return -1;
    for (it = results; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    return fd;
}

int xdbg_remote_send_all(int fd, const char *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t n = send(fd, data + written, size - written, 0);
        if (n <= 0) return -1;
        written += (size_t)n;
    }
    return 0;
}

int xdbg_remote_recv_line(int fd, char *buffer, size_t buffer_size) {
    size_t used = 0;
    if (!buffer || buffer_size < 2) return -1;
    while (used + 1 < buffer_size) {
        char ch;
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n <= 0) return -1;
        if (ch == '\r') continue;
        buffer[used++] = ch;
        if (ch == '\n') break;
    }
    buffer[used] = '\0';
    return 0;
}
