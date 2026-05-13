#define _POSIX_C_SOURCE 200809L

#include "remote_client.h"

#include "remote_net.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int recv_response_block(int fd, char *response, size_t response_size) {
    static const char marker[] = "\n--xdbg-end--\n";
    const size_t marker_len = sizeof(marker) - 1;
    size_t used = 0;

    if (!response || response_size == 0) return -1;

    while (1) {
        char chunk[1024];
        ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
        char *marker_at;

        if (n <= 0) return -1;
        if (used + (size_t)n >= response_size) {
            fprintf(stderr, "remote response too large; dropping buffered output\n");
            used = 0;
        }

        memcpy(response + used, chunk, (size_t)n);
        used += (size_t)n;
        response[used] = '\0';

        if (used < marker_len) continue;
        marker_at = strstr(response, marker);
        if (!marker_at) continue;

        *marker_at = '\0';
        printf("%s", response);
        fflush(stdout);
        return 0;
    }
}

int xdbg_run_remote_client_impl(const char *connect_endpoint) {
    int fd;
    char line[1024];
    char response[65536];

    if (!connect_endpoint) return 1;
    fd = xdbg_remote_create_client_socket(connect_endpoint);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    if (recv_response_block(fd, response, sizeof(response)) != 0) goto out;

    while (1) {
        printf("xdbg-remote> ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        if (xdbg_remote_send_all(fd, line, strlen(line)) != 0) break;
        if (recv_response_block(fd, response, sizeof(response)) != 0) break;
        if (strcmp(line, "quit\n") == 0 || strcmp(line, "q\n") == 0) break;
    }
out:
    close(fd);
    return 0;
}
