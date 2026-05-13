#define _POSIX_C_SOURCE 200809L

#include "remote_worker.h"

#include "remote_ipc.h"
#include "remote_net.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int has_prompt_suffix(const char *buffer, size_t len) {
    static const char prompt[] = "xdbg> ";
    size_t prompt_len = sizeof(prompt) - 1;
    if (len < prompt_len) return 0;
    return memcmp(buffer + len - prompt_len, prompt, prompt_len) == 0;
}

static int pump_backend_until_prompt_buffer(int backend_out, char *buffer, size_t capacity, size_t *out_size) {
    size_t used = 0;
    if (!buffer || capacity == 0 || !out_size) return -1;
    while (used + 1 < capacity) {
        char ch;
        ssize_t n = read(backend_out, &ch, 1);
        if (n <= 0) return -1;
        buffer[used++] = ch;
        if (has_prompt_suffix(buffer, used)) {
            used -= 6;
            break;
        }
    }
    buffer[used] = '\0';
    *out_size = used;
    return 0;
}

static int send_client_block_with_marker(int client_fd, const char *buffer, size_t size) {
    static const char end_marker[] = "\n--xdbg-end--\n";
    if (xdbg_remote_send_all(client_fd, buffer, size) != 0) return -1;
    if (xdbg_remote_send_all(client_fd, end_marker, sizeof(end_marker) - 1) != 0) return -1;
    return 0;
}

static int xdbg_tracer_process(const char *self_path,
                               int target_argc,
                               char **target_argv,
                               int command_read_fd,
                               int event_write_fd) {
    int in_pipe[2];
    int out_pipe[2];
    pid_t backend_child;
    char output[65536];
    uint32_t msg_type = 0;
    uint32_t msg_size = 0;
    size_t output_size = 0;
    char command[1024];
    int status;
    if (pipe(in_pipe) != 0) return 1;
    if (pipe(out_pipe) != 0) {
        close(in_pipe[0]);
        close(in_pipe[1]);
        return 1;
    }

    backend_child = fork();
    if (backend_child == -1) {
        close(in_pipe[0]); close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        return 1;
    }
    if (backend_child == 0) {
        char *args[96];
        int i;
        int idx = 0;
        dup2(in_pipe[0], STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(out_pipe[1], STDERR_FILENO);
        close(in_pipe[1]);
        close(out_pipe[0]);
        args[idx++] = (char *)self_path;
        args[idx++] = "debug";
        for (i = 0; i < target_argc && idx + 1 < (int)(sizeof(args) / sizeof(args[0])); ++i) args[idx++] = target_argv[i];
        args[idx] = NULL;
        execv(self_path, args);
        _exit(127);
    }

    close(in_pipe[0]);
    close(out_pipe[1]);
    if (pump_backend_until_prompt_buffer(out_pipe[0], output, sizeof(output), &output_size) != 0) return 1;
    if (output_size > UINT32_MAX) output_size = UINT32_MAX;
    msg_size = (uint32_t)output_size;
    if (xdbg_ipc_send_message(event_write_fd, XDBG_IPC_EVT_OUTPUT, output, msg_size) != 0) return 1;

    while (xdbg_ipc_recv_message(command_read_fd, &msg_type, command, sizeof(command) - 1, &msg_size) == 0) {
        command[msg_size < sizeof(command) ? msg_size : sizeof(command) - 1] = '\0';
        if (msg_type == XDBG_IPC_CMD_SHUTDOWN) break;
        if (msg_type != XDBG_IPC_CMD_EXEC) continue;
        if (xdbg_ipc_write_all(in_pipe[1], command, (unsigned long)strlen(command)) != 0) break;
        if (xdbg_ipc_write_all(in_pipe[1], "\n", 1) != 0) break;
        if (pump_backend_until_prompt_buffer(out_pipe[0], output, sizeof(output), &output_size) != 0) break;
        if (output_size > UINT32_MAX) output_size = UINT32_MAX;
        msg_size = (uint32_t)output_size;
        if (xdbg_ipc_send_message(event_write_fd, XDBG_IPC_EVT_OUTPUT, output, msg_size) != 0) break;
        if (strcmp(command, "quit") == 0 || strcmp(command, "q") == 0) {
            xdbg_ipc_send_message(event_write_fd, XDBG_IPC_EVT_EXITED, NULL, 0);
            break;
        }
    }

    close(in_pipe[1]);
    close(out_pipe[0]);
    waitpid(backend_child, &status, 0);
    return 0;
}

int xdbg_run_remote_worker_impl(const char *self_path,
                                const char *listen_endpoint,
                                int target_argc,
                                char **target_argv) {
    int listen_fd = -1;
    int client_fd = -1;
    int command_pipe[2];
    int event_pipe[2];
    pid_t tracer;
    int status = 0;
    int result = 1;
    char line[1024];
    char event_payload[65536];
    uint32_t event_type = 0;
    uint32_t event_size = 0;
    if (!self_path || !listen_endpoint) return 1;
    if (pipe(command_pipe) != 0) return 1;
    if (pipe(event_pipe) != 0) {
        close(command_pipe[0]); close(command_pipe[1]);
        return 1;
    }
    tracer = fork();
    if (tracer == -1) return 1;
    if (tracer == 0) {
        close(command_pipe[1]);
        close(event_pipe[0]);
        _exit(xdbg_tracer_process(self_path, target_argc, target_argv, command_pipe[0], event_pipe[1]) == 0 ? 0 : 1);
    }
    close(command_pipe[0]);
    close(event_pipe[1]);

    listen_fd = xdbg_remote_create_listen_socket(listen_endpoint);
    if (listen_fd < 0) goto cleanup;
    fprintf(stderr, "xdbg-worker listening on %s\n", listen_endpoint);
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) goto cleanup;
    if (xdbg_ipc_recv_message(event_pipe[0], &event_type, event_payload, sizeof(event_payload), &event_size) != 0) goto cleanup;
    if (event_type != XDBG_IPC_EVT_OUTPUT) goto cleanup;
    if (send_client_block_with_marker(client_fd, event_payload, event_size) != 0) goto cleanup;

    while (xdbg_remote_recv_line(client_fd, line, sizeof(line)) == 0) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (xdbg_ipc_send_message(command_pipe[1], XDBG_IPC_CMD_EXEC, line, (uint32_t)strlen(line)) != 0) break;
        if (xdbg_ipc_recv_message(event_pipe[0], &event_type, event_payload, sizeof(event_payload), &event_size) != 0) break;
        if (event_type != XDBG_IPC_EVT_OUTPUT) break;
        if (send_client_block_with_marker(client_fd, event_payload, event_size) != 0) break;
        if (strcmp(line, "quit") == 0 || strcmp(line, "q") == 0) break;
    }
    result = 0;

cleanup:
    if (client_fd >= 0) close(client_fd);
    if (listen_fd >= 0) close(listen_fd);
    xdbg_ipc_send_message(command_pipe[1], XDBG_IPC_CMD_SHUTDOWN, NULL, 0);
    close(command_pipe[1]);
    close(event_pipe[0]);
    waitpid(tracer, &status, 0);
    return result;
}
