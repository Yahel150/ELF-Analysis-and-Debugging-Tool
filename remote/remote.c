#include "remote.h"

#include "remote_client.h"
#include "remote_worker.h"

int xdbg_run_remote_worker(const char *self_path,
                           const char *listen_endpoint,
                           int target_argc,
                           char **target_argv) {
    return xdbg_run_remote_worker_impl(self_path, listen_endpoint, target_argc, target_argv);
}

int xdbg_run_remote_client(const char *connect_endpoint) {
    return xdbg_run_remote_client_impl(connect_endpoint);
}
