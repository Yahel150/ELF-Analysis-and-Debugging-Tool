#ifndef XDBG_REMOTE_H
#define XDBG_REMOTE_H

int xdbg_run_remote_worker(const char *self_path,
                           const char *listen_endpoint,
                           int target_argc,
                           char **target_argv);
int xdbg_run_remote_client(const char *connect_endpoint);

#endif
