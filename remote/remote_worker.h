#ifndef XDBG_REMOTE_WORKER_H
#define XDBG_REMOTE_WORKER_H

int xdbg_run_remote_worker_impl(const char *self_path,
                                const char *listen_endpoint,
                                int target_argc,
                                char **target_argv);

#endif
