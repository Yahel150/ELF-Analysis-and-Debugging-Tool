#ifndef XDBG_SOURCE_MAP_H
#define XDBG_SOURCE_MAP_H

#include "../debugger/debugger.h"

int xdbg_source_map_resolve(const xdbg_session_t *session, uint64_t address, xdbg_source_location_t *out);
int xdbg_source_map_load_context(const xdbg_source_location_t *location,
                                 char *buffer,
                                 unsigned long buffer_size,
                                 int context_lines);

#endif
