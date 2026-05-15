#define _POSIX_C_SOURCE 200809L

#include "source_map.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim_newline(char *text) {
    size_t len;
    if (!text) return;
    len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len -= 1;
    }
}

int xdbg_source_map_resolve(const xdbg_session_t *session, uint64_t address, xdbg_source_location_t *out) {
    const Elf64_Sym *symbol;
    uint64_t module_bias = 0;
    uint64_t normalized_address = address;

    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    if (session && session->has_elf && session->elf.ehdr && session->elf.ehdr->e_type == ET_DYN) {
        module_bias = session->program_base;
        if (address >= module_bias) normalized_address = address - module_bias;
    }

    if (session && session->has_elf) {
        size_t i;
        symbol = NULL;
        for (i = 0; i < session->elf.sym_count; ++i) {
            const Elf64_Sym *candidate = &session->elf.symtab[i];
            uint64_t symbol_start;
            uint64_t symbol_end;
            if (ELF64_ST_TYPE(candidate->st_info) != STT_FUNC) continue;
            symbol_start = candidate->st_value + module_bias;
            symbol_end = symbol_start + (candidate->st_size ? candidate->st_size : 1);
            if (address >= symbol_start && address < symbol_end) {
                symbol = candidate;
                break;
            }
        }
        if (symbol) {
            const char *name = elf_symbol_name(&session->elf, symbol, false);
            if (name) snprintf(out->function, sizeof(out->function), "%s", name);
        }
    }

#ifdef __linux__
    if (session && session->program_path[0]) {
        char command[768];
        char file_line[320];
        FILE *pipe;

        snprintf(command, sizeof(command), "addr2line -f -e \"%s\" 0x%llx 2>/dev/null",
                 session->program_path,
                 (unsigned long long)normalized_address);
        pipe = popen(command, "r");
        if (pipe) {
            if (fgets(out->function, (int)sizeof(out->function), pipe)) {
                trim_newline(out->function);
            }
            if (fgets(file_line, (int)sizeof(file_line), pipe)) {
                char *colon;
                trim_newline(file_line);
                colon = strrchr(file_line, ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(out->file, sizeof(out->file), "%s", file_line);
                    out->line = atoi(colon + 1);
                    out->has_location = 1;
                    out->has_source_file = out->file[0] != '\0' && strcmp(out->file, "??") != 0;
                }
            }
            pclose(pipe);
        }
    }
#else
    (void)address;
#endif

    return 0;
}

int xdbg_source_map_load_context(const xdbg_source_location_t *location,
                                 char *buffer,
                                 unsigned long buffer_size,
                                 int context_lines) {
    FILE *file;
    char line[512];
    int current_line = 0;
    int start_line;
    int end_line;
    size_t used = 0;

    if (!buffer || buffer_size == 0) return -1;
    buffer[0] = '\0';
    if (!location || !location->has_source_file || location->line <= 0) {
        snprintf(buffer, (size_t)buffer_size, "Source unavailable\n");
        return -1;
    }

    file = fopen(location->file, "r");
    if (!file) {
        snprintf(buffer, (size_t)buffer_size, "Source file not found: %s\n", location->file);
        return -1;
    }

    start_line = location->line - context_lines;
    end_line = location->line + context_lines;
    if (start_line < 1) start_line = 1;

    while (fgets(line, sizeof(line), file)) {
        int written;
        current_line += 1;
        if (current_line < start_line) continue;
        if (current_line > end_line) break;
        trim_newline(line);
        written = snprintf(buffer + used, (size_t)buffer_size - used,
                           "%c %4d %s\n",
                           current_line == location->line ? '>' : ' ',
                           current_line,
                           line);
        if (written < 0 || (unsigned long)written >= buffer_size - used) break;
        used += (size_t)written;
    }

    fclose(file);
    return 0;
}
