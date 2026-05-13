#include "elf_parser.h"

#include <stdio.h>

const char *elf_segment_type_to_string(uint32_t p_type) {
    switch (p_type) {
        case PT_NULL: return "NULL";
        case PT_LOAD: return "LOAD";
        case PT_DYNAMIC: return "DYNAMIC";
        case PT_INTERP: return "INTERP";
        case PT_NOTE: return "NOTE";
        case PT_SHLIB: return "SHLIB";
        case PT_PHDR: return "PHDR";
        case PT_TLS: return "TLS";
#ifdef PT_GNU_EH_FRAME
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
#endif
#ifdef PT_GNU_STACK
        case PT_GNU_STACK: return "GNU_STACK";
#endif
#ifdef PT_GNU_RELRO
        case PT_GNU_RELRO: return "GNU_RELRO";
#endif
        default: return "OTHER";
    }
}

const char *elf_segment_flags_to_string(uint32_t p_flags, char *buffer, size_t buffer_size) {
    size_t length = 0;

    if (buffer_size == 0) return buffer;
    if (p_flags & PF_R && length + 1 < buffer_size) buffer[length++] = 'R';
    if (p_flags & PF_W && length + 1 < buffer_size) buffer[length++] = 'W';
    if (p_flags & PF_X && length + 1 < buffer_size) buffer[length++] = 'X';
    buffer[length] = '\0';
    return buffer;
}

void elf_print_segments(const elf_file_t *elf) {
    size_t index;

    if (!elf || !elf->phdrs) {
        printf("  [!] program header table unavailable\n");
        return;
    }

    printf("  %-4s %-14s %-8s %-18s %-18s %-18s %-18s %-18s\n",
           "Idx", "Type", "Flags", "Offset", "Vaddr", "Paddr", "Filesz", "Memsz");
    for (index = 0; index < elf->phnum; ++index) {
        const Elf64_Phdr *segment = &elf->phdrs[index];
        char flags[8];
        printf("  [%02zu] %-14s %-8s 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
               index,
               elf_segment_type_to_string(segment->p_type),
               elf_segment_flags_to_string(segment->p_flags, flags, sizeof(flags)),
               (unsigned long)segment->p_offset,
               (unsigned long)segment->p_vaddr,
               (unsigned long)segment->p_paddr,
               (unsigned long)segment->p_filesz,
               (unsigned long)segment->p_memsz);
    }

    printf("\n  Notable segments:\n");
    for (index = 0; index < elf->phnum; ++index) {
        const Elf64_Phdr *segment = &elf->phdrs[index];
        char flags[8];

        if (segment->p_type != PT_GNU_RELRO &&
            segment->p_type != PT_GNU_STACK &&
            segment->p_type != PT_INTERP &&
            segment->p_type != PT_DYNAMIC) {
            continue;
        }

        printf("    %-10s vaddr=0x%lx memsz=0x%lx flags=%s\n",
               elf_segment_type_to_string(segment->p_type),
               (unsigned long)segment->p_vaddr,
               (unsigned long)segment->p_memsz,
               elf_segment_flags_to_string(segment->p_flags, flags, sizeof(flags)));
    }
}
