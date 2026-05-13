#include "elf_parser.h"

#include <stdio.h>
#include <string.h>

const char *elf_section_type_to_string(uint32_t sh_type) {
    switch (sh_type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_DYNSYM: return "DYNSYM";
#ifdef SHT_GNU_HASH
        case SHT_GNU_HASH: return "GNU_HASH";
#endif
        default: return "OTHER";
    }
}

static const char *section_flags(uint64_t flags, char *buffer, size_t buffer_size) {
    size_t length = 0;

    if (buffer_size == 0) return buffer;
    if (flags & SHF_WRITE && length + 1 < buffer_size) buffer[length++] = 'W';
    if (flags & SHF_ALLOC && length + 1 < buffer_size) buffer[length++] = 'A';
    if (flags & SHF_EXECINSTR && length + 1 < buffer_size) buffer[length++] = 'X';
    if (flags & SHF_MERGE && length + 1 < buffer_size) buffer[length++] = 'M';
    if (flags & SHF_STRINGS && length + 1 < buffer_size) buffer[length++] = 'S';
    if (flags & SHF_INFO_LINK && length + 1 < buffer_size) buffer[length++] = 'I';
    if (flags & SHF_LINK_ORDER && length + 1 < buffer_size) buffer[length++] = 'L';
    if (flags & SHF_OS_NONCONFORMING && length + 1 < buffer_size) buffer[length++] = 'O';
    if (flags & SHF_GROUP && length + 1 < buffer_size) buffer[length++] = 'G';
    if (flags & SHF_TLS && length + 1 < buffer_size) buffer[length++] = 'T';
    buffer[length] = '\0';
    return buffer;
}

void elf_print_sections(const elf_file_t *elf) {
    size_t index;
    static const char *important_sections[] = {
        ".text", ".rodata", ".data", ".bss", ".plt", ".got", ".got.plt", ".dynsym", ".symtab"
    };

    if (!elf || !elf->shdrs || !elf->shstrtab) {
        printf("  [!] section table unavailable\n");
        return;
    }

    printf("  %-4s %-20s %-12s %-18s %-18s %-10s %-8s\n",
           "Idx", "Name", "Type", "Addr", "Offset", "Size", "Flags");
    for (index = 0; index < elf->shnum; ++index) {
        const Elf64_Shdr *section = &elf->shdrs[index];
        const char *name = elf_section_name(elf, section);
        char flags[16];

        printf("  [%02zu] %-20s %-12s 0x%016lx 0x%016lx 0x%08lx %-8s\n",
               index,
               name ? name : "",
               elf_section_type_to_string(section->sh_type),
               (unsigned long)section->sh_addr,
               (unsigned long)section->sh_offset,
               (unsigned long)section->sh_size,
               section_flags(section->sh_flags, flags, sizeof(flags)));
    }

    printf("\n  Key sections:");
    for (index = 0; index < sizeof(important_sections) / sizeof(important_sections[0]); ++index) {
        const Elf64_Shdr *section = elf_find_section_by_name(elf, important_sections[index]);
        if (!section) continue;
        printf("    %-8s addr=0x%lx off=0x%lx size=0x%lx\n",
               important_sections[index],
               (unsigned long)section->sh_addr,
               (unsigned long)section->sh_offset,
               (unsigned long)section->sh_size);
    }
}
