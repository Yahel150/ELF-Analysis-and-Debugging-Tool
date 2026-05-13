#define _POSIX_C_SOURCE 200809L

#include "elf_parser.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool elf_range_is_valid(const elf_file_t *elf, size_t offset, size_t size) {
    if (!elf || !elf->map) return false;
    if (offset > elf->size) return false;
    if (size > elf->size - offset) return false;
    return true;
}

static const Elf64_Shdr *section_by_index(const elf_file_t *elf, size_t index) {
    if (!elf || !elf->shdrs || index >= elf->shnum) return NULL;
    return &elf->shdrs[index];
}

static const char *safe_string_from_table(const elf_file_t *elf, const char *table, size_t table_offset) {
    const unsigned char *base;
    size_t offset;

    if (!elf || !table) return NULL;

    base = (const unsigned char *)elf->map;
    if ((const unsigned char *)table < base || (const unsigned char *)table >= base + elf->size) {
        return NULL;
    }

    offset = (size_t)((const unsigned char *)table - base);
    if (table_offset >= elf->size - offset) return NULL;
    return table + table_offset;
}

static int validate_elf_header(const Elf64_Ehdr *header) {
    if (!header) return -1;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (header->e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) return -1;
    if (header->e_ident[EI_VERSION] != EV_CURRENT) return -1;
    if (header->e_phentsize != sizeof(Elf64_Phdr)) return -1;
    if (header->e_shentsize != sizeof(Elf64_Shdr)) return -1;
    return 0;
}

static void load_string_tables(elf_file_t *elf) {
    size_t index;

    if (!elf || !elf->shdrs || !elf->shstrtab) return;

    for (index = 0; index < elf->shnum; ++index) {
        const Elf64_Shdr *section = &elf->shdrs[index];
        const char *name = elf_section_name(elf, section);

        if (!name) continue;

        if (strcmp(name, ".shstrtab") == 0) {
            elf->shstrtab = elf_section_data(elf, section);
        } else if (strcmp(name, ".strtab") == 0) {
            elf->sym_strtab = elf_section_data(elf, section);
        } else if (strcmp(name, ".dynstr") == 0) {
            elf->dynstr = elf_section_data(elf, section);
        }
    }
}

static void load_symbols(elf_file_t *elf) {
    size_t index;

    if (!elf || !elf->shdrs) return;

    for (index = 0; index < elf->shnum; ++index) {
        const Elf64_Shdr *section = &elf->shdrs[index];

        if (section->sh_type == SHT_SYMTAB) {
            elf->symtab_shdr = section;
        } else if (section->sh_type == SHT_DYNSYM) {
            elf->dynsym_shdr = section;
        }
    }

    if (elf->symtab_shdr && elf_range_is_valid(elf, elf->symtab_shdr->sh_offset, elf->symtab_shdr->sh_size)) {
        elf->symtab = (const Elf64_Sym *)((const unsigned char *)elf->map + elf->symtab_shdr->sh_offset);
        elf->sym_count = elf->symtab_shdr->sh_size / sizeof(Elf64_Sym);
        if (!elf->sym_strtab && elf->symtab_shdr->sh_link < elf->shnum) {
            const Elf64_Shdr *strings = section_by_index(elf, elf->symtab_shdr->sh_link);
            elf->sym_strtab = elf_section_data(elf, strings);
        }
    }

    if (elf->dynsym_shdr && elf_range_is_valid(elf, elf->dynsym_shdr->sh_offset, elf->dynsym_shdr->sh_size)) {
        elf->dynsym = (const Elf64_Sym *)((const unsigned char *)elf->map + elf->dynsym_shdr->sh_offset);
        elf->dynsym_count = elf->dynsym_shdr->sh_size / sizeof(Elf64_Sym);
        if (!elf->dynstr && elf->dynsym_shdr->sh_link < elf->shnum) {
            const Elf64_Shdr *strings = section_by_index(elf, elf->dynsym_shdr->sh_link);
            elf->dynstr = elf_section_data(elf, strings);
        }
    }
}

const char *elf_relro_to_string(elf_relro_kind_t relro) {
    switch (relro) {
        case ELF_RELRO_NONE: return "none";
        case ELF_RELRO_PARTIAL: return "partial";
        case ELF_RELRO_FULL: return "full";
        default: return "unknown";
    }
}

const char *elf_type_to_string(uint16_t e_type) {
    switch (e_type) {
        case ET_NONE: return "NONE";
        case ET_REL: return "REL";
        case ET_EXEC: return "EXEC";
        case ET_DYN: return "DYN";
        case ET_CORE: return "CORE";
        default: return "OTHER";
    }
}

const char *elf_machine_to_string(uint16_t e_machine) {
    switch (e_machine) {
        case EM_X86_64: return "x86-64";
        case EM_386: return "i386";
        case EM_AARCH64: return "AArch64";
        default: return "OTHER";
    }
}

const char *elf_section_name(const elf_file_t *elf, const Elf64_Shdr *shdr) {
    if (!elf || !elf->shstrtab || !shdr) return NULL;
    return safe_string_from_table(elf, elf->shstrtab, shdr->sh_name);
}

const void *elf_section_data(const elf_file_t *elf, const Elf64_Shdr *shdr) {
    if (!elf || !shdr) return NULL;
    if (!elf_range_is_valid(elf, shdr->sh_offset, shdr->sh_size)) return NULL;
    return (const unsigned char *)elf->map + shdr->sh_offset;
}

const char *elf_symbol_name(const elf_file_t *elf, const Elf64_Sym *symbol, bool dynamic_table) {
    const char *strings;

    if (!elf || !symbol) return NULL;

    strings = dynamic_table ? elf->dynstr : elf->sym_strtab;
    if (!strings) return NULL;

    return safe_string_from_table(elf, strings, symbol->st_name);
}

const Elf64_Sym *elf_find_symbol_by_name(const elf_file_t *elf, const char *name, bool dynamic_table) {
    const Elf64_Sym *symbols;
    const char *strings;
    size_t count;
    size_t index;

    if (!elf || !name) return NULL;

    if (dynamic_table) {
        symbols = elf->dynsym;
        strings = elf->dynstr;
        count = elf->dynsym_count;
    } else {
        symbols = elf->symtab;
        strings = elf->sym_strtab;
        count = elf->sym_count;
    }

    if (!symbols || !strings) return NULL;

    for (index = 0; index < count; ++index) {
        const char *symbol_name = elf_symbol_name(elf, &symbols[index], dynamic_table);
        if (symbol_name && strcmp(symbol_name, name) == 0) {
            return &symbols[index];
        }
    }

    return NULL;
}

const Elf64_Shdr *elf_find_section_by_name(const elf_file_t *elf, const char *name) {
    size_t index;

    if (!elf || !elf->shdrs || !name) return NULL;

    for (index = 0; index < elf->shnum; ++index) {
        const char *section_name = elf_section_name(elf, &elf->shdrs[index]);
        if (section_name && strcmp(section_name, name) == 0) {
            return &elf->shdrs[index];
        }
    }

    return NULL;
}

const Elf64_Shdr *elf_find_section_by_type(const elf_file_t *elf, uint32_t sh_type) {
    size_t index;

    if (!elf || !elf->shdrs) return NULL;

    for (index = 0; index < elf->shnum; ++index) {
        if (elf->shdrs[index].sh_type == sh_type) return &elf->shdrs[index];
    }

    return NULL;
}

const Elf64_Shdr *elf_find_section_containing_va(const elf_file_t *elf, uint64_t va) {
    size_t index;

    if (!elf || !elf->shdrs) return NULL;

    for (index = 0; index < elf->shnum; ++index) {
        const Elf64_Shdr *section = &elf->shdrs[index];
        if (section->sh_size == 0) continue;
        if (va >= section->sh_addr && va < section->sh_addr + section->sh_size) {
            return section;
        }
    }

    return NULL;
}

int elf_open_file(const char *path, elf_file_t *out) {
    struct stat file_stat;
    const Elf64_Ehdr *header;
    size_t phdr_bytes;
    size_t shdr_bytes;
    int fd;
    void *map;

    if (!path || !out) {
        errno = EINVAL;
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->fd = -1;

    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    if (fstat(fd, &file_stat) != 0) {
        close(fd);
        return -1;
    }

    if (file_stat.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    map = mmap(NULL, (size_t)file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    header = (const Elf64_Ehdr *)map;
    if (validate_elf_header(header) != 0) {
        munmap(map, (size_t)file_stat.st_size);
        close(fd);
        errno = EINVAL;
        return -1;
    }

    phdr_bytes = (size_t)header->e_phentsize * header->e_phnum;
    shdr_bytes = (size_t)header->e_shentsize * header->e_shnum;

    if (!elf_range_is_valid(&(elf_file_t){ .map = map, .size = (size_t)file_stat.st_size }, header->e_phoff, phdr_bytes) ||
        !elf_range_is_valid(&(elf_file_t){ .map = map, .size = (size_t)file_stat.st_size }, header->e_shoff, shdr_bytes)) {
        munmap(map, (size_t)file_stat.st_size);
        close(fd);
        errno = EINVAL;
        return -1;
    }

    out->path = strdup(path);
    if (!out->path) {
        munmap(map, (size_t)file_stat.st_size);
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    out->fd = fd;
    out->size = (size_t)file_stat.st_size;
    out->map = map;
    out->ehdr = header;
    out->phdrs = (const Elf64_Phdr *)((const unsigned char *)map + header->e_phoff);
    out->phnum = header->e_phnum;
    out->shdrs = (const Elf64_Shdr *)((const unsigned char *)map + header->e_shoff);
    out->shnum = header->e_shnum;

    if (header->e_shstrndx != SHN_UNDEF && header->e_shstrndx < out->shnum) {
        const Elf64_Shdr *section_names = section_by_index(out, header->e_shstrndx);
        out->shstrtab = elf_section_data(out, section_names);
    }

    load_string_tables(out);
    load_symbols(out);
    return 0;
}

void elf_close_file(elf_file_t *elf) {
    if (!elf) return;

    if (elf->map && elf->size) {
        munmap(elf->map, elf->size);
    }

    if (elf->fd >= 0) {
        close(elf->fd);
    }

    free(elf->path);
    memset(elf, 0, sizeof(*elf));
    elf->fd = -1;
}

static void print_header_sanity(const elf_file_t *elf) {
    const Elf64_Ehdr *header = elf->ehdr;

    printf("  Header sanity:\n");
    printf("    e_phoff = 0x%lx, e_shoff = 0x%lx\n", (unsigned long)header->e_phoff, (unsigned long)header->e_shoff);
    printf("    e_phentsize = %u, e_shentsize = %u\n", header->e_phentsize, header->e_shentsize);
    printf("    shstrndx = %u, phnum = %u, shnum = %u\n", header->e_shstrndx, header->e_phnum, header->e_shnum);
}

void elf_print_header(const elf_file_t *elf) {
    const Elf64_Ehdr *header;

    if (!elf || !elf->ehdr) {
        printf("  ELF header unavailable\n");
        return;
    }

    header = elf->ehdr;

    printf("  File        : %s\n", elf->path ? elf->path : "(unknown)");
    printf("  Size        : %zu bytes\n", elf->size);
    printf("  Type        : %s (0x%x)\n", elf_type_to_string(header->e_type), header->e_type);
    printf("  Machine     : %s (0x%x)\n", elf_machine_to_string(header->e_machine), header->e_machine);
    printf("  Entry point : 0x%016lx\n", (unsigned long)header->e_entry);
    printf("  Phdr count  : %u\n", header->e_phnum);
    printf("  Shdr count  : %u\n", header->e_shnum);

    print_header_sanity(elf);
}
