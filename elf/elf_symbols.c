#include "elf_parser.h"

#include <stdio.h>

static const char *sym_name_from_table(const elf_file_t *elf, const char *strtab, const Elf64_Sym *sym) {
    if (!elf || !strtab || !sym) return NULL;
    if (strtab == elf->dynstr) return elf_symbol_name(elf, sym, true);
    return elf_symbol_name(elf, sym, false);
}

static const char *sym_bind(uint8_t info) {
    switch (ELF64_ST_BIND(info)) {
        case STB_LOCAL: return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK: return "WEAK";
        default: return "OTHER";
    }
}

static const char *sym_type(uint8_t info) {
    switch (ELF64_ST_TYPE(info)) {
        case STT_NOTYPE: return "NOTYPE";
        case STT_OBJECT: return "OBJECT";
        case STT_FUNC: return "FUNC";
        case STT_SECTION: return "SECTION";
        case STT_FILE: return "FILE";
        case STT_COMMON: return "COMMON";
        case STT_TLS: return "TLS";
        default: return "OTHER";
    }
}

static void print_symbol_table(const elf_file_t *elf,
                               const char *title,
                               const Elf64_Sym *symbols,
                               size_t count,
                               const char *strings,
                               size_t limit) {
    size_t index;
    size_t shown = 0;

    if (!symbols || !count || !strings) {
        printf("  %s: unavailable\n", title);
        return;
    }

    printf("  %s (showing up to %zu named entries)\n", title, limit);
    printf("  %-4s %-28s %-8s %-8s %-18s %-10s %-6s\n",
           "Idx", "Name", "Bind", "Type", "Value", "Size", "Shndx");

    for (index = 0; index < count && shown < limit; ++index) {
        const Elf64_Sym *symbol = &symbols[index];
        const char *name = sym_name_from_table(elf, strings, symbol);

        if (!name || !*name) continue;

        printf("  [%03zu] %-28.28s %-8s %-8s 0x%016lx %-10lu %-6u\n",
               index,
               name,
               sym_bind(symbol->st_info),
               sym_type(symbol->st_info),
               (unsigned long)symbol->st_value,
               (unsigned long)symbol->st_size,
               symbol->st_shndx);
        ++shown;
    }

    if (shown == 0) {
        printf("    (no named symbols)\n");
    }
}

void elf_print_symbols(const elf_file_t *elf) {
    const Elf64_Shdr *plt;
    const Elf64_Shdr *gotplt;
    const Elf64_Shdr *relaplt;

    if (!elf) {
        printf("  [!] symbols unavailable\n");
        return;
    }

    print_symbol_table(elf, ".symtab", elf->symtab, elf->sym_count, elf->sym_strtab, 24);
    printf("\n");
    print_symbol_table(elf, ".dynsym", elf->dynsym, elf->dynsym_count, elf->dynstr, 24);

    plt = elf_find_section_by_name(elf, ".plt");
    gotplt = elf_find_section_by_name(elf, ".got.plt");
    relaplt = elf_find_section_by_name(elf, ".rela.plt");

    printf("\n  Linking hints:\n");
    if (plt) {
        printf("    .plt      @ 0x%lx (size 0x%lx)\n", (unsigned long)plt->sh_addr, (unsigned long)plt->sh_size);
    } else {
        printf("    .plt      : not present\n");
    }
    if (gotplt) {
        printf("    .got.plt  @ 0x%lx (size 0x%lx)\n", (unsigned long)gotplt->sh_addr, (unsigned long)gotplt->sh_size);
    } else {
        printf("    .got.plt  : not present\n");
    }
    if (relaplt) {
        printf("    .rela.plt : present (imports use relocations)\n");
    } else {
        printf("    .rela.plt : not present\n");
    }
}
