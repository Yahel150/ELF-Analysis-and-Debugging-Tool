
#ifndef XDBG_ELF_PARSER_H
#define XDBG_ELF_PARSER_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct elf_file {
    char *path;
    int fd;
    size_t size;
    void *map;

    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdrs;
    size_t phnum;

    const Elf64_Shdr *shdrs;
    size_t shnum;
    const char *shstrtab;

    const Elf64_Shdr *symtab_shdr;
    const Elf64_Shdr *dynsym_shdr;
    const Elf64_Sym *symtab;
    size_t sym_count;
    const char *sym_strtab;

    const Elf64_Sym *dynsym;
    size_t dynsym_count;
    const char *dynstr;
} elf_file_t;

typedef enum elf_relro_kind {
    ELF_RELRO_NONE = 0,
    ELF_RELRO_PARTIAL,
    ELF_RELRO_FULL
} elf_relro_kind_t;

typedef struct elf_security_profile {
    bool is_64bit;
    bool little_endian;
    bool pie;
    bool nx;
    elf_relro_kind_t relro;
    bool bind_now;
    bool canary;
    bool has_textrel;
    bool has_interp;
    bool has_gnu_relro_segment;
    bool has_plt;
    bool has_got_plt;
    bool has_dynamic;
    bool has_dangerous_functions;
} elf_security_profile_t;

int elf_open_file(const char *path, elf_file_t *out);
void elf_close_file(elf_file_t *elf);

const char *elf_relro_to_string(elf_relro_kind_t relro);
const char *elf_type_to_string(uint16_t e_type);
const char *elf_machine_to_string(uint16_t e_machine);
const char *elf_section_type_to_string(uint32_t sh_type);
const char *elf_segment_type_to_string(uint32_t p_type);
const char *elf_segment_flags_to_string(uint32_t p_flags, char *buf, size_t buf_sz);

const char *elf_section_name(const elf_file_t *elf, const Elf64_Shdr *shdr);
const Elf64_Shdr *elf_find_section_by_name(const elf_file_t *elf, const char *name);
const Elf64_Shdr *elf_find_section_by_type(const elf_file_t *elf, uint32_t sh_type);
const Elf64_Shdr *elf_find_section_containing_va(const elf_file_t *elf, uint64_t va);
const char *elf_symbol_name(const elf_file_t *elf, const Elf64_Sym *symbol, bool dynamic_table);
const Elf64_Sym *elf_find_symbol_by_name(const elf_file_t *elf, const char *name, bool dynamic_table);
const void *elf_section_data(const elf_file_t *elf, const Elf64_Shdr *shdr);

void elf_print_header(const elf_file_t *elf);
void elf_print_sections(const elf_file_t *elf);
void elf_print_segments(const elf_file_t *elf);
void elf_print_symbols(const elf_file_t *elf);
void elf_print_security_report(const elf_file_t *elf, const elf_security_profile_t *profile);

void elf_analyze_security(const elf_file_t *elf, elf_security_profile_t *profile);

#endif
