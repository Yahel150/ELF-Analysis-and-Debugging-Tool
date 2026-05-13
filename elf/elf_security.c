#include "elf_parser.h"

#include <stdio.h>
#include <string.h>

static bool has_symbol_name(const elf_file_t *elf, const char *name) {
    return elf_find_symbol_by_name(elf, name, false) != NULL ||
           elf_find_symbol_by_name(elf, name, true) != NULL;
}

static bool has_dangerous_function(const elf_file_t *elf) {
    static const char *dangerous_functions[] = {
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "sscanf", "system", "memcpy", "memmove"
    };
    size_t index;

    for (index = 0; index < sizeof(dangerous_functions) / sizeof(dangerous_functions[0]); ++index) {
        if (has_symbol_name(elf, dangerous_functions[index])) return true;
    }

    return false;
}

void elf_analyze_security(const elf_file_t *elf, elf_security_profile_t *profile) {
    size_t index;

    if (!profile) return;
    memset(profile, 0, sizeof(*profile));

    if (!elf || !elf->ehdr) return;

    profile->is_64bit = (elf->ehdr->e_ident[EI_CLASS] == ELFCLASS64);
    profile->little_endian = (elf->ehdr->e_ident[EI_DATA] == ELFDATA2LSB);
    profile->pie = (elf->ehdr->e_type == ET_DYN);
    profile->has_plt = (elf_find_section_by_name(elf, ".plt") != NULL);
    profile->has_got_plt = (elf_find_section_by_name(elf, ".got.plt") != NULL);
    profile->has_dynamic = (elf_find_section_by_type(elf, SHT_DYNAMIC) != NULL);
    profile->has_dangerous_functions = has_dangerous_function(elf);
    profile->relro = ELF_RELRO_NONE;

    for (index = 0; index < elf->phnum; ++index) {
        const Elf64_Phdr *segment = &elf->phdrs[index];

        if (segment->p_type == PT_GNU_STACK) {
            profile->nx = ((segment->p_flags & PF_X) == 0);
        } else if (segment->p_type == PT_GNU_RELRO) {
            profile->has_gnu_relro_segment = true;
            profile->relro = ELF_RELRO_PARTIAL;
        } else if (segment->p_type == PT_INTERP) {
            profile->has_interp = true;
        } else if (segment->p_type == PT_DYNAMIC) {
            const Elf64_Dyn *dynamic_entries = (const Elf64_Dyn *)((const unsigned char *)elf->map + segment->p_offset);
            size_t entry_count = segment->p_filesz / sizeof(Elf64_Dyn);
            size_t dynamic_index;

            for (dynamic_index = 0; dynamic_index < entry_count; ++dynamic_index) {
                if (dynamic_entries[dynamic_index].d_tag == DT_NULL) break;
                if (dynamic_entries[dynamic_index].d_tag == DT_BIND_NOW) profile->bind_now = true;
#ifdef DT_FLAGS
                if (dynamic_entries[dynamic_index].d_tag == DT_FLAGS &&
                    (dynamic_entries[dynamic_index].d_un.d_val & DF_BIND_NOW)) {
                    profile->bind_now = true;
                }
#endif
#ifdef DT_FLAGS_1
                if (dynamic_entries[dynamic_index].d_tag == DT_FLAGS_1 &&
                    (dynamic_entries[dynamic_index].d_un.d_val & DF_1_NOW)) {
                    profile->bind_now = true;
                }
#endif
#ifdef DT_TEXTREL
                if (dynamic_entries[dynamic_index].d_tag == DT_TEXTREL) {
                    profile->has_textrel = true;
                }
#endif
            }
        }
    }

    if (profile->has_gnu_relro_segment && profile->bind_now) {
        profile->relro = ELF_RELRO_FULL;
    }

    profile->canary = has_symbol_name(elf, "__stack_chk_fail");
}

void elf_print_security_report(const elf_file_t *elf, const elf_security_profile_t *profile) {
    (void)elf;

    if (!profile) {
        printf("  Security profile unavailable\n");
        return;
    }

    printf("  Security profile:\n");
    printf("    ELF64           : %s\n", profile->is_64bit ? "yes" : "no");
    printf("    Little endian   : %s\n", profile->little_endian ? "yes" : "no");
    printf("    PIE             : %s\n", profile->pie ? "yes" : "no");
    printf("    NX stack        : %s\n", profile->nx ? "yes" : "no");
    printf("    RELRO           : %s\n", elf_relro_to_string(profile->relro));
    printf("    BIND_NOW        : %s\n", profile->bind_now ? "yes" : "no");
    printf("    Canary          : %s\n", profile->canary ? "yes" : "no");
    printf("    Text reloc      : %s\n", profile->has_textrel ? "yes" : "no");
    printf("    Interp segment  : %s\n", profile->has_interp ? "yes" : "no");
    printf("    PLT present     : %s\n", profile->has_plt ? "yes" : "no");
    printf("    GOT.PLT present : %s\n", profile->has_got_plt ? "yes" : "no");
    printf("    Dynamic seg     : %s\n", profile->has_dynamic ? "yes" : "no");
    printf("    Dangerous APIs  : %s\n", profile->has_dangerous_functions ? "yes" : "no");
}
