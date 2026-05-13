#include "live_got.h"
#include "memory.h"

#include <string.h>

int xdbg_live_got_find_slot(const elf_file_t *elf, const char *symbol_name, uint64_t *slot_address) {
    const Elf64_Shdr *relaplt;
    const Elf64_Rela *rela_entries;
    size_t rela_count;
    size_t i;

    if (!elf || !symbol_name || !slot_address) return -1;
    relaplt = elf_find_section_by_name(elf, ".rela.plt");
    if (!relaplt || !elf->dynsym || !elf->dynstr) return -1;
    rela_entries = (const Elf64_Rela *)elf_section_data(elf, relaplt);
    if (!rela_entries) return -1;
    rela_count = relaplt->sh_size / sizeof(Elf64_Rela);
    for (i = 0; i < rela_count; ++i) {
        uint32_t sym_index = (uint32_t)ELF64_R_SYM(rela_entries[i].r_info);
        const char *name;
        if (sym_index >= elf->dynsym_count) continue;
        name = elf_symbol_name(elf, &elf->dynsym[sym_index], true);
        if (!name) continue;
        if (strcmp(name, symbol_name) == 0) {
            *slot_address = rela_entries[i].r_offset;
            return 0;
        }
    }
    return -1;
}

int xdbg_live_got_is_plt_address(const elf_file_t *elf, uint64_t runtime_address, uint64_t module_bias) {
    const Elf64_Shdr *plt;
    uint64_t low;
    uint64_t high;
    if (!elf) return 0;
    plt = elf_find_section_by_name(elf, ".plt");
    if (!plt) return 0;
    low = plt->sh_addr + module_bias;
    high = low + plt->sh_size;
    return runtime_address >= low && runtime_address < high;
}

int xdbg_live_got_read_slot(int pid, uint64_t slot_address, uint64_t *slot_value) {
    return xdbg_peek_text_word(pid, slot_address, slot_value);
}
