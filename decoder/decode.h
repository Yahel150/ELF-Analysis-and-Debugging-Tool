#ifndef XDBG_DECODER_H
#define XDBG_DECODER_H

#include "../elf/elf_parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct x86_decoded_instruction {
    uint64_t address;
    size_t length;
    size_t byte_count;
    uint8_t bytes[16];
    size_t legacy_prefix_count;
    uint8_t legacy_prefixes[4];
    bool has_rex;
    uint8_t rex;
    uint8_t opcode;
    uint8_t opcode2;
    bool two_byte_opcode;
    bool has_modrm;
    uint8_t modrm;
    uint8_t modrm_mod;
    uint8_t modrm_reg;
    uint8_t modrm_rm;
    uint8_t modrm_reg_full;
    uint8_t modrm_rm_full;
    bool has_sib;
    uint8_t sib;
    uint8_t sib_scale_bits;
    uint8_t sib_scale;
    uint8_t sib_index;
    uint8_t sib_base;
    uint8_t sib_index_full;
    uint8_t sib_base_full;
    int displacement_size;
    int32_t displacement;
    int immediate_size;
    int32_t immediate;
    char text[256];
    char details[1024];
} x86_decoded_instruction_t;

int x86_decode_instruction(const uint8_t *code, size_t code_size, uint64_t address, x86_decoded_instruction_t *out);
void x86_print_instruction(const x86_decoded_instruction_t *instruction);
void x86_decode_text_section(const elf_file_t *elf, const char *binary_path, size_t instruction_limit);

#endif
