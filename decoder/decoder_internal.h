#ifndef XDBG_DECODER_INTERNAL_H
#define XDBG_DECODER_INTERNAL_H

#include "decode.h"

typedef struct x86_modrm_fields {
    uint8_t mod;
    uint8_t reg;
    uint8_t rm;
} x86_modrm_fields_t;

typedef struct x86_sib_fields {
    uint8_t scale;
    uint8_t index;
    uint8_t base;
} x86_sib_fields_t;

const char *x86_register_name(int index, int width64);
const char *x86_legacy_prefix_name(uint8_t prefix);
const char *x86_jcc_mnemonic(uint8_t opcode, int two_byte);

int x86_parse_prefixes(const uint8_t *code, size_t code_size, size_t *offset, x86_decoded_instruction_t *instruction);
x86_modrm_fields_t x86_parse_modrm(uint8_t modrm);
x86_sib_fields_t x86_parse_sib(uint8_t sib);
int32_t x86_read_displacement(const uint8_t *code, size_t offset, int size);
int32_t x86_read_immediate(const uint8_t *code, size_t offset, int size);

int x86_opcode_uses_modrm(uint8_t opcode);
const char *x86_opcode_mnemonic(uint8_t opcode);
int x86_opcode_is_reverse_operands(uint8_t opcode);
int x86_opcode_is_group1_immediate(uint8_t opcode);
int x86_opcode_is_short_jcc(uint8_t opcode);
int x86_opcode_is_mov_imm(uint8_t opcode);
int x86_opcode_is_push_reg(uint8_t opcode);
int x86_opcode_is_pop_reg(uint8_t opcode);

void x86_append_detail(char *buffer, size_t buffer_size, const char *text);
void x86_format_bytes(const x86_decoded_instruction_t *instruction, char *buffer, size_t buffer_size);
void x86_format_memory_operand(char *buffer,
                               size_t buffer_size,
                               x86_modrm_fields_t modrm,
                               int rex_b,
                               int rex_x,
                               int displacement_size,
                               int32_t displacement,
                               int has_sib,
                               uint8_t sib_byte);
void x86_describe_operands(x86_decoded_instruction_t *instruction);

#endif
