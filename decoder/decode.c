#include "decoder_internal.h"

#include <stdio.h>
#include <string.h>

static int decode_two_byte_opcode(const uint8_t *code,
                                  size_t code_size,
                                  uint64_t address,
                                  size_t *offset,
                                  x86_decoded_instruction_t *out) {
    if (out->opcode2 == 0x05) {
        snprintf(out->text, sizeof(out->text), "syscall");
        return 0;
    }

    if (out->opcode2 >= 0x80 && out->opcode2 <= 0x8F) {
        const char *mnemonic = x86_jcc_mnemonic(out->opcode2, 1);
        if (*offset + 4 > code_size) return -1;
        out->immediate_size = 4;
        out->immediate = x86_read_immediate(code, *offset, 4);
        snprintf(out->text, sizeof(out->text), "%s 0x%016llx",
                 mnemonic,
                 (unsigned long long)(address + *offset + 4 + out->immediate));
        *offset += 4;
        return 0;
    }

    snprintf(out->text, sizeof(out->text), "db 0x0f 0x%02x", out->opcode2);
    return 0;
}

static int decode_modrm_displacement(const uint8_t *code,
                                     size_t code_size,
                                     size_t *offset,
                                     x86_decoded_instruction_t *out) {
    x86_modrm_fields_t modrm = x86_parse_modrm(out->modrm);
    out->modrm_mod = modrm.mod;
    out->modrm_reg = modrm.reg;
    out->modrm_rm = modrm.rm;

    if (modrm.mod != 3 && modrm.rm == 4) {
        x86_sib_fields_t sib;
        if (*offset >= code_size) return -1;
        out->has_sib = true;
        out->sib = code[(*offset)++];
        sib = x86_parse_sib(out->sib);
        out->sib_scale_bits = sib.scale;
        out->sib_scale = (uint8_t)(1u << sib.scale);
        out->sib_index = sib.index;
        out->sib_base = sib.base;
    }

    if (modrm.mod == 1) {
        if (*offset + 1 > code_size) return -1;
        out->displacement_size = 1;
        out->displacement = x86_read_displacement(code, *offset, 1);
        *offset += 1;
    } else if (modrm.mod == 2 ||
               (modrm.mod == 0 && modrm.rm == 5) ||
               (modrm.mod == 0 && modrm.rm == 4 && out->has_sib && out->sib_base == 5)) {
        if (*offset + 4 > code_size) return -1;
        out->displacement_size = 4;
        out->displacement = x86_read_displacement(code, *offset, 4);
        *offset += 4;
    }

    return 0;
}

static void decode_binary_operands(x86_decoded_instruction_t *out, int rex_w, int rex_r, int rex_x, int rex_b) {
    x86_modrm_fields_t modrm = x86_parse_modrm(out->modrm);
    char left[64];
    char right[64];
    int reg = modrm.reg | (rex_r << 3);
    int rm = modrm.rm | (rex_b << 3);
    int width64 = rex_w ? 1 : 0;
    const char *mnemonic = x86_opcode_mnemonic(out->opcode);
    char mnemonic_with_size[16];
    out->modrm_reg_full = (uint8_t)reg;
    out->modrm_rm_full = (uint8_t)rm;
    if (out->has_sib) {
        out->sib_index_full = (uint8_t)(out->sib_index | (rex_x << 3));
        out->sib_base_full = (uint8_t)(out->sib_base | (rex_b << 3));
    }

    if (modrm.mod == 3) {
        snprintf(left, sizeof(left), "%%%s", x86_register_name(rm, width64));
    } else {
        x86_format_memory_operand(left, sizeof(left), modrm, rex_b, rex_x,
                                  out->displacement_size, out->displacement,
                                  out->has_sib, out->sib);
    }

    snprintf(right, sizeof(right), "%%%s", x86_register_name(reg, width64));
    snprintf(mnemonic_with_size, sizeof(mnemonic_with_size), "%s%c", mnemonic, width64 ? 'q' : 'l');

    if (x86_opcode_is_reverse_operands(out->opcode)) {
        snprintf(out->text, sizeof(out->text), "%s %s, %s", mnemonic_with_size, left, right);
    } else {
        snprintf(out->text, sizeof(out->text), "%s %s, %s", mnemonic_with_size, right, left);
    }
}

static int decode_modrm_opcode(const uint8_t *code,
                               size_t code_size,
                               size_t *offset,
                               x86_decoded_instruction_t *out,
                               int rex_w,
                               int rex_r,
                               int rex_x,
                               int rex_b) {
    if (*offset >= code_size) return -1;

    out->has_modrm = true;
    out->modrm = code[(*offset)++];

    if (decode_modrm_displacement(code, code_size, offset, out) != 0) return -1;

    if (out->opcode == 0xC7) {
        x86_modrm_fields_t modrm = x86_parse_modrm(out->modrm);
        char operand[64];
        int width64 = rex_w ? 1 : 0;
        out->modrm_reg_full = (uint8_t)(modrm.reg | (rex_r << 3));
        out->modrm_rm_full = (uint8_t)(modrm.rm | (rex_b << 3));
        if (out->has_sib) {
            out->sib_index_full = (uint8_t)(out->sib_index | (rex_x << 3));
            out->sib_base_full = (uint8_t)(out->sib_base | (rex_b << 3));
        }

        if (modrm.reg != 0) {
            snprintf(out->text, sizeof(out->text), "db 0xc7");
            return 0;
        }

        if (*offset + 4 > code_size) return -1;
        out->immediate_size = 4;
        out->immediate = x86_read_immediate(code, *offset, 4);
        *offset += 4;

        if (modrm.mod == 3) {
            snprintf(operand, sizeof(operand), "%%%s",
                     x86_register_name(modrm.rm | (rex_b << 3), width64));
        } else {
            x86_format_memory_operand(operand, sizeof(operand), modrm, rex_b, rex_x,
                                      out->displacement_size, out->displacement,
                                      out->has_sib, out->sib);
        }

        snprintf(out->text, sizeof(out->text), "mov%c $0x%x, %s",
                 width64 ? 'q' : 'l', (unsigned int)out->immediate, operand);
        return 0;
    }

    if (x86_opcode_is_group1_immediate(out->opcode)) {
        x86_modrm_fields_t modrm = x86_parse_modrm(out->modrm);
        char operand[64];
        const char *mnemonic = "grp";
        int width64 = rex_w ? 1 : 0;
        out->modrm_reg_full = (uint8_t)(modrm.reg | (rex_r << 3));
        out->modrm_rm_full = (uint8_t)(modrm.rm | (rex_b << 3));
        if (out->has_sib) {
            out->sib_index_full = (uint8_t)(out->sib_index | (rex_x << 3));
            out->sib_base_full = (uint8_t)(out->sib_base | (rex_b << 3));
        }

        if (out->opcode == 0x83) {
            if (*offset + 1 > code_size) return -1;
            out->immediate_size = 1;
            out->immediate = x86_read_immediate(code, *offset, 1);
            *offset += 1;
        } else {
            if (*offset + 4 > code_size) return -1;
            out->immediate_size = 4;
            out->immediate = x86_read_immediate(code, *offset, 4);
            *offset += 4;
        }

        if (modrm.mod == 3) {
            snprintf(operand, sizeof(operand), "%%%s",
                     x86_register_name(modrm.rm | (rex_b << 3), width64));
        } else {
            x86_format_memory_operand(operand, sizeof(operand), modrm, rex_b, rex_x,
                                      out->displacement_size, out->displacement,
                                      out->has_sib, out->sib);
        }

        if (modrm.reg == 0) mnemonic = "add";
        if (modrm.reg == 5) mnemonic = "sub";
        if (modrm.reg == 7) mnemonic = "cmp";

        snprintf(out->text, sizeof(out->text), "%s%c $0x%x, %s",
                 mnemonic, width64 ? 'q' : 'l', (unsigned int)out->immediate, operand);
        return 0;
    }

    decode_binary_operands(out, rex_w, rex_r, rex_x, rex_b);
    return 0;
}

static int decode_simple_opcode(const uint8_t *code,
                                size_t code_size,
                                uint64_t address,
                                size_t *offset,
                                x86_decoded_instruction_t *out,
                                int rex_w,
                                int rex_b) {
    if (x86_opcode_is_push_reg(out->opcode)) {
        snprintf(out->text, sizeof(out->text), "pushq %%%s",
                 x86_register_name((out->opcode - 0x50) | (rex_b << 3), 1));
        return 0;
    }

    if (x86_opcode_is_pop_reg(out->opcode)) {
        snprintf(out->text, sizeof(out->text), "popq %%%s",
                 x86_register_name((out->opcode - 0x58) | (rex_b << 3), 1));
        return 0;
    }

    if (x86_opcode_is_mov_imm(out->opcode)) {
        if (*offset + 4 > code_size) return -1;
        out->immediate_size = 4;
        out->immediate = x86_read_immediate(code, *offset, 4);
        snprintf(out->text, sizeof(out->text), "mov%c $0x%x, %%%s",
                 rex_w ? 'q' : 'l',
                 (unsigned int)out->immediate,
                 x86_register_name((out->opcode - 0xB8) | (rex_b << 3), rex_w ? 1 : 0));
        *offset += 4;
        return 0;
    }

    if (x86_opcode_is_short_jcc(out->opcode)) {
        const char *mnemonic = x86_jcc_mnemonic(out->opcode, 0);
        if (*offset + 1 > code_size) return -1;
        out->immediate_size = 1;
        out->immediate = x86_read_immediate(code, *offset, 1);
        snprintf(out->text, sizeof(out->text), "%s 0x%016llx",
                 mnemonic,
                 (unsigned long long)(address + *offset + 1 + out->immediate));
        *offset += 1;
        return 0;
    }

    switch (out->opcode) {
        case 0x68:
            if (*offset + 4 > code_size) return -1;
            out->immediate_size = 4;
            out->immediate = x86_read_immediate(code, *offset, 4);
            snprintf(out->text, sizeof(out->text), "pushq $0x%x", (unsigned int)out->immediate);
            *offset += 4;
            return 0;
        case 0x6A:
            if (*offset + 1 > code_size) return -1;
            out->immediate_size = 1;
            out->immediate = x86_read_immediate(code, *offset, 1);
            snprintf(out->text, sizeof(out->text), "pushq $0x%x", (unsigned int)out->immediate);
            *offset += 1;
            return 0;
        case 0xC3:
            snprintf(out->text, sizeof(out->text), "ret");
            return 0;
        case 0xCC:
            snprintf(out->text, sizeof(out->text), "int3");
            return 0;
        case 0x90:
            snprintf(out->text, sizeof(out->text), "nop");
            return 0;
        case 0xE8:
            if (*offset + 4 > code_size) return -1;
            out->immediate_size = 4;
            out->immediate = x86_read_immediate(code, *offset, 4);
            snprintf(out->text, sizeof(out->text), "callq 0x%016llx",
                     (unsigned long long)(address + *offset + 4 + out->immediate));
            *offset += 4;
            return 0;
        case 0xE9:
            if (*offset + 4 > code_size) return -1;
            out->immediate_size = 4;
            out->immediate = x86_read_immediate(code, *offset, 4);
            snprintf(out->text, sizeof(out->text), "jmp 0x%016llx",
                     (unsigned long long)(address + *offset + 4 + out->immediate));
            *offset += 4;
            return 0;
        case 0xEB:
            if (*offset + 1 > code_size) return -1;
            out->immediate_size = 1;
            out->immediate = x86_read_immediate(code, *offset, 1);
            snprintf(out->text, sizeof(out->text), "jmp 0x%016llx",
                     (unsigned long long)(address + *offset + 1 + out->immediate));
            *offset += 1;
            return 0;
        default:
            snprintf(out->text, sizeof(out->text), "db 0x%02x", out->opcode);
            return 0;
    }
}

int x86_decode_instruction(const uint8_t *code, size_t code_size, uint64_t address, x86_decoded_instruction_t *out) {
    size_t offset = 0;
    int rex_w;
    int rex_r;
    int rex_x;
    int rex_b;

    if (!code || !out || code_size == 0) return -1;

    memset(out, 0, sizeof(*out));
    out->address = address;

    if (x86_parse_prefixes(code, code_size, &offset, out) != 0) return -1;
    if (offset >= code_size) return -1;

    rex_w = out->has_rex ? ((out->rex >> 3) & 1) : 0;
    rex_r = out->has_rex ? ((out->rex >> 2) & 1) : 0;
    rex_x = out->has_rex ? ((out->rex >> 1) & 1) : 0;
    rex_b = out->has_rex ? (out->rex & 1) : 0;

    out->opcode = code[offset++];
    if (out->opcode == 0x0F) {
        if (offset >= code_size) return -1;
        out->two_byte_opcode = true;
        out->opcode2 = code[offset++];
        if (decode_two_byte_opcode(code, code_size, address, &offset, out) != 0) return -1;
    } else if (x86_opcode_uses_modrm(out->opcode)) {
        if (decode_modrm_opcode(code, code_size, &offset, out, rex_w, rex_r, rex_x, rex_b) != 0) return -1;
    } else {
        if (decode_simple_opcode(code, code_size, address, &offset, out, rex_w, rex_b) != 0) return -1;
    }

    out->length = offset;
    out->byte_count = offset < sizeof(out->bytes) ? offset : sizeof(out->bytes);
    memcpy(out->bytes, code, out->byte_count);
    x86_describe_operands(out);
    return 0;
}

void x86_decode_text_section(const elf_file_t *elf, const char *binary_path, size_t instruction_limit) {
    const Elf64_Shdr *text_section;
    const uint8_t *code;
    size_t offset = 0;
    size_t decoded = 0;
    x86_decoded_instruction_t instructions[256];
    size_t instruction_count = 0;

    if (!elf) return;

    text_section = elf_find_section_by_name(elf, ".text");
    if (!text_section) {
        printf("  .text section not found\n");
        return;
    }

    code = elf_section_data(elf, text_section);
    if (!code) {
        printf("  .text bytes unavailable\n");
        return;
    }

    while (offset < text_section->sh_size && decoded < instruction_limit && instruction_count < sizeof(instructions) / sizeof(instructions[0])) {
        if (x86_decode_instruction(code + offset,
                                   (size_t)text_section->sh_size - offset,
                                   text_section->sh_addr + offset,
                                   &instructions[instruction_count]) != 0 ||
            instructions[instruction_count].length == 0) {
            memset(&instructions[instruction_count], 0, sizeof(instructions[instruction_count]));
            instructions[instruction_count].address = text_section->sh_addr + offset;
            instructions[instruction_count].length = 1;
            instructions[instruction_count].byte_count = 1;
            instructions[instruction_count].bytes[0] = code[offset];
            snprintf(instructions[instruction_count].text, sizeof(instructions[instruction_count].text), "db 0x%02x", code[offset]);
        }

        offset += instructions[instruction_count].length;
        decoded += 1;
        instruction_count += 1;
    }

    printf("Input\n");
    printf("  Binary   : %s\n", binary_path ? binary_path : "(unknown)");
    printf("  Target   : .text\n");
    printf("  Start    : 0x%016llx\n", (unsigned long long)text_section->sh_addr);
    printf("  Size     : 0x%llx bytes\n", (unsigned long long)text_section->sh_size);
    printf("  Syntax   : AT&T\n\n");

    printf("------------------------------------------------------------\n");
    printf("[TEXT SECTION - objdump-style view]\n");
    printf("------------------------------------------------------------\n\n");
    for (offset = 0; offset < instruction_count; ++offset) {
        char line[384];
        x86_format_objdump_line(&instructions[offset], line, sizeof(line));
        printf("%s\n", line);
    }

    printf("\n------------------------------------------------------------\n");
    printf("[TEXT SECTION - Decoder explanation]\n");
    printf("------------------------------------------------------------\n\n");
    for (offset = 0; offset < instruction_count; ++offset) {
        x86_print_instruction(&instructions[offset]);
        printf("\n");
    }
}
