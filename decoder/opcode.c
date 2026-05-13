#include "decoder_internal.h"

static const char *jcc_names[] = {
    "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
    "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
};

int x86_opcode_uses_modrm(uint8_t opcode) {
    switch (opcode) {
        case 0x89:
        case 0x8B:
        case 0x8D:
        case 0x01:
        case 0x03:
        case 0x29:
        case 0x2B:
        case 0x39:
        case 0x3B:
        case 0x31:
        case 0x33:
        case 0x85:
        case 0x83:
        case 0x81:
            return 1;
        default:
            return 0;
    }
}

const char *x86_opcode_mnemonic(uint8_t opcode) {
    switch (opcode) {
        case 0x89:
        case 0x8B: return "mov";
        case 0x8D: return "lea";
        case 0x01:
        case 0x03: return "add";
        case 0x29:
        case 0x2B: return "sub";
        case 0x39:
        case 0x3B: return "cmp";
        case 0x31:
        case 0x33: return "xor";
        case 0x85: return "test";
        default: return "db";
    }
}

int x86_opcode_is_reverse_operands(uint8_t opcode) {
    return opcode == 0x8B || opcode == 0x8D || opcode == 0x03 || opcode == 0x2B || opcode == 0x3B || opcode == 0x33;
}

int x86_opcode_is_group1_immediate(uint8_t opcode) {
    return opcode == 0x81 || opcode == 0x83;
}

int x86_opcode_is_short_jcc(uint8_t opcode) {
    return opcode >= 0x70 && opcode <= 0x7F;
}

int x86_opcode_is_mov_imm(uint8_t opcode) {
    return opcode >= 0xB8 && opcode <= 0xBF;
}

int x86_opcode_is_push_reg(uint8_t opcode) {
    return opcode >= 0x50 && opcode <= 0x57;
}

int x86_opcode_is_pop_reg(uint8_t opcode) {
    return opcode >= 0x58 && opcode <= 0x5F;
}

const char *x86_jcc_mnemonic(uint8_t opcode, int two_byte) {
    if (!two_byte && opcode >= 0x70 && opcode <= 0x7F) {
        return jcc_names[opcode - 0x70];
    }

    if (two_byte && opcode >= 0x80 && opcode <= 0x8F) {
        return jcc_names[opcode - 0x80];
    }

    return "jcc";
}
