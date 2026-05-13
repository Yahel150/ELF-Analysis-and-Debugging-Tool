#include "decoder_internal.h"

static int is_legacy_prefix(uint8_t byte) {
    switch (byte) {
        case 0xF0:
        case 0xF2:
        case 0xF3:
        case 0x2E:
        case 0x36:
        case 0x3E:
        case 0x26:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
            return 1;
        default:
            return 0;
    }
}

const char *x86_register_name(int index, int width64) {
    static const char *reg64[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    static const char *reg32[] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };

    if (index < 0 || index > 15) return "unk";
    return width64 ? reg64[index] : reg32[index];
}

const char *x86_legacy_prefix_name(uint8_t prefix) {
    switch (prefix) {
        case 0xF0: return "LOCK";
        case 0xF2: return "REPNE/REPNZ";
        case 0xF3: return "REP/REPE/REPZ";
        case 0x2E: return "CS segment override";
        case 0x36: return "SS segment override";
        case 0x3E: return "DS segment override";
        case 0x26: return "ES segment override";
        case 0x64: return "FS segment override";
        case 0x65: return "GS segment override";
        case 0x66: return "Operand-size override";
        case 0x67: return "Address-size override";
        default: return "Unknown legacy prefix";
    }
}

int x86_parse_prefixes(const uint8_t *code, size_t code_size, size_t *offset, x86_decoded_instruction_t *instruction) {
    if (!code || !offset || !instruction || *offset >= code_size) return -1;

    while (*offset < code_size && instruction->legacy_prefix_count < sizeof(instruction->legacy_prefixes) &&
           is_legacy_prefix(code[*offset])) {
        instruction->legacy_prefixes[instruction->legacy_prefix_count++] = code[*offset];
        *offset += 1;
    }

    if (*offset >= code_size) return 0;
    if ((code[*offset] & 0xF0) != 0x40) return 0;

    instruction->has_rex = true;
    instruction->rex = code[*offset] & 0x0F;
    *offset += 1;
    return (*offset <= code_size) ? 0 : -1;
}
