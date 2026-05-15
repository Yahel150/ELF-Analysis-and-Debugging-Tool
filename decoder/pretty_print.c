#include "decoder_internal.h"

#include <stdio.h>
#include <string.h>

static void append_hex_bytes(char *buffer, size_t buffer_size, const uint8_t *bytes, size_t count) {
    size_t index;
    size_t used = strlen(buffer);

    for (index = 0; index < count && used < buffer_size; ++index) {
        int written = snprintf(buffer + used, buffer_size - used,
                               index == 0 ? "0x%02x" : " 0x%02x",
                               bytes[index]);
        if (written < 0 || (size_t)written >= buffer_size - used) break;
        used += (size_t)written;
    }
}

static size_t prefix_bytes(const x86_decoded_instruction_t *instruction) {
    return instruction->legacy_prefix_count + (instruction->has_rex ? 1u : 0u);
}

static size_t opcode_bytes(const x86_decoded_instruction_t *instruction) {
    return instruction->two_byte_opcode ? 2u : 1u;
}

static void describe_prefixes(x86_decoded_instruction_t *instruction) {
    size_t index;
    char line[256];

    if (instruction->legacy_prefix_count == 0 && !instruction->has_rex) {
        x86_append_detail(instruction->details, sizeof(instruction->details),
                          "    Prefix    : none\n");
        return;
    }

    for (index = 0; index < instruction->legacy_prefix_count; ++index) {
        snprintf(line, sizeof(line),
                 "    Prefix    : legacy prefix byte=0x%02x (%s)\n",
                 instruction->legacy_prefixes[index],
                 x86_legacy_prefix_name(instruction->legacy_prefixes[index]));
        x86_append_detail(instruction->details, sizeof(instruction->details), line);
    }

    if (instruction->has_rex) {
        snprintf(line, sizeof(line),
                 "    Prefix    : REX prefix byte=0x%02x -> W=%u R=%u X=%u B=%u\n",
                 (unsigned int)(instruction->rex | 0x40),
                 (instruction->rex >> 3) & 1u,
                 (instruction->rex >> 2) & 1u,
                 (instruction->rex >> 1) & 1u,
                 instruction->rex & 1u);
        x86_append_detail(instruction->details, sizeof(instruction->details), line);
    }
}

void x86_append_detail(char *buffer, size_t buffer_size, const char *text) {
    size_t used = strlen(buffer);
    if (used >= buffer_size) return;
    snprintf(buffer + used, buffer_size - used, "%s", text);
}

void x86_format_bytes(const x86_decoded_instruction_t *instruction, char *buffer, size_t buffer_size) {
    size_t index;
    size_t used = 0;

    if (!instruction || !buffer || buffer_size == 0) return;

    buffer[0] = '\0';
    for (index = 0; index < instruction->byte_count; ++index) {
        int written = snprintf(buffer + used, buffer_size - used,
                               index == 0 ? "%02x" : " %02x",
                               instruction->bytes[index]);
        if (written < 0 || (size_t)written >= buffer_size - used) break;
        used += (size_t)written;
    }
}

void x86_format_objdump_line(const x86_decoded_instruction_t *instruction, char *buffer, size_t buffer_size) {
    char bytes[64];

    if (!buffer || buffer_size == 0) return;
    buffer[0] = '\0';
    if (!instruction) return;

    x86_format_bytes(instruction, bytes, sizeof(bytes));
    snprintf(buffer, buffer_size,
             "0x%016llx:  %-28s %s",
             (unsigned long long)instruction->address,
             bytes,
             instruction->text);
}

void x86_format_memory_operand(char *buffer,
                               size_t buffer_size,
                               x86_modrm_fields_t modrm,
                               int rex_b,
                               int rex_x,
                               int displacement_size,
                               int32_t displacement,
                               int has_sib,
                               uint8_t sib_byte) {
    char disp[32] = "";

    if (displacement_size == 1 || displacement_size == 4) {
        if (displacement < 0) {
            snprintf(disp, sizeof(disp), "-0x%x", (unsigned int)(-displacement));
        } else if (displacement > 0) {
            snprintf(disp, sizeof(disp), "+0x%x", (unsigned int)displacement);
        }
    }

    if (has_sib) {
        x86_sib_fields_t sib = x86_parse_sib(sib_byte);
        int base = sib.base | (rex_b << 3);
        int index = sib.index | (rex_x << 3);
        int scale = 1 << sib.scale;

        if (modrm.mod == 0 && sib.base == 5) {
            snprintf(buffer, buffer_size, "%s(%s,%d)", disp[0] ? disp + 1 : "0x0", x86_register_name(index, 1), scale);
        } else if (sib.index == 4 && rex_x == 0) {
            if (disp[0] == '-') {
                snprintf(buffer, buffer_size, "-0x%x(%%%s)", (unsigned int)(-displacement), x86_register_name(base, 1));
            } else if (disp[0] == '+') {
                snprintf(buffer, buffer_size, "0x%x(%%%s)", (unsigned int)displacement, x86_register_name(base, 1));
            } else {
                snprintf(buffer, buffer_size, "(%%%s)", x86_register_name(base, 1));
            }
        } else {
            if (disp[0] == '-') {
                snprintf(buffer, buffer_size, "-0x%x(%%%s,%%%s,%d)",
                         (unsigned int)(-displacement),
                         x86_register_name(base, 1),
                         x86_register_name(index, 1),
                         scale);
            } else if (disp[0] == '+') {
                snprintf(buffer, buffer_size, "0x%x(%%%s,%%%s,%d)",
                         (unsigned int)displacement,
                         x86_register_name(base, 1),
                         x86_register_name(index, 1),
                         scale);
            } else {
                snprintf(buffer, buffer_size, "(%%%s,%%%s,%d)",
                         x86_register_name(base, 1),
                         x86_register_name(index, 1),
                         scale);
            }
        }
        return;
    }

    if (modrm.mod == 0 && modrm.rm == 5) {
        snprintf(buffer, buffer_size, "0x%x(%%rip)", (unsigned int)displacement);
        return;
    }

    if (disp[0] == '-') {
        snprintf(buffer, buffer_size, "-0x%x(%%%s)", (unsigned int)(-displacement), x86_register_name(modrm.rm | (rex_b << 3), 1));
    } else if (disp[0] == '+') {
        snprintf(buffer, buffer_size, "0x%x(%%%s)", (unsigned int)displacement, x86_register_name(modrm.rm | (rex_b << 3), 1));
    } else {
        snprintf(buffer, buffer_size, "(%%%s)", x86_register_name(modrm.rm | (rex_b << 3), 1));
    }
}

void x86_describe_operands(x86_decoded_instruction_t *instruction) {
    size_t offset = 0;
    char line[256];

    instruction->details[0] = '\0';
    describe_prefixes(instruction);

    if (instruction->byte_count > 0) {
        char opcode_bytes_text[64] = "";
        size_t opcode_count = opcode_bytes(instruction);
        append_hex_bytes(opcode_bytes_text, sizeof(opcode_bytes_text),
                         instruction->bytes + prefix_bytes(instruction), opcode_count);
        snprintf(line, sizeof(line),
                 "    Opcode    : %s%s\n",
                 opcode_count == 2 ? "escape+opcode bytes=" : "byte=",
                 opcode_bytes_text);
        x86_append_detail(instruction->details, sizeof(instruction->details), line);
        offset = prefix_bytes(instruction) + opcode_count;
    }

    if (instruction->has_modrm) {
        snprintf(line, sizeof(line),
                 "    ModR/M    : byte=0x%02x mod=%u reg=%u(%s) rm=%u(%s)\n",
                 instruction->modrm,
                 instruction->modrm_mod,
                 instruction->modrm_reg_full,
                 x86_register_name(instruction->modrm_reg_full, 1),
                 instruction->modrm_rm_full,
                 x86_register_name(instruction->modrm_rm_full, 1));
        x86_append_detail(instruction->details, sizeof(instruction->details), line);
        offset += 1;

        if (instruction->has_sib) {
            snprintf(line, sizeof(line),
                     "    SIB       : byte=0x%02x scale=%u(2^%u) index=%u(%s)%s base=%u(%s)\n",
                     instruction->sib,
                     instruction->sib_scale,
                     instruction->sib_scale_bits,
                     instruction->sib_index_full,
                     x86_register_name(instruction->sib_index_full, 1),
                     (instruction->sib_index == 4) ? " special=no index" : "",
                     instruction->sib_base_full,
                     x86_register_name(instruction->sib_base_full, 1));
            x86_append_detail(instruction->details, sizeof(instruction->details), line);
            offset += 1;
        }

        if (instruction->displacement_size > 0) {
            char disp_bytes[64] = "";
            append_hex_bytes(disp_bytes, sizeof(disp_bytes),
                             instruction->bytes + offset,
                             (size_t)instruction->displacement_size);
            snprintf(line, sizeof(line),
                     "    Disp      : %d bytes raw=%s value=%#x\n",
                     instruction->displacement_size,
                     disp_bytes,
                     instruction->displacement);
            x86_append_detail(instruction->details, sizeof(instruction->details), line);
            offset += (size_t)instruction->displacement_size;
        }
    }

    if (instruction->immediate_size > 0) {
        char imm_bytes[64] = "";
        append_hex_bytes(imm_bytes, sizeof(imm_bytes),
                         instruction->bytes + offset,
                         (size_t)instruction->immediate_size);
        snprintf(line, sizeof(line),
                 "    Immediate : %d bytes raw=%s value=%#x\n",
                 instruction->immediate_size,
                 imm_bytes,
                 instruction->immediate);
        x86_append_detail(instruction->details, sizeof(instruction->details), line);
    }
}

void x86_print_instruction(const x86_decoded_instruction_t *instruction) {
    char bytes[64];

    if (!instruction) return;

    x86_format_bytes(instruction, bytes, sizeof(bytes));
    printf("[0x%016llx]  %s\n", (unsigned long long)instruction->address, bytes);
    printf("  %s\n", instruction->text);
    if (instruction->details[0] != '\0') {
        printf("%s", instruction->details);
    }
}
