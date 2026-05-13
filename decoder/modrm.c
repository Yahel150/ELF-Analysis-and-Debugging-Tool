#include "decoder_internal.h"

x86_modrm_fields_t x86_parse_modrm(uint8_t modrm) {
    x86_modrm_fields_t fields;
    fields.mod = (modrm >> 6) & 0x3;
    fields.reg = (modrm >> 3) & 0x7;
    fields.rm = modrm & 0x7;
    return fields;
}

x86_sib_fields_t x86_parse_sib(uint8_t sib) {
    x86_sib_fields_t fields;
    fields.scale = (sib >> 6) & 0x3;
    fields.index = (sib >> 3) & 0x7;
    fields.base = sib & 0x7;
    return fields;
}
