#include "decoder_internal.h"

int32_t x86_read_displacement(const uint8_t *code, size_t offset, int size) {
    if (size == 1) return (int8_t)code[offset];
    if (size == 4) {
        return (int32_t)((uint32_t)code[offset] |
                         ((uint32_t)code[offset + 1] << 8) |
                         ((uint32_t)code[offset + 2] << 16) |
                         ((uint32_t)code[offset + 3] << 24));
    }
    return 0;
}

int32_t x86_read_immediate(const uint8_t *code, size_t offset, int size) {
    if (size == 1) return (int8_t)code[offset];
    if (size == 4) {
        return (int32_t)((uint32_t)code[offset] |
                         ((uint32_t)code[offset + 1] << 8) |
                         ((uint32_t)code[offset + 2] << 16) |
                         ((uint32_t)code[offset + 3] << 24));
    }
    return 0;
}
