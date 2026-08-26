/* SPDX-License-Identifier: MIT */
#include "os/crc16.h"

uint16_t crc16(const void *data, size_t len)
{
    if (data == NULL) {
        return 0xFFFFu;
    }
    const uint8_t *p   = (const uint8_t *)data;
    uint16_t       crc = 0xFFFFu;

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)p[i] << 8);
        for (unsigned bit = 0; bit < 8u; bit++) {
            if ((crc & 0x8000u) != 0u) {
                crc = (uint16_t)((uint16_t)(crc << 1) ^ 0x1021u);
            } else {
                crc = (uint16_t)(crc << 1);
            }
        }
    }
    return crc;
}
