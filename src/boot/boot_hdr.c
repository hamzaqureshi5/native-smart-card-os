/* SPDX-License-Identifier: MIT
 *
 * boot_hdr.c -- serialise and parse the OS slot header. See boot_hdr.h.
 */
#include "boot/boot_hdr.h"
#include "os/crc16.h"

static uint16_t rd16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

bool boot_hdr_parse(const uint8_t raw[BOOT_HDR_SIZE], boot_hdr *out)
{
    if (raw == NULL || out == NULL) {
        return false;
    }
    if (raw[0] != BOOT_HDR_MAGIC_0 || raw[1] != BOOT_HDR_MAGIC_1 ||
        raw[2] != BOOT_HDR_MAGIC_2 || raw[3] != BOOT_HDR_MAGIC_3) {
        return false;
    }
    if (rd16(&raw[4]) != (uint16_t)BOOT_HDR_VERSION) {
        return false;
    }
    if (rd16(&raw[12]) != crc16(raw, 12u)) {
        return false;
    }
    out->version   = rd16(&raw[4]);
    out->length    = rd32(&raw[6]);
    out->image_crc = rd16(&raw[10]);
    out->state     = rd16(&raw[14]);
    return true;
}

void boot_hdr_serialise(const boot_hdr *in, uint8_t raw[BOOT_HDR_SIZE])
{
    if (in == NULL || raw == NULL) {
        return;
    }
    raw[0] = BOOT_HDR_MAGIC_0;
    raw[1] = BOOT_HDR_MAGIC_1;
    raw[2] = BOOT_HDR_MAGIC_2;
    raw[3] = BOOT_HDR_MAGIC_3;
    wr16(&raw[4], (uint16_t)BOOT_HDR_VERSION);
    wr32(&raw[6], in->length);
    wr16(&raw[10], in->image_crc);
    wr16(&raw[12], crc16(raw, 12u));
    /* State left erased: ACTIVATE clears bits here later, without an erase. */
    raw[14] = 0xFFu;
    raw[15] = 0xFFu;
}
