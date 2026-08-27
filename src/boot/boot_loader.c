/* SPDX-License-Identifier: MIT
 *
 * boot_loader.c -- SCV1 boot loader logic. See boot_loader.h.
 */
#include "boot/boot_loader.h"
#include "boot/cflash.h"
#include "os/crc16.h"

/* ISO/IEC 7816-4 status words. Reusing the standard ones rather than inventing
 * proprietary values: a reader that already understands a card understands
 * these, and there is nothing here that ISO does not already have a word for. */
#define SW_OK             0x9000u
#define SW_WRONG_LENGTH   0x6700u
#define SW_WRONG_P1P2     0x6A86u
#define SW_NO_SPACE       0x6A84u
#define SW_COND_NOT_MET   0x6985u
#define SW_MEMORY_FAILURE 0x6581u
#define SW_NOT_FOUND      0x6A82u
#define SW_BAD_DATA       0x6A80u
#define SW_DATA_INVALID   0x6984u
#define SW_INS_NOT_SUP    0x6D00u
#define SW_CLA_NOT_SUP    0x6E00u

void boot_ctx_init(boot_ctx *ctx, uint8_t *osflash, uint32_t osflash_size,
                   uint8_t *oshdr, uint32_t oshdr_size, uint32_t page_size,
                   uint32_t load_addr, uint32_t sram_base, uint32_t sram_size)
{
    if (ctx == NULL) {
        return;
    }
    ctx->osflash      = osflash;
    ctx->osflash_size = osflash_size;
    ctx->oshdr        = oshdr;
    ctx->oshdr_size   = oshdr_size;
    ctx->page_size    = page_size;
    ctx->load_addr    = load_addr;
    ctx->sram_base    = sram_base;
    ctx->sram_size    = sram_size;
    ctx->high_water   = 0u;
    ctx->erased       = false;
}

/* -------------------------------------------------------- slot inspection -- */

boot_slot_state boot_slot_check(const uint8_t *oshdr, uint32_t oshdr_size,
                                const uint8_t *osflash, uint32_t osflash_size,
                                boot_hdr *out)
{
    boot_hdr h = { 0u, 0u, 0u, 0u };

    if (oshdr == NULL || oshdr_size < BOOT_HDR_SIZE || osflash == NULL) {
        return BOOT_SLOT_DAMAGED;
    }
    if (!boot_hdr_parse(oshdr, &h)) {
        /* No magic, wrong version, or a bad header CRC. An erased page lands
         * here, and so does a half-written one -- both mean "nothing to boot",
         * so they get the same answer rather than a scary one. */
        return BOOT_SLOT_BLANK;
    }
    if (out != NULL) {
        *out = h;
    }
    if (h.length == 0u || h.length > osflash_size) {
        return BOOT_SLOT_DAMAGED;
    }
    if (crc16(osflash, h.length) != h.image_crc) {
        return BOOT_SLOT_DAMAGED;
    }
    return (h.state == BOOT_STATE_ACTIVE) ? BOOT_SLOT_ACTIVE : BOOT_SLOT_LOADED;
}

bool boot_image_plausible(const uint8_t *img, uint32_t len, uint32_t load_addr,
                          uint32_t sram_base, uint32_t sram_size)
{
    if (img == NULL || len < 8u) {
        return false;
    }
    /* Little-endian, read byte-wise: the image is ARM code regardless of what
     * the host running this check happens to be. */
    const uint32_t sp = ((uint32_t)img[0]) | ((uint32_t)img[1] << 8) |
                        ((uint32_t)img[2] << 16) | ((uint32_t)img[3] << 24);
    const uint32_t pc = ((uint32_t)img[4]) | ((uint32_t)img[5] << 8) |
                        ((uint32_t)img[6] << 16) | ((uint32_t)img[7] << 24);

    /* The initial SP is the value pushed onto, so it may legitimately be one
     * past the top of SRAM -- the stack is pre-decrement. It must not be below
     * the base, and must be 4-byte aligned (8 in practice, but ARMv7-M only
     * requires the stack to be 4-aligned outside exception entry). */
    const uint64_t sram_end = (uint64_t)sram_base + (uint64_t)sram_size;
    if ((uint64_t)sp <= (uint64_t)sram_base || (uint64_t)sp > sram_end) {
        return false;
    }
    if ((sp % 4u) != 0u) {
        return false;
    }
    /* Thumb bit. ARMv7-M has no ARM state; a reset vector with bit 0 clear
     * faults immediately, so this catches a byte-swapped or non-ARM image. */
    if ((pc & 1u) == 0u) {
        return false;
    }
    const uint32_t entry = pc & ~1u;
    if (entry < load_addr) {
        return false;
    }
    if ((uint64_t)entry >= (uint64_t)load_addr + (uint64_t)len) {
        return false;
    }
    return true;
}

/* ------------------------------------------------------------- responses --- */

static uint16_t build_status(const boot_ctx *ctx, uint8_t *rsp,
                             uint32_t rsp_cap, uint32_t *rsp_len)
{
    if (rsp_cap < BOOT_STATUS_RSP_LEN) {
        return SW_WRONG_LENGTH;
    }
    boot_hdr              h  = { 0u, 0u, 0u, 0u };
    const boot_slot_state st = boot_slot_check(
        ctx->oshdr, ctx->oshdr_size, ctx->osflash, ctx->osflash_size, &h);
    const bool have_hdr = (st == BOOT_SLOT_LOADED || st == BOOT_SLOT_ACTIVE);

    rsp[0]   = 1u; /* loader protocol version           */
    rsp[1]   = (uint8_t)st;
    rsp[2]   = (uint8_t)(ctx->osflash_size >> 24);
    rsp[3]   = (uint8_t)(ctx->osflash_size >> 16);
    rsp[4]   = (uint8_t)(ctx->osflash_size >> 8);
    rsp[5]   = (uint8_t)(ctx->osflash_size);
    rsp[6]   = have_hdr ? (uint8_t)(h.length >> 24) : 0u;
    rsp[7]   = have_hdr ? (uint8_t)(h.length >> 16) : 0u;
    rsp[8]   = have_hdr ? (uint8_t)(h.length >> 8) : 0u;
    rsp[9]   = have_hdr ? (uint8_t)(h.length) : 0u;
    rsp[10]  = have_hdr ? (uint8_t)(h.image_crc >> 8) : 0u;
    rsp[11]  = have_hdr ? (uint8_t)(h.image_crc) : 0u;
    rsp[12]  = (uint8_t)BOOT_BLOCK_SIZE;
    rsp[13]  = ctx->erased ? 1u : 0u;
    rsp[14]  = (uint8_t)(ctx->high_water >> 8);
    rsp[15]  = (uint8_t)(ctx->high_water);
    *rsp_len = BOOT_STATUS_RSP_LEN;
    return SW_OK;
}

/* ------------------------------------------------------------- commands ---- */

static uint16_t do_erase(boot_ctx *ctx)
{
    /* Header first. If power is lost between the two erases, a card with a
     * blank header and a half-erased image reads as BLANK and stays in the
     * loader -- recoverable. The other order could leave a valid-looking
     * header pointing at an erased image, which reads as DAMAGED. */
    if (cf_erase_all(ctx->oshdr, ctx->oshdr_size, ctx->page_size) != CF_OK) {
        return SW_MEMORY_FAILURE;
    }
    if (cf_erase_all(ctx->osflash, ctx->osflash_size, ctx->page_size) !=
        CF_OK) {
        return SW_MEMORY_FAILURE;
    }
    ctx->erased     = true;
    ctx->high_water = 0u;
    return SW_OK;
}

static uint16_t do_load(boot_ctx *ctx, uint8_t p1, uint8_t p2,
                        const uint8_t *data, uint32_t lc)
{
    if (!ctx->erased) {
        /* Refusing rather than erasing implicitly. An implicit erase triggered
         * by a stray APDU would destroy a working OS, and the whole point of
         * the ACTIVE flag is that the card should be hard to brick by
         * accident. The host has to say ERASE. */
        return SW_COND_NOT_MET;
    }
    if (lc == 0u || lc > BOOT_BLOCK_SIZE) {
        return SW_WRONG_LENGTH;
    }
    const uint32_t block = ((uint32_t)p1 << 8) | (uint32_t)p2;
    const uint32_t off   = block * BOOT_BLOCK_SIZE; /* max 65535*128 < 2^24 */
    const uint64_t end   = (uint64_t)off + (uint64_t)lc;
    if (end > (uint64_t)ctx->osflash_size) {
        return SW_NO_SPACE;
    }
    const cf_status cst =
        cf_program(ctx->osflash, ctx->osflash_size, off, data, lc);
    if (cst == CF_ERR_NOT_ERASED) {
        /* The host sent the same block twice, or overlapping blocks. Real
         * flash cannot honour that and neither do we. */
        return SW_COND_NOT_MET;
    }
    if (cst != CF_OK) {
        return SW_MEMORY_FAILURE;
    }
    if ((uint32_t)end > ctx->high_water) {
        ctx->high_water = (uint32_t)end;
    }
    return SW_OK;
}

static uint16_t do_verify(boot_ctx *ctx, const uint8_t *data, uint32_t lc)
{
    if (lc != 6u) {
        return SW_WRONG_LENGTH;
    }
    if (!ctx->erased) {
        return SW_COND_NOT_MET;
    }
    const uint32_t len = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                         ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    const uint16_t crc = (uint16_t)(((uint16_t)data[4] << 8) | data[5]);

    if (len == 0u || len > ctx->osflash_size) {
        return SW_NO_SPACE;
    }
    if (len > ctx->high_water) {
        /* Claiming more bytes than were ever written. The tail would be 0xFF,
         * so the CRC would almost certainly fail anyway -- but saying so
         * precisely is more useful than a CRC error. */
        return SW_BAD_DATA;
    }
    if (crc16(ctx->osflash, len) != crc) {
        return SW_BAD_DATA;
    }
    if (!boot_image_plausible(ctx->osflash, len, ctx->load_addr, ctx->sram_base,
                              ctx->sram_size)) {
        /* The bytes arrived intact but they are not an ARMv7-M image for this
         * chip. Refusing here, at VERIFY, is the difference between the host
         * seeing an error and the card faulting silently on the next reset. */
        return SW_DATA_INVALID;
    }
    uint8_t  raw[BOOT_HDR_SIZE];
    boot_hdr h;
    h.length    = len;
    h.image_crc = crc;
    h.state     = BOOT_STATE_LOADED;
    h.version   = BOOT_HDR_VERSION;
    boot_hdr_serialise(&h, raw);

    if (cf_program(ctx->oshdr, ctx->oshdr_size, 0u, raw, BOOT_HDR_SIZE) !=
        CF_OK) {
        return SW_MEMORY_FAILURE;
    }
    return SW_OK;
}

static uint16_t do_activate(boot_ctx *ctx)
{
    boot_hdr              h  = { 0u, 0u, 0u, 0u };
    const boot_slot_state st = boot_slot_check(
        ctx->oshdr, ctx->oshdr_size, ctx->osflash, ctx->osflash_size, &h);
    if (st == BOOT_SLOT_BLANK) {
        return SW_NOT_FOUND;
    }
    if (st == BOOT_SLOT_DAMAGED) {
        return SW_DATA_INVALID;
    }
    if (st == BOOT_SLOT_ACTIVE) {
        return SW_OK; /* idempotent: already active */
    }
    /* Clear the state word. Only bit-clearing, so no erase is needed -- which
     * is the entire reason the state word is laid out this way. */
    const uint8_t zero[2] = { 0x00u, 0x00u };
    if (cf_program(ctx->oshdr, ctx->oshdr_size, 14u, zero, 2u) != CF_OK) {
        return SW_MEMORY_FAILURE;
    }
    return SW_OK;
}

/* ------------------------------------------------------------- dispatch ---- */

/*
 * A deliberately minimal APDU parse.
 *
 * The OS has a full ISO 7816-4 case-detecting parser in src/apdu/, and it is
 * fuzzed. This does NOT reuse it, on purpose. The loader lives in mask ROM: a
 * bug here cannot be fixed after the wafer is made, and linking the OS's
 * parser would mean the OS's future changes reach into unpatchable code. So
 * the loader accepts only the exact two shapes it needs -- a 5-byte header, or
 * a 5-byte header plus Lc bytes -- and rejects everything else. Fewer states,
 * less to get wrong.
 */
uint16_t boot_handle(boot_ctx *ctx, const uint8_t *cmd, uint32_t len,
                     uint8_t *rsp, uint32_t rsp_cap, uint32_t *rsp_len,
                     boot_action *action)
{
    if (ctx == NULL || cmd == NULL || rsp_len == NULL || action == NULL) {
        return SW_WRONG_LENGTH;
    }
    *rsp_len = 0u;
    *action  = BOOT_ACT_NONE;

    if (len < 4u) {
        return SW_WRONG_LENGTH;
    }
    if (cmd[0] != BOOT_CLA) {
        return SW_CLA_NOT_SUP;
    }
    const uint8_t ins = cmd[1];
    const uint8_t p1  = cmd[2];
    const uint8_t p2  = cmd[3];

    /* Body. len==4 is a header with no fifth byte; len==5 means the fifth byte
     * is Le (we ignore its value -- every response here is fixed size); len>5
     * means the fifth byte is Lc and must account for exactly the rest. */
    const uint8_t *data = NULL;
    uint32_t       lc   = 0u;
    if (len > 5u) {
        lc = (uint32_t)cmd[4];
        if (lc == 0u || lc != len - 5u) {
            return SW_WRONG_LENGTH;
        }
        data = &cmd[5];
    } else if (len == 5u) {
        if (cmd[4] != 0u && ins != BOOT_INS_GET_STATUS) {
            /* A non-zero fifth byte on a command that takes no data is a
             * truncated data command, not a Case 2. Say so. */
            return SW_WRONG_LENGTH;
        }
    }

    switch (ins) {
    case BOOT_INS_GET_STATUS:
        if (lc != 0u) {
            return SW_WRONG_LENGTH;
        }
        if (p1 != 0u || p2 != 0u) {
            return SW_WRONG_P1P2;
        }
        return build_status(ctx, rsp, rsp_cap, rsp_len);

    case BOOT_INS_ERASE:
        if (lc != 0u) {
            return SW_WRONG_LENGTH;
        }
        if (p1 != 0u || p2 != 0u) {
            return SW_WRONG_P1P2;
        }
        return do_erase(ctx);

    case BOOT_INS_LOAD:
        if (lc == 0u) {
            return SW_WRONG_LENGTH;
        }
        return do_load(ctx, p1, p2, data, lc);

    case BOOT_INS_VERIFY:
        if (lc == 0u) {
            return SW_WRONG_LENGTH;
        }
        if (p1 != 0u || p2 != 0u) {
            return SW_WRONG_P1P2;
        }
        return do_verify(ctx, data, lc);

    case BOOT_INS_ACTIVATE:
        if (lc != 0u) {
            return SW_WRONG_LENGTH;
        }
        if (p1 != 0u || p2 != 0u) {
            return SW_WRONG_P1P2;
        }
        return do_activate(ctx);

    case BOOT_INS_RESTART: {
        if (lc != 0u) {
            return SW_WRONG_LENGTH;
        }
        if (p1 != 0u || p2 != 0u) {
            return SW_WRONG_P1P2;
        }
        const boot_slot_state st = boot_slot_check(
            ctx->oshdr, ctx->oshdr_size, ctx->osflash, ctx->osflash_size, NULL);
        if (st != BOOT_SLOT_ACTIVE) {
            return SW_NOT_FOUND;
        }
        *action = BOOT_ACT_RESTART;
        return SW_OK;
    }

    default:
        return SW_INS_NOT_SUP;
    }
}
