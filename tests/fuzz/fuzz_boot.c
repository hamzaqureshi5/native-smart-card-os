/* SPDX-License-Identifier: MIT
 *
 * fuzz_boot.c -- the boot loader, driven by arbitrary bytes.
 *
 * This target matters more than the others. The OS can be reloaded if it turns
 * out to be broken; the boot loader is mask ROM and cannot. A crash here is a
 * dead part, and a memory-safety bug here is an attacker writing wherever they
 * like in code flash on a chip they physically hold.
 *
 * The input is treated as a SEQUENCE of commands so that ordering bugs are
 * reachable -- ERASE after VERIFY, ACTIVATE over a damaged header, LOAD after
 * ACTIVATE. Each command is length-prefixed:
 *
 *     [len][len bytes of APDU][len][len bytes of APDU]...
 *
 * After every command the invariants below are re-checked. They are the whole
 * point of the target: the loader is allowed to reject anything, but it is
 * never allowed to corrupt flash outside the slot, and it is never allowed to
 * report a bootable image that is not actually there.
 */
#include "boot/boot_loader.h"
#include "boot/cflash.h"
#include "os/crc16.h"

#include "fuzz_targets.h"

#include <assert.h>
#include <string.h>

#define F_PAGE      1024u
#define F_OSFLASH   (4u * 1024u)
#define F_OSHDR     1024u
#define F_LOAD_ADDR 0x00002000u
#define F_SRAM_BASE 0x20000000u
#define F_SRAM_SIZE (16u * 1024u)

/* Guard bands either side of each region. Nothing the loader does may touch
 * them; ASan would catch a wild pointer, but a one-byte overrun into adjacent
 * valid memory would not show up any other way. */
#define GUARD      64u
#define GUARD_BYTE 0xC7u

static uint8_t g_flash_mem[GUARD + F_OSFLASH + GUARD];
static uint8_t g_hdr_mem[GUARD + F_OSHDR + GUARD];

static uint8_t *flash(void)
{ return &g_flash_mem[GUARD]; }
static uint8_t *hdr(void)
{ return &g_hdr_mem[GUARD]; }

static void guards_intact(void)
{
    for (uint32_t i = 0; i < GUARD; i++) {
        assert(g_flash_mem[i] == GUARD_BYTE);
        assert(g_flash_mem[GUARD + F_OSFLASH + i] == GUARD_BYTE);
        assert(g_hdr_mem[i] == GUARD_BYTE);
        assert(g_hdr_mem[GUARD + F_OSHDR + i] == GUARD_BYTE);
    }
}

int scos_fuzz_boot(const uint8_t *data, size_t size)
{
    memset(g_flash_mem, GUARD_BYTE, sizeof(g_flash_mem));
    memset(g_hdr_mem, GUARD_BYTE, sizeof(g_hdr_mem));
    memset(flash(), 0xFF, F_OSFLASH);
    memset(hdr(), 0xFF, F_OSHDR);

    boot_ctx ctx;
    boot_ctx_init(&ctx, flash(), F_OSFLASH, hdr(), F_OSHDR, F_PAGE, F_LOAD_ADDR,
                  F_SRAM_BASE, F_SRAM_SIZE);

    size_t pos = 0;
    while (pos < size) {
        const size_t n = data[pos++];
        if (n == 0u || pos + n > size) {
            break;
        }
        uint8_t     rsp[BOOT_STATUS_RSP_LEN];
        uint32_t    rsp_len = 0xFFFFFFFFu;
        boot_action act     = (boot_action)0xFF;

        memset(rsp, 0x5A, sizeof(rsp));
        const uint16_t sw = boot_handle(&ctx, &data[pos], (uint32_t)n, rsp,
                                        sizeof(rsp), &rsp_len, &act);
        pos += n;

        /* 1. A status word is always produced, and it is a real one. */
        assert(sw != 0x0000u);
        const uint8_t sw1 = (uint8_t)(sw >> 8);
        assert(sw1 >= 0x61u);

        /* 2. Response length is set, and within the buffer. */
        assert(rsp_len <= sizeof(rsp));

        /* 3. A response is only produced on success. */
        if (sw != 0x9000u) {
            assert(rsp_len == 0u);
        }

        /* 4. RESTART is only ever signalled with a 9000. */
        assert(act == BOOT_ACT_NONE || act == BOOT_ACT_RESTART);
        if (act == BOOT_ACT_RESTART) {
            assert(sw == 0x9000u);
        }

        /* 5. Nothing outside the two regions was written. */
        guards_intact();

        /* 6. The central promise: if the slot says ACTIVE, the image really is
         *    there, really matches its CRC, and really is plausible code. This
         *    is the condition the reset path trusts before it jumps, so if
         *    any sequence of commands can make it lie, the card is brickable
         *    by a hostile reader. */
        boot_hdr              h = { 0u, 0u, 0u, 0u };
        const boot_slot_state st =
            boot_slot_check(hdr(), F_OSHDR, flash(), F_OSFLASH, &h);
        if (st == BOOT_SLOT_ACTIVE) {
            assert(h.length > 0u && h.length <= F_OSFLASH);
            assert(crc16(flash(), h.length) == h.image_crc);
            assert(boot_image_plausible(flash(), h.length, F_LOAD_ADDR,
                                        F_SRAM_BASE, F_SRAM_SIZE));
        }

        /* 7. RESTART must never be granted unless the slot is ACTIVE. */
        if (act == BOOT_ACT_RESTART) {
            assert(st == BOOT_SLOT_ACTIVE);
        }
    }
    return 0;
}
