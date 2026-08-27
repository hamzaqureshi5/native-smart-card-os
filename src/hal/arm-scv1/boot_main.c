/* SPDX-License-Identifier: MIT
 *
 * boot_main.c -- the SCV1 boot ROM.
 *
 * This is what a blank chip runs. There is no OS yet, no filesystem, and
 * possibly nothing at all in the OS slot but erased flash. Its job is:
 *
 *   1. decide whether a trustworthy OS image is present,
 *   2. if so, hand the core over to it and never come back,
 *   3. if not, sit on the card interface and let a host program one.
 *
 * The decision logic and the command set are in src/boot/, which is pure and
 * host-tested. THIS file is the part that cannot be tested on the host: real
 * addresses, real flash, and the jump itself.
 */
#include <stdbool.h>
#include <stdint.h>

#include "boot/boot_loader.h"
#include "hal/hal.h"
#include "scv1.h"
#include "scv1_internal.h"
#include "semihost.h"

/*
 * The boot loader's ATR. Historical bytes 'B' 'O' 'O' 'T'.
 *
 * Deliberately distinguishable from the OS's ATR ('S' 'C' 'O' 'S'), because a
 * reader has no other way to tell a blank card from a programmed one before it
 * sends anything. The interface bytes are identical -- the link parameters are
 * a property of the chip, not of the software answering.
 */
const uint8_t  scv1_atr_bytes[] = { 0x3B, 0x94, 0x11, 0x00,
                                    0x42, 0x4F, 0x4F, 0x54 };
const uint32_t scv1_atr_len     = (uint32_t)sizeof(scv1_atr_bytes);

/* Real chip regions. Pointers rather than arrays: this memory is not ours to
 * define, it is where the chip put it. */
static uint8_t *const g_osflash = (uint8_t *)SCV1_OSFLASH_BASE;
static uint8_t *const g_oshdr   = (uint8_t *)SCV1_OSHDR_BASE;

static boot_ctx g_ctx;
static bool     g_dirty;

/* --------------------------------------------------------- persistence ---- */

/*
 * On real silicon flash is persistent the moment it is programmed and none of
 * this exists. On the emulator the OS slot is ordinary RAM that vanishes when
 * QEMU exits, so the boot ROM mirrors it to host files through semihosting --
 * the same trick, and the same honest caveat, as the NVM HAL.
 *
 * The mirror is written at the points that change whether the card is
 * bootable, not after every block. A power cut mid-load therefore loses the
 * partial image here, whereas real flash would keep it. That difference is not
 * observable: without a VERIFY there is no header, so a partial image is
 * unbootable either way and the card comes up in the loader regardless.
 */
#define OSFLASH_FILE "card_osflash.bin"
#define OSHDR_FILE   "card_oshdr.bin"

/*
 * BOOTSEL -- forced entry into the loader.
 *
 * Without this the card is a one-way door: the moment a slot goes ACTIVE the
 * boot ROM jumps past the loader on every reset, and the loader can never be
 * reached again. recycle.ldr would be delivered to the OS, which answers 6E00
 * because CLA 80 is not its. There would be no way to reprogram the part.
 *
 * Real parts solve this with a pin sampled at reset -- BOOTSEL, BOOT0, RECOV,
 * the name varies. Hold it, power up, and the mask ROM stays in the loader no
 * matter what is in flash. SCV1 has no GPIO modelled, so the strap is a host
 * file, checked exactly once at power-on: present means "held".
 *
 * ON A REAL PRODUCT THIS PIN IS NOT SHIPPED LIKE THIS. A card an attacker can
 * put back into an unauthenticated loader is a card whose OS an attacker can
 * replace. A production part authenticates loader entry and then blows a fuse
 * at issuance that disables the loader permanently. Both are in
 * docs/threat-model.md; neither is implemented, because the first needs the
 * crypto abstraction and the second needs real silicon.
 */
#define BOOTSEL_FILE "card_bootsel.bin"

static bool bootsel_asserted(void)
{
    if (!semihost_available()) {
        return false;
    }
    uint8_t probe[1];
    /* A file that opens at all counts as the strap being held; contents are
     * irrelevant, the same way a pin's history is. semihost_load returns -1
     * when the file does not exist. */
    return semihost_load(BOOTSEL_FILE, probe, (uint32_t)sizeof(probe)) >= 0;
}

static void slot_power_on(void)
{
    if (semihost_available()) {
        const long a =
            semihost_load(OSFLASH_FILE, g_osflash, SCV1_OSFLASH_SIZE);
        const long b = semihost_load(OSHDR_FILE, g_oshdr, SCV1_OSHDR_SIZE);
        if (a > 0 && b > 0) {
            return; /* a previously programmed card */
        }
    }
    /* No stored image. Erase to 0xFF -- the state a part leaves the factory
     * in. QEMU hands us zeroed RAM, which is NOT what blank flash looks like,
     * and a slot full of 0x00 would read as a header with a bad CRC rather
     * than as a blank card. */
    for (uint32_t i = 0; i < SCV1_OSFLASH_SIZE; i++) {
        g_osflash[i] = 0xFFu;
    }
    for (uint32_t i = 0; i < SCV1_OSHDR_SIZE; i++) {
        g_oshdr[i] = 0xFFu;
    }
}

static void slot_flush(void)
{
    if (!g_dirty || !semihost_available()) {
        return;
    }
    (void)semihost_store(OSFLASH_FILE, g_osflash, SCV1_OSFLASH_SIZE);
    (void)semihost_store(OSHDR_FILE, g_oshdr, SCV1_OSHDR_SIZE);
    g_dirty = false;
}

/* ------------------------------------------------------------- handover --- */

/*
 * Give the core to the OS.
 *
 * Three things have to happen, in this order:
 *
 *   VTOR   The vector table must point at the OS's, or the first fault -- or
 *          any exception -- would vector back into the boot ROM's handlers,
 *          which by then are describing the wrong program.
 *   MSP    The OS expects the stack pointer its own linker script chose. We
 *          are still on the boot ROM's stack; the moment MSP moves, every
 *          local in this function is gone, so sp and pc are read into
 *          registers BEFORE the write.
 *   BX     Branch, not call. There is no return.
 *
 * dsb/isb between the VTOR write and the jump: the write must be visible and
 * the pipeline must not still hold instructions fetched under the old mapping.
 */
__attribute__((noreturn)) static void boot_jump(uint32_t base)
{
    const uint32_t *v  = (const uint32_t *)base;
    const uint32_t  sp = v[0];
    const uint32_t  pc = v[1];

    SCV1_SCB_VTOR = base;
    __asm__ volatile("dsb\nisb" ::: "memory");
    __asm__ volatile("msr msp, %0\n"
                     "bx  %1\n"
                     :
                     : "r"(sp), "r"(pc)
                     : "memory");
    for (;;) {}
}

/* ------------------------------------------------------------- reporting -- */

static void put_hex8(uint8_t b)
{
    static const char d[] = "0123456789ABCDEF";
    char              s[3];
    s[0] = d[(b >> 4) & 0x0Fu];
    s[1] = d[b & 0x0Fu];
    s[2] = '\0';
    scv1_uart_puts(s);
}

static void put_u32(uint32_t v)
{
    char buf[11];
    int  n = 0;
    if (v == 0u) {
        scv1_uart_puts("0");
        return;
    }
    while (v > 0u && n < 10) {
        buf[n++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    char out[12];
    int  m = 0;
    while (n > 0) {
        out[m++] = buf[--n];
    }
    out[m] = '\0';
    scv1_uart_puts(out);
}

static const char *slot_name(boot_slot_state st)
{
    switch (st) {
    case BOOT_SLOT_BLANK:
        return "BLANK (no OS loaded)";
    case BOOT_SLOT_LOADED:
        return "LOADED (not activated)";
    case BOOT_SLOT_ACTIVE:
        return "ACTIVE";
    case BOOT_SLOT_DAMAGED:
        return "DAMAGED (header or image failed CRC)";
    default:
        return "?";
    }
}

static void banner(boot_slot_state st, const boot_hdr *h, bool strap)
{
    scv1_uart_puts("SCV1 BOOT ROM v1  (mask ROM, 8 KB at 0x00000000)\r\n");
    scv1_uart_puts("OS slot: 0x00002000  ");
    put_u32(SCV1_OSFLASH_SIZE / 1024u);
    scv1_uart_puts(" KB\r\nState:   ");
    scv1_uart_puts(slot_name(st));
    scv1_uart_puts("\r\n");
    if (st == BOOT_SLOT_LOADED || st == BOOT_SLOT_ACTIVE) {
        scv1_uart_puts("Image:   ");
        put_u32(h->length);
        scv1_uart_puts(" bytes, CRC ");
        put_hex8((uint8_t)(h->image_crc >> 8));
        put_hex8((uint8_t)h->image_crc);
        scv1_uart_puts("\r\n");
    }
    if (strap) {
        scv1_uart_puts("BOOTSEL: held -- staying in the loader\r\n");
    }
    scv1_uart_puts("ATR:     3B 94 11 00 42 4F 4F 54\r\n");
    scv1_uart_puts(semihost_available()
                       ? "Slot:    persistent (semihosting)\r\n"
                       : "Slot:    volatile (no semihosting host)\r\n");
    scv1_uart_puts("Waiting for loader APDUs (CLA 80)...\r\n");
}

/* ------------------------------------------------------------------ main -- */

/* Response buffer. The loader's largest response is 16 bytes; +2 for SW. */
static uint8_t s_rsp[BOOT_STATUS_RSP_LEN + 2u];
static uint8_t s_cmd[5u + BOOT_BLOCK_SIZE];

static void loader_loop(void)
{
    for (;;) {
        uint32_t         n = 0u;
        const hal_status hs =
            hal_card_receive(s_cmd, (uint32_t)sizeof(s_cmd), &n);

        if (hs == HAL_ERR_LINK_DOWN) {
            slot_flush();
            return;
        }
        if (hs == HAL_CARD_RESET) {
            /* A reset re-runs the boot decision. That is what makes the flow
             * "load, activate, reset, and the OS comes up" work. */
            slot_flush();
            boot_hdr h = { 0u, 0u, 0u, 0u };
            if (!bootsel_asserted() &&
                boot_slot_check(g_oshdr, SCV1_OSHDR_SIZE, g_osflash,
                                SCV1_OSFLASH_SIZE, &h) == BOOT_SLOT_ACTIVE) {
                boot_jump(SCV1_OSFLASH_BASE);
            }
            g_ctx.erased     = false;
            g_ctx.high_water = 0u;
            continue;
        }
        if (hs != HAL_OK) {
            continue;
        }

        boot_action    act    = BOOT_ACT_NONE;
        uint32_t       rsplen = 0u;
        const uint16_t sw     = boot_handle(&g_ctx, s_cmd, n, s_rsp,
                                            BOOT_STATUS_RSP_LEN, &rsplen, &act);
        if (sw == 0x9000u) {
            g_dirty = true; /* conservative: any success may have written */
        }
        s_rsp[rsplen]      = (uint8_t)(sw >> 8);
        s_rsp[rsplen + 1u] = (uint8_t)sw;
        (void)hal_card_send(s_rsp, rsplen + 2u);

        if (act == BOOT_ACT_RESTART) {
            slot_flush();
            boot_jump(SCV1_OSFLASH_BASE);
        }
    }
}

int main(void)
{
    scv1_uart_init();
    semihost_probe();

    slot_power_on();

    boot_hdr              h  = { 0u, 0u, 0u, 0u };
    const boot_slot_state st = boot_slot_check(
        g_oshdr, SCV1_OSHDR_SIZE, g_osflash, SCV1_OSFLASH_SIZE, &h);
    const bool strap = bootsel_asserted();

    /*
     * The boot decision. An ACTIVE slot whose CRC still matches, and whose
     * first two words still look like an ARMv7-M image, is booted. Anything
     * else falls through to the loader -- including DAMAGED, because a card
     * that will not boot is far more useful sitting in a loader that can
     * reprogram it than sitting in a fault loop.
     */
    if (!strap && st == BOOT_SLOT_ACTIVE &&
        boot_image_plausible(g_osflash, h.length, SCV1_OSFLASH_BASE,
                             SCV1_SRAM_BASE, SCV1_SRAM_SIZE)) {
        scv1_uart_puts("SCV1 BOOT ROM: OS slot ACTIVE, starting OS\r\n");
        boot_jump(SCV1_OSFLASH_BASE);
    }

    banner(st, &h, strap);

    boot_ctx_init(&g_ctx, g_osflash, SCV1_OSFLASH_SIZE, g_oshdr,
                  SCV1_OSHDR_SIZE, SCV1_CFLASH_PAGE, SCV1_OSFLASH_BASE,
                  SCV1_SRAM_BASE, SCV1_SRAM_SIZE);

    loader_loop();

    scv1_uart_puts("boot loader: link closed\r\n");
    semihost_exit(0);
    for (;;) {
        __asm__ volatile("wfi");
    }
}
