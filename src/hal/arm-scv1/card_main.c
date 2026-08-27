/* SPDX-License-Identifier: MIT
 *
 * card_main.c -- SCV1 firmware entry point.
 *
 * The ARM equivalent of simulator/main.c. No arguments, because a chip has no
 * command line, and no return, because there is nothing to return to.
 */
#include "hal/hal.h"
#include "os/kernel.h"
#include "os/scos_config.h"
#include "scv1.h"
#include "scv1_internal.h"
#include "semihost.h"


/*
 * The card's RAM.
 *
 * One static object in SRAM, exactly as on the native build. Here the linker
 * script polices it for real: if this plus .bss plus the reserved stack exceeds
 * 16 KB, scv1.ld's ASSERT fails the link. That is the constraint a native build
 * cannot enforce.
 */
static scos_kernel s_card;

/*
 * The OS's ATR. Historical bytes 'S' 'C' 'O' 'S'.
 *
 *   3B    TS   direct convention
 *   94    T0   TA1 present, 4 historical bytes
 *   11    TA1  Fi/Di default (372/1)
 *   00    TB1  no programming voltage required (deprecated but common)
 *   53 43 4F 53   historical bytes, "SCOS"
 *
 * A blank card never sends this: the boot loader is answering then, with its
 * own ATR. See hal_arm_io.c and docs/chip-scv1.md.
 */
const uint8_t  scv1_atr_bytes[] = { 0x3B, 0x94, 0x11, 0x00, 0x53, 0x43, 0x4F, 0x53 };
const uint32_t scv1_atr_len     = (uint32_t)sizeof(scv1_atr_bytes);

static void put_u32_dec(uint32_t v)
{
    char buf[12];
    int  n = 0;
    if (v == 0u) {
        scv1_uart_puts("0");
        return;
    }
    while (v > 0u && n < (int)sizeof(buf)) {
        buf[n++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    char out[13];
    int  m = 0;
    while (n > 0) { out[m++] = buf[--n]; }
    out[m] = '\0';
    scv1_uart_puts(out);
}

static void banner(void)
{
    scv1_uart_puts("SmartCard OS on SCV1 (ARM Cortex-M3)\r\n");
    scv1_uart_puts("Version: " SCOS_VERSION_STRING "\r\n");
    /* Report OSFLASH, not CODE. The OS occupies the programmable slot; the
     * 8 KB below it is the boot ROM's and the OS can neither write nor
     * meaningfully claim it. */
    scv1_uart_puts("OSFLASH 0x00002000  ");
    put_u32_dec(SCV1_OSFLASH_SIZE / 1024u);
    scv1_uart_puts(" KB\r\nEEPROM  0x00010000  ");
    put_u32_dec(SCV1_EEPROM_SIZE / 1024u);
    scv1_uart_puts(" KB\r\nDFLASH  0x00014000  ");
    put_u32_dec(SCV1_DFLASH_SIZE / 1024u);
    scv1_uart_puts(" KB\r\nSRAM    0x20000000  ");
    put_u32_dec(SCV1_SRAM_SIZE / 1024u);
    scv1_uart_puts(" KB\r\nATR: 3B 94 11 00 53 43 4F 53\r\n");
    scv1_uart_puts("Started by the SCV1 boot ROM from an ACTIVE OS slot.\r\n");
    scv1_uart_puts(semihost_available()
                       ? "NVM: persistent (semihosting)\r\n"
                       : "NVM: volatile (no semihosting host)\r\n");
    scv1_uart_puts("Waiting for APDU...\r\n");
}

int main(void)
{
    if (hal_init() != HAL_OK) {
        scv1_uart_puts("fatal: HAL init failed\r\n");
        semihost_exit(1);
        for (;;) { }
    }

    /* A filesystem that will not mount is not a reason to stop: a card cannot
     * exit, and must answer 6581 so a reader can tell "corrupt filesystem"
     * from "dead card". See simulator/main.c for the same reasoning. */
    const scos_status st = scos_init(&s_card);
    if (st != SCOS_OK && s_card.lifecycle != SCOS_LC_FS_ERROR) {
        scv1_uart_puts("fatal: OS init failed\r\n");
        semihost_exit(1);
        for (;;) { }
    }
    if (s_card.lifecycle == SCOS_LC_FS_ERROR) {
        scv1_uart_puts("WARNING: filesystem did not mount; answering 6581\r\n");
    }

    banner();

    /* Serve APDUs until the reader disconnects. */
    scos_card_loop(&s_card);

    /* Orderly power-down: flush NVM. */
    hal_shutdown();
    scv1_uart_puts("card powered down\r\n");
    semihost_exit(0);

    /* Unreachable on an emulator; on real silicon the card simply loses power
     * here. Halting rather than returning, because there is nothing above us. */
    for (;;) {
        __asm__ volatile("wfi");
    }
}
