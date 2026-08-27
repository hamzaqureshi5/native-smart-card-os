/* SPDX-License-Identifier: MIT
 *
 * scv1.h -- SCV1 chip definitions.
 *
 * ======================================================================
 * SCV1 IS A CHIP WE INVENTED. IT IS NOT A REAL PRODUCT.
 *
 * "Smart Card Virtual, revision 1". Its memory map and peripheral layout
 * are OURS, defined in docs/chip-scv1.md. It is not a Samsung part, not
 * any other vendor's part, and no register value here was taken from any
 * vendor's documentation.
 *
 * What IS real and public:
 *   - the CPU architecture: ARM Cortex-M3 (ARMv7-M), fully documented in
 *     the ARMv7-M Architecture Reference Manual. Secure MCUs used in SIM
 *     and embedded-SE applications commonly use ARM SecurCore SC000/SC300,
 *     which implement ARMv6-M/ARMv7-M -- the same architecture. So the
 *     core is a realistic choice rather than a guess.
 *   - SysTick, at the architecturally fixed address below.
 *   - the ARM CMSDK APB UART, documented in ARM's CMSDK technical
 *     reference manual, which is what the MPS2 development platform (and
 *     therefore QEMU) provides.
 *
 * The point of SCV1 is to have a target that is honestly specified. When
 * real hardware documentation arrives, src/hal/s3m228a/ gets written
 * against it and this stays as the reference target.
 * ======================================================================
 */
#ifndef SCV1_H
#define SCV1_H

#include <stdint.h>

/* ------------------------------------------------------------ memory map -- */
/*
 * Region        Base         Size    Character
 * ------------- -----------  ------  ----------------------------------------
 * CODE          0x00000000    64 KB  executable. Subdivided below.
 * EEPROM        0x00010000    16 KB  byte-writable, high endurance. Metadata.
 * DFLASH        0x00014000   256 KB  page-erased (256 B). File data.
 * SRAM          0x20000000    16 KB  volatile.
 *
 * EEPROM/DFLASH geometry is kept identical to the native simulator so the same
 * filesystem image is valid on both.
 */
#define SCV1_CODE_BASE 0x00000000u
#define SCV1_CODE_SIZE (64u * 1024u)

/*
 * CODE is not one flat lump. A chip that can be shipped blank and programmed
 * afterwards must have something non-erasable to do the programming:
 *
 *   0x00000000  BOOTROM   8 KB   mask ROM. Holds the boot loader. The reset
 *                                vector lives here, so this is what runs on a
 *                                blank part. Physically unwritable -- an
 *                                attacker who owns the loader owns the card,
 *                                so the loader must not be replaceable.
 *   0x00002000  OSFLASH  55 KB   programmable. The OS image lands here, and
 *                                its vector table sits at OSFLASH_BASE.
 *   0x0000FC00  OSHDR     1 KB   programmable. One page describing the slot:
 *                                length, CRC, and whether it is ACTIVE.
 *
 * OSFLASH_BASE is 8 KB aligned, which satisfies the ARMv7-M requirement that
 * VTOR be aligned to at least 128 bytes (and to the table size rounded up to a
 * power of two). The boot loader points VTOR here before handing over.
 *
 * The header is at the TOP rather than the bottom so OSFLASH_BASE stays a
 * round number -- it is the address you will see in every link map and every
 * loader transcript, so it is worth keeping legible.
 */
#define SCV1_BOOTROM_BASE 0x00000000u
#define SCV1_BOOTROM_SIZE (8u * 1024u)

#define SCV1_OSFLASH_BASE 0x00002000u
#define SCV1_OSFLASH_SIZE (55u * 1024u)

#define SCV1_OSHDR_BASE 0x0000FC00u
#define SCV1_OSHDR_SIZE 1024u

/* Code flash erases a page at a time and can only clear bits; see cflash.h. */
#define SCV1_CFLASH_PAGE 1024u

#define SCV1_EEPROM_BASE 0x00010000u
#define SCV1_EEPROM_SIZE (16u * 1024u)
#define SCV1_EEPROM_PAGE 4u

#define SCV1_DFLASH_BASE 0x00014000u
#define SCV1_DFLASH_SIZE (256u * 1024u)
#define SCV1_DFLASH_PAGE 256u

#define SCV1_SRAM_BASE 0x20000000u
#define SCV1_SRAM_SIZE (16u * 1024u)

/* ------------------------------------------------------------ peripherals -- */

/*
 * UART0 -- stands in for the ISO/IEC 7816-3 contact interface.
 *
 * A real card has no general-purpose UART: it has a single bidirectional I/O
 * contact driven by a dedicated interface block that handles T=0/T=1 framing,
 * guard times and parity in hardware. This UART carries the same APDUs over a
 * simpler link, which is exactly the abstraction hal_card_send/receive exists
 * to provide -- the OS above cannot tell the difference.
 *
 * Register layout: ARM CMSDK APB UART (public).
 */
#define SCV1_UART0_BASE   0x40004000u
#define SCV1_UART_DATA    (*(volatile uint32_t *)(SCV1_UART0_BASE + 0x00u))
#define SCV1_UART_STATE   (*(volatile uint32_t *)(SCV1_UART0_BASE + 0x04u))
#define SCV1_UART_CTRL    (*(volatile uint32_t *)(SCV1_UART0_BASE + 0x08u))
#define SCV1_UART_BAUDDIV (*(volatile uint32_t *)(SCV1_UART0_BASE + 0x10u))

#define SCV1_UART_STATE_TX_FULL 0x1u
#define SCV1_UART_STATE_RX_FULL 0x2u
#define SCV1_UART_CTRL_TX_EN    0x1u
#define SCV1_UART_CTRL_RX_EN    0x2u

/* Vector Table Offset Register -- ARMv7-M core peripheral (SCB->VTOR), address
 * fixed by the architecture. The boot loader writes it to relocate the vector
 * table from BOOTROM to the loaded OS before jumping. */
#define SCV1_SCB_VTOR (*(volatile uint32_t *)0xE000ED08u)

/* SysTick -- ARMv7-M core peripheral, address fixed by the architecture. */
#define SCV1_SYSTICK_CSR (*(volatile uint32_t *)0xE000E010u)
#define SCV1_SYSTICK_RVR (*(volatile uint32_t *)0xE000E014u)
#define SCV1_SYSTICK_CVR (*(volatile uint32_t *)0xE000E018u)

#define SCV1_SYSTICK_ENABLE    0x1u
#define SCV1_SYSTICK_TICKINT   0x2u
#define SCV1_SYSTICK_CLKSOURCE 0x4u

/* Declared system clock. A real part's clock is a datasheet fact and often
 * attacker-influenced; see hal_timer_get_ms() on why the OS must never make a
 * security decision from time. */
#define SCV1_SYSCLK_HZ 25000000u

#endif /* SCV1_H */
