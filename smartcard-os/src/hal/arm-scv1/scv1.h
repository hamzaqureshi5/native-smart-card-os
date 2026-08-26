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
 * real hardware documentation arrives, src/hal/samsung/ gets written
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
 * CODE          0x00000000    64 KB  OS code, rodata, vector table. "ROM".
 * EEPROM        0x00010000    16 KB  byte-writable, high endurance. Metadata.
 * DFLASH        0x00014000   256 KB  page-erased (256 B). File data.
 * SRAM          0x20000000    16 KB  volatile.
 *
 * Kept identical to the simulator's geometry so the same filesystem image is
 * valid on both, and so the RAM/ROM budgets mean the same thing.
 */
#define SCV1_CODE_BASE    0x00000000u
#define SCV1_CODE_SIZE    (64u * 1024u)

#define SCV1_EEPROM_BASE  0x00010000u
#define SCV1_EEPROM_SIZE  (16u * 1024u)
#define SCV1_EEPROM_PAGE  4u

#define SCV1_DFLASH_BASE  0x00014000u
#define SCV1_DFLASH_SIZE  (256u * 1024u)
#define SCV1_DFLASH_PAGE  256u

#define SCV1_SRAM_BASE    0x20000000u
#define SCV1_SRAM_SIZE    (16u * 1024u)

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

/* SysTick -- ARMv7-M core peripheral, address fixed by the architecture. */
#define SCV1_SYSTICK_CSR  (*(volatile uint32_t *)0xE000E010u)
#define SCV1_SYSTICK_RVR  (*(volatile uint32_t *)0xE000E014u)
#define SCV1_SYSTICK_CVR  (*(volatile uint32_t *)0xE000E018u)

#define SCV1_SYSTICK_ENABLE    0x1u
#define SCV1_SYSTICK_TICKINT   0x2u
#define SCV1_SYSTICK_CLKSOURCE 0x4u

/* Declared system clock. A real part's clock is a datasheet fact and often
 * attacker-influenced; see hal_timer_get_ms() on why the OS must never make a
 * security decision from time. */
#define SCV1_SYSCLK_HZ 25000000u

#endif /* SCV1_H */
