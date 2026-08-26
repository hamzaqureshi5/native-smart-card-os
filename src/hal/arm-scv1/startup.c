/* SPDX-License-Identifier: MIT
 *
 * startup.c -- SCV1 reset vector and C runtime bring-up.
 *
 * This is the code that runs before main(). On a native build the host loader
 * does all of it invisibly; on a chip somebody has to write it, and that
 * somebody is us.
 *
 * On reset an ARMv7-M core reads two words from address 0:
 *   [0x00] the initial stack pointer
 *   [0x04] the reset vector
 * and starts executing. Everything a C program assumes -- initialised
 * globals, zeroed statics -- has to be arranged by hand first.
 */
#include <stdint.h>

#include "scv1.h"
#include "scv1_internal.h"
#include "semihost.h"

/* Provided by scv1.ld. */
extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;

int main(void);

/* ---------------------------------------------------- fault handling ------ */

/*
 * A fault on a smart card is a SECURITY EVENT, not a crash to be recovered
 * from. Memory corruption, a bad pointer or an alignment fault may be the
 * visible effect of a fault-injection attack -- a voltage or clock glitch aimed
 * at skipping a comparison. The correct response is to stop, not to retry.
 *
 * A production card would additionally zeroize RAM, increment a persistent
 * tamper counter, and refuse to boot again if it trips too often. We halt and
 * say so, which is honest for a development target; the rest needs hardware
 * support and a policy decision (docs/threat-model.md).
 */
static void fault_halt(const char *what)
{
    /* Written directly to the UART: no buffering, no allocation, nothing that
     * could itself fail. We may be running on a corrupted stack. */
    SCV1_UART_CTRL = SCV1_UART_CTRL_TX_EN | SCV1_UART_CTRL_RX_EN;
    const char *p = what;
    while (*p != '\0') {
        while ((SCV1_UART_STATE & SCV1_UART_STATE_TX_FULL) != 0u) { }
        SCV1_UART_DATA = (uint32_t)(unsigned char)*p++;
    }
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/*
 * HardFault, with ONE deliberate recovery path.
 *
 * The only fault this card forgives is the semihosting probe: a BKPT executed
 * on purpose to find out whether a debug host exists (see semihost.h). When
 * that is in flight, we step the stacked PC over the 2-byte Thumb BKPT and
 * return, and the probe reports "no host".
 *
 * EVERY OTHER FAULT HALTS. That is not laziness. A fault may be the visible
 * effect of a fault-injection attack -- a voltage or clock glitch aimed at
 * skipping a comparison -- and "recover and carry on" is precisely what an
 * attacker wants. Note that the recovery is gated on a flag set immediately
 * before a known instruction, so it cannot be used as a general fault-skipping
 * primitive.
 *
 * On exception entry the core stacks {R0,R1,R2,R3,R12,LR,PC,xPSR}, so the
 * return address is the seventh word.
 */
#define FRAME_PC_INDEX 6u

void scv1_fault_c(uint32_t *frame);

void scv1_fault_c(uint32_t *frame)
{
    if (semihost_probe_in_flight() != 0) {
        semihost_probe_faulted();
        frame[FRAME_PC_INDEX] += 2u; /* BKPT is a 16-bit Thumb instruction */
        return;
    }
    fault_halt("\n!! SCV1 FAULT: HardFault\n");
}

/* Naked so no prologue disturbs the frame, and so LR keeps its EXC_RETURN
 * value: branching (not calling) means scv1_fault_c's own return performs the
 * exception return. */
__attribute__((naked)) static void handler_hardfault(void)
{
    __asm__ volatile(
        "mrs r0, msp   \n"
        "b scv1_fault_c\n");
}

static void handler_nmi(void)        { fault_halt("\n!! SCV1 FAULT: NMI\n"); }
static void handler_memmanage(void)  { fault_halt("\n!! SCV1 FAULT: MemManage\n"); }
static void handler_busfault(void)   { fault_halt("\n!! SCV1 FAULT: BusFault\n"); }
static void handler_usagefault(void) { fault_halt("\n!! SCV1 FAULT: UsageFault\n"); }
static void handler_default(void)    { fault_halt("\n!! SCV1 FAULT: unexpected interrupt\n"); }

/* DebugMonitor takes the BKPT instead of HardFault when debug is enabled, so
 * it needs the same recovery. */
__attribute__((naked)) static void handler_debugmon(void)
{
    __asm__ volatile(
        "mrs r0, msp   \n"
        "b scv1_fault_c\n");
}

/* ------------------------------------------------------ vector table ------ */

/*
 * ARMv7-M vector table.
 *
 * Entry 0 is not a handler: it is the initial value of the stack pointer. So
 * the table mixes an address with function pointers, and ISO C does not permit
 * casting between the two -- a union of both representations does the job
 * legally and still lays out one word per entry, which is what the hardware
 * reads.
 */
typedef union {
    void      (*handler)(void);
    uintptr_t   value;
} scv1_vector;

__attribute__((section(".vectors"), used))
const scv1_vector scv1_vectors[16] = {
    { .value   = (uintptr_t)&_estack },   /*  0: initial stack pointer  */
    { .handler = scv1_reset_handler   },  /*  1: reset                  */
    { .handler = handler_nmi          },  /*  2: NMI                    */
    { .handler = handler_hardfault    },  /*  3: HardFault              */
    { .handler = handler_memmanage    },  /*  4: MemManage              */
    { .handler = handler_busfault     },  /*  5: BusFault               */
    { .handler = handler_usagefault   },  /*  6: UsageFault             */
    { .value   = 0u }, { .value = 0u },   /*  7-8:  reserved            */
    { .value   = 0u }, { .value = 0u },   /*  9-10: reserved            */
    { .handler = handler_default      },  /* 11: SVCall                 */
    { .handler = handler_debugmon     },  /* 12: DebugMonitor           */
    { .value   = 0u },                    /* 13: reserved               */
    { .handler = handler_default      },  /* 14: PendSV                 */
    { .handler = handler_default      }   /* 15: SysTick                */
};

/* ------------------------------------------------------ reset handler ----- */

void scv1_reset_handler(void)
{
    /* 1. Copy initialised data from CODE to SRAM. Until this runs, every
     *    global with an initialiser holds garbage. */
    const uint32_t *src = &_sidata;
    uint32_t       *dst = &_sdata;
    while (dst < &_edata) {
        *dst++ = *src++;
    }

    /* 2. Zero .bss. C guarantees statics start at zero; nothing else provides
     *    that guarantee on a chip. */
    for (uint32_t *p = &_sbss; p < &_ebss; p++) {
        *p = 0u;
    }

    /* 3. Enter the OS. main() must never return -- there is nothing to return
     *    to. If it does, halt loudly rather than executing whatever follows. */
    (void)main();

    fault_halt("\n!! SCV1: main() returned\n");
}
