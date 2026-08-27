/* SPDX-License-Identifier: MIT
 *
 * kernel.h -- Card OS kernel.
 *
 * WHY THIS IS NOT A LINUX-STYLE KERNEL
 * ------------------------------------
 * There are no processes, no scheduler, no interrupts to speak of, and no
 * heap. A smart card has exactly one thread of control and it is driven from
 * outside: the reader sends a command, the card computes, the card answers,
 * the card waits. Power can vanish between any two instructions. Under those
 * constraints a preemptive multitasking kernel buys nothing and costs
 * everything -- so this "kernel" is a command dispatcher plus a pile of
 * carefully guarded state.
 *
 * DESIGN RULE: scos_process() IS A PURE FUNCTION OF (state, command).
 * It performs no I/O. All I/O lives in scos_card_loop(), which does nothing
 * but pump bytes between the HAL and scos_process(). That split is what makes
 * the entire command surface testable without a reader, a socket or a file.
 */
#ifndef SCOS_KERNEL_H
#define SCOS_KERNEL_H

#include <stdbool.h>
#include <stdint.h>

#include "filesystem/fs_types.h"
#include "filesystem/fs.h"
#include "os/scos_config.h"

typedef enum {
    SCOS_OK        = 0,
    SCOS_ERR_PARAM = -1,
    SCOS_ERR_STATE = -2, /* called in the wrong lifecycle state */
    SCOS_ERR_HAL   = -3
} scos_status;

/* Card lifecycle. Mirrors the coarse ISO 7816-4 / GlobalPlatform notion of a
 * card life cycle; the fine-grained states arrive with the Card Manager. */
typedef enum {
    SCOS_LC_NO_POWER = 0,
    SCOS_LC_INITIALISING,
    SCOS_LC_OPERATIONAL,
    SCOS_LC_FS_ERROR,  /* filesystem unreadable: answers only with 6581 */
    SCOS_LC_TERMINATED /* unrecoverable; answers only with 6985 */
} scos_lifecycle;

/*
 * The card's entire volatile working set.
 *
 * This struct IS the card's RAM as far as the OS is concerned. It is allocated
 * statically by the platform (see simulator/main.c) -- never on a heap,
 * because there is no heap. Keeping it in one object means sizeof() is an
 * honest measure of our RAM footprint, which the _Static_assert below holds to
 * the configured budget. When a future subsystem needs RAM it gets a member
 * here and the build fails the moment we exceed the chip we are pretending to
 * have. That failure is the point.
 */
typedef struct {
    scos_lifecycle lifecycle;

    /* Reset counter. Volatile on purpose: it counts resets in this power
     * session, which is what an anti-tearing test wants to see. */
    uint32_t reset_count;

    /* --- current filesystem selection ------------------------------------ */
    /* The card's most important volatile state: almost every command is
     * implicitly scoped by it. See fs.h for the ISO transition rules. */
    fs_selection sel;

    /* --- APDU working buffers --------------------------------------------- */
    uint8_t  cmd[SCOS_APDU_CMD_MAX];
    uint16_t cmd_len;
    uint8_t  rsp[SCOS_APDU_RSP_MAX];
    uint16_t rsp_len;

    /* --- authentication state --------------------------------------------- */
    /*
     * One bit per successfully verified PIN reference: bit (ref-1).
     *
     * VOLATILE ON PURPOSE, and the reason is the whole point of the field. A
     * card must forget that a PIN was presented the moment power or the
     * session goes away -- otherwise pulling the card and re-inserting it
     * would leave it authenticated, and a stolen card would need no PIN at
     * all. scos_reset() zeroes the entire struct, so this is cleared by
     * construction rather than by anyone remembering to clear it.
     *
     * A bitmask rather than a bool because the PUK is a second reference and
     * being unblocked is not the same as being authenticated.
     */
    uint8_t auth;

    /* --- response waiting for GET RESPONSE -------------------------------- */
    /*
     * Under T=0 a command cannot return data the reader did not ask for: the
     * protocol has no way to send it. ISO/IEC 7816-4's answer is 61XX -- "I
     * have XX bytes for you" -- followed by the reader issuing GET RESPONSE.
     * These three fields are that pending data.
     *
     * pending_pos exists because the reader may collect the data in several
     * smaller GET RESPONSEs, each answered with a fresh 61XX for the rest.
     *
     * SECURITY-RELEVANT: this buffer is cleared by ANY command other than GET
     * RESPONSE, enforced in scos_process(). ISO requires GET RESPONSE to
     * immediately follow the command that produced the 61XX, and a card that
     * kept the data around would let a later, unrelated command collect the
     * output of an earlier one -- possibly across a change of selection or, in
     * M3, a change of authentication state.
     */
    uint8_t  pending[SCOS_PENDING_MAX];
    uint16_t pending_len;
    uint16_t pending_pos;
} scos_kernel;

/* --- authentication helpers ------------------------------------------------ */

static inline bool scos_is_authenticated(const scos_kernel *k, uint8_t ref)
{
    return k != NULL && ref >= 1u && ref <= 8u &&
           (k->auth & (uint8_t)(1u << (ref - 1u))) != 0u;
}

static inline void scos_set_authenticated(scos_kernel *k, uint8_t ref)
{
    if (k != NULL && ref >= 1u && ref <= 8u) {
        k->auth = (uint8_t)(k->auth | (uint8_t)(1u << (ref - 1u)));
    }
}

static inline void scos_clear_authenticated(scos_kernel *k, uint8_t ref)
{
    if (k != NULL && ref >= 1u && ref <= 8u) {
        k->auth = (uint8_t)(k->auth & (uint8_t)~(uint8_t)(1u << (ref - 1u)));
    }
}

_Static_assert(sizeof(scos_kernel) <= SCOS_OS_RAM_BUDGET_BYTES,
               "OS working set exceeds the configured RAM budget; either "
               "shrink it or raise SCOS_SIM_RAM_KB deliberately");

/* Cold boot. Zeroes volatile state and brings the card to OPERATIONAL.
 * hal_init() must already have succeeded. */
scos_status scos_init(scos_kernel *k);

/* Warm reset (reader asserted RST). Clears volatile state -- which in later
 * milestones means dropping PIN authentication and any open transaction --
 * while non-volatile memory survives. */
void scos_reset(scos_kernel *k);

/*
 * Execute one command APDU. THE CENTRAL ENTRY POINT OF THE OS.
 *
 * Guarantees, which the tests enforce:
 *   - Always produces a well-formed response of at least 2 bytes (SW1 SW2),
 *     for ANY input including empty, truncated and hostile.
 *   - Never reads outside cmd[0..cmd_len) or writes outside rsp[0..rsp_cap).
 *   - Never returns SCOS_OK without writing a status word.
 */
scos_status scos_process(scos_kernel *k, const uint8_t *cmd, uint16_t cmd_len,
                         uint8_t *rsp, uint16_t rsp_cap, uint16_t *rsp_len);

/* Receive/execute/respond until the reader disconnects. Uses only hal_card_*,
 * so it is identical on the simulator and on real silicon. */
void scos_card_loop(scos_kernel *k);

/* ------------------------------------------------- pending response data -- */

/*
 * Hand `n` bytes to the kernel for later collection by GET RESPONSE, and
 * return the status word to answer with: 61XX, where XX is n (00 meaning 256).
 *
 * Used by a command that has produced response data the reader cannot receive
 * yet -- a Case 3 SELECT is the canonical case, since the reader sent no Le
 * and under T=0 no data can be returned at all.
 *
 * Returns 6F00 and stages nothing if n is 0 or exceeds SCOS_PENDING_MAX: a
 * caller asking to stage more than can be announced is a bug in the OS, not a
 * protocol error, so it must not be reported as one.
 */
uint16_t scos_stage_response(scos_kernel *k, const uint8_t *data, uint16_t n);

/* Discard any pending response data. Called for every command except GET
 * RESPONSE; exposed so a future command can drop it explicitly. */
void scos_pending_clear(scos_kernel *k);

/* Bytes still waiting. 0 means nothing is pending. */
uint16_t scos_pending_remaining(const scos_kernel *k);

#endif /* SCOS_KERNEL_H */
