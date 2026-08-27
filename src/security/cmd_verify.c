/* SPDX-License-Identifier: MIT
 *
 * cmd_verify.c -- VERIFY (INS 20), ISO/IEC 7816-4.
 *
 * Two forms, and the difference is not cosmetic:
 *
 *   Lc = 0, no data   STATUS QUERY. "Do I need to authenticate, and how many
 *                     attempts do I have?" Spends nothing.
 *   Lc > 0            the actual attempt. Always spends a try.
 *
 * The query form exists because the alternative is worse. Without it a reader
 * that wants to know whether authentication is required has to attempt a PIN
 * to find out -- and a wrong guess costs a try. Cards that lack the query form
 * push readers into burning the cardholder's attempts on discovery.
 *
 * WHAT THE QUERY FORM DOES NOT LEAK
 *
 * It reports state and remaining attempts, which is what the card would tell
 * anyone who asked and is exactly what a reader needs to render a sane prompt.
 * It reveals nothing about the PIN itself, and it cannot be used as an oracle:
 * the numbers it returns change only when a real attempt is made.
 *
 * THE SUBSET IMPLEMENTED
 *
 * P1 must be 00. ISO/IEC 7816-4 assigns other P1 values -- notably FF, which
 * RESETS the security status rather than establishing it -- and those are
 * refused with 6A86 rather than guessed at. Implementing "forget that I
 * authenticated" as a side effect of a misread P1 would be a security bug in
 * the quietest possible form.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "os/kernel.h"
#include "security/pin.h"

/* pin_status -> status word. One place, so no handler invents its own. */
static uint16_t pin_error_to_sw(pin_status st, const pin_info *info)
{
    switch (st) {
    case PIN_OK:
        return SW_OK;

    case PIN_ERR_WRONG:
        /*
         * 63CX, X = attempts remaining. The count is deliberately given: a
         * reader that cannot tell the cardholder "two attempts left" leads to
         * cards blocked by accident, and hiding it buys nothing -- the
         * attacker learns the same number by counting their own attempts.
         *
         * X is one nibble, so it saturates at 15. PIN_MAX_TRY_LIMIT is 8, so
         * the saturation is unreachable; the mask is there because a status
         * word with a corrupted nibble is worse than one that is merely
         * imprecise.
         */
        return SW_NVM_CHANGED_PIN_TRIES(info->tries_left);

    case PIN_ERR_BLOCKED:
        /* 6983 and NOT 63C0. A reader that receives 63C0 may reasonably retry
         * with a different value; 6983 says the door is shut and retrying is
         * pointless. */
        return SW_AUTH_METHOD_BLOCKED; /* 6983 */

    case PIN_ERR_UNSET:
        /*
         * There is no PIN to compare against, because this card has never been
         * personalised with one -- see pin_personalise(), which deliberately
         * ships no default.
         *
         * 6A88 "reference data not found" is the honest answer. NOT 6983,
         * which would claim the PIN is blocked and send an administrator
         * hunting for a PUK that would not help. NOT 9000 either, which would
         * report success for an attempt that was never checked -- the failure
         * mode where a card with no PIN accepts every PIN.
         */
        return SW_REFERENCE_DATA_NOT_FOUND; /* 6A88 */

    case PIN_ERR_NOT_FOUND:
        return SW_REFERENCE_DATA_NOT_FOUND; /* 6A88 */

    case PIN_ERR_CORRUPT:
        /* A PIN record that fails its integrity check is not a card that
         * should be answering security questions. 6581 says the fault is the
         * card's, not the caller's. */
        return SW_MEMORY_FAILURE; /* 6581 */

    case PIN_ERR_NVM:
        return SW_MEMORY_FAILURE;

    case PIN_ERR_ENTROPY:
        /* Only reachable from pin_set(), but mapped here so the switch is
         * total and a new caller cannot fall into the default. */
        return SW_MEMORY_FAILURE;

    case PIN_ERR_PARAM:
    default:
        return SW_INCORRECT_P1P2;
    }
}

uint16_t scos_cmd_verify(scos_kernel *k, const apdu_command *cmd,
                         apdu_response *rsp)
{
    (void)rsp; /* VERIFY returns no data in either form */

    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }

    /* Only the "verification data provided" form. See the header comment for
     * why P1=FF in particular is refused rather than approximated. */
    if (cmd->p1 != 0x00u) {
        return SW_INCORRECT_P1P2; /* 6A86 */
    }

    const uint8_t ref = cmd->p2;
    if (ref != PIN_REF_USER && ref != PIN_REF_UNBLOCK) {
        /* An unknown qualifier is not a malformed command; it names something
         * this card does not have. */
        return SW_REFERENCE_DATA_NOT_FOUND; /* 6A88 */
    }

    if (cmd->le_present) {
        /* Neither form returns data. */
        return SW_WRONG_LENGTH; /* 6700 */
    }

    /* --------------------------------------------------- the query form --- */
    if (cmd->lc == 0u) {
        pin_info         info = { PIN_STATE_UNSET, 0u, 0u };
        const pin_status st   = pin_get(ref, &info);
        if (st != PIN_OK) {
            return pin_error_to_sw(st, &info);
        }
        if (info.state == PIN_STATE_BLOCKED) {
            return SW_AUTH_METHOD_BLOCKED;
        }
        if (info.state == PIN_STATE_UNSET) {
            return SW_REFERENCE_DATA_NOT_FOUND;
        }
        if (scos_is_authenticated(k, ref)) {
            /*
             * Already verified in this session. 9000 means "you need do
             * nothing", which is the useful answer -- and it is why the
             * authentication bitmask is consulted here rather than only in the
             * access-condition checks.
             */
            return SW_OK;
        }
        /* Not yet verified: say how many attempts remain. */
        return SW_NVM_CHANGED_PIN_TRIES(info.tries_left);
    }

    /* ------------------------------------------------- the attempt form --- */

    /*
     * Length is checked HERE and not inside pin_verify(), and the ordering
     * matters: a value of the wrong length is a malformed command, not a
     * failed attempt, so it must NOT cost a try. Otherwise a reader could
     * exhaust a cardholder's attempts with junk that was never compared
     * against anything -- and pin_verify() spends the try before it looks at
     * the value, by design.
     */
    if (cmd->lc < PIN_MIN_LEN || cmd->lc > PIN_MAX_LEN) {
        return SW_WRONG_LENGTH; /* 6700 */
    }
    if (cmd->data == NULL) {
        return SW_WRONG_LENGTH;
    }

    /*
     * A successful re-verification is still a real attempt. It is tempting to
     * short-circuit when the reference is already authenticated, but that
     * would turn VERIFY into a free oracle: an attacker holding an
     * authenticated session could test candidate PINs at no cost, and worse,
     * a wrong one would answer 9000.
     */
    pin_info         info = { PIN_STATE_UNSET, 0u, 0u };
    const pin_status st   = pin_verify(ref, cmd->data, (uint8_t)cmd->lc, &info);

    if (st == PIN_OK) {
        scos_set_authenticated(k, ref);
        return SW_OK;
    }

    /*
     * Any failure drops the authentication for this reference.
     *
     * Not merely tidy: without it, one successful verification followed by
     * wrong guesses would leave the session authenticated while the counter
     * ran down -- so an attacker who learned the PIN once could keep access
     * across a PIN change. Failure means "not authenticated", full stop.
     */
    scos_clear_authenticated(k, ref);
    return pin_error_to_sw(st, &info);
}
