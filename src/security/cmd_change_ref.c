/* SPDX-License-Identifier: MIT
 *
 * cmd_change_ref.c -- CHANGE REFERENCE DATA (INS 24), ISO/IEC 7816-4.
 *
 * Without this command the PIN mechanism is unreachable: pin_personalise()
 * deliberately ships no default PIN, so VERIFY answers 6A88 forever and
 * nothing can be tested end to end. This is how a PIN comes into existence.
 *
 * THE ACCESS RULE, WHICH IS THE INTERESTING PART
 *
 *   PIN is UNSET    -> allowed. This is initial personalisation, and there is
 *                     no credential yet that could authorise it.
 *   PIN is ACTIVE   -> the reference must have been VERIFIED in this session.
 *   PIN is BLOCKED  -> refused. Changing a blocked PIN would be an unblock
 *                     without the PUK, which is the entire point of blocking.
 *
 * The middle rule is what makes the PIN mean anything at all before per-file
 * access conditions land. Without it, CHANGE REFERENCE DATA would be an
 * unauthenticated overwrite: anyone holding the reader could replace the PIN
 * with one they knew and then "authenticate" -- and every attempt counter,
 * blocked state and constant-time comparison in src/security/pin.c would be
 * decoration. CREATE FILE and DELETE FILE are still unauthenticated and that
 * is tracked for later in this milestone, but a PIN that can be silently
 * replaced is a different order of problem, so it is fixed here rather than
 * deferred.
 *
 * THE SUBSET IMPLEMENTED
 *
 * P1 = 01 only: the data field carries the NEW value and nothing else.
 *
 * ISO also defines P1 = 00, where the data field holds the old value followed
 * by the new one. That encoding requires the card to know where the boundary
 * is, which in practice means imposing a fixed PIN length -- typically an
 * 8-byte block padded with FF. This project does not impose a PIN format (see
 * pin.h), so there is no honest way to split that field, and P1 = 00 is
 * refused with 6A86 rather than guessed at. Guessing would mean a card that
 * accepts "12345678" as either a change from 1234 to 5678 or a change to
 * 12345678, depending on a convention nobody agreed to.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "os/kernel.h"
#include "security/pin.h"

uint16_t scos_cmd_change_ref_data(scos_kernel *k, const apdu_command *cmd,
                                  apdu_response *rsp)
{
    (void)rsp; /* returns no data */

    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }

    /* See the header: P1=00 needs a PIN format this project does not impose. */
    if (cmd->p1 != 0x01u) {
        return SW_INCORRECT_P1P2; /* 6A86 */
    }

    const uint8_t ref = cmd->p2;
    if (ref != PIN_REF_USER && ref != PIN_REF_UNBLOCK) {
        return SW_REFERENCE_DATA_NOT_FOUND; /* 6A88 */
    }
    if (cmd->le_present) {
        return SW_WRONG_LENGTH; /* 6700 */
    }
    if (cmd->lc < PIN_MIN_LEN || cmd->lc > PIN_MAX_LEN || cmd->data == NULL) {
        return SW_WRONG_LENGTH; /* 6700 */
    }

    /* What state is the reference in? The access rule depends entirely on it. */
    pin_info         info = { PIN_STATE_UNSET, 0u, 0u };
    const pin_status gst  = pin_get(ref, &info);
    if (gst != PIN_OK) {
        return (gst == PIN_ERR_NOT_FOUND) ? SW_REFERENCE_DATA_NOT_FOUND
                                          : SW_MEMORY_FAILURE;
    }

    if (info.state == PIN_STATE_BLOCKED) {
        /*
         * 6983. Allowing a blocked PIN to be changed would make blocking
         * pointless: an attacker who exhausted the counter could simply set a
         * new PIN and carry on. Recovery is the PUK's job, and RESET RETRY
         * COUNTER (INS 2C) does not exist yet -- so on this card a blocked PIN
         * is terminal. That is a deliberate, documented state, not an
         * oversight; see docs/roadmap.md.
         */
        return SW_AUTH_METHOD_BLOCKED; /* 6983 */
    }

    if (info.state == PIN_STATE_ACTIVE && !scos_is_authenticated(k, ref)) {
        /* 6982: the command is understood and the caller is not entitled to
         * it. Distinct from 6983, which says nobody is. */
        return SW_SECURITY_NOT_SATISFIED; /* 6982 */
    }

    /*
     * Try limit: kept at the existing one when replacing, and set to a default
     * on first personalisation.
     *
     * 3 is the value real cards use, and it is not arbitrary -- it is small
     * enough that guessing a 4-digit PIN is hopeless and large enough that a
     * cardholder mistyping twice does not lose the card.
     */
    const uint8_t limit = (info.try_limit != 0u) ? info.try_limit : 3u;

    const pin_status st = pin_set(ref, cmd->data, (uint8_t)cmd->lc, limit);
    if (st != PIN_OK) {
        /* -Wswitch-enum is on, so every value is listed. That is the point:
         * a new pin_status added later cannot silently fall into a default
         * that answers 6581 when it means something else. */
        switch (st) {
        case PIN_ERR_ENTROPY:
            /*
             * No salt, so no PIN. 6581 rather than a success with a weak salt:
             * crypto_random_bytes() refuses instead of falling back, and this
             * is the status word that refusal has to become. A card that set a
             * PIN with a predictable salt and answered 9000 would be worse
             * than one that failed loudly.
             */
            return SW_MEMORY_FAILURE; /* 6581 */
        case PIN_ERR_PARAM:
            return SW_WRONG_LENGTH;
        case PIN_ERR_NVM:
        case PIN_ERR_CORRUPT:
        case PIN_ERR_NOT_FOUND:
            return SW_MEMORY_FAILURE;
        /* Not reachable from pin_set(), which neither compares a value nor
         * consults the counter -- listed so the switch is total. */
        case PIN_ERR_WRONG:
        case PIN_ERR_BLOCKED:
        case PIN_ERR_UNSET:
        case PIN_OK:
        default:
            return SW_NO_PRECISE_DIAGNOSIS;
        }
    }

    /*
     * A new PIN means the old authentication is void.
     *
     * Whoever was authenticated was authenticated against a value that no
     * longer exists, so keeping the bit set would let the session continue on
     * a credential the card has forgotten. It also means the caller must
     * VERIFY the new PIN before doing anything that requires it, which is the
     * behaviour that makes a compromised-then-changed PIN actually revoke
     * access.
     */
    scos_clear_authenticated(k, ref);
    return SW_OK;
}
