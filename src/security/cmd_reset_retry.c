/* SPDX-License-Identifier: MIT
 *
 * cmd_reset_retry.c -- RESET RETRY COUNTER (INS 2C), ISO/IEC 7816-4.
 *
 * Until this command existed, a blocked PIN on this card was TERMINAL: three
 * wrong attempts and the cardholder's credential was gone for good, with no
 * route back through any command. That was a deliberate, documented state --
 * better than a fake recovery -- but it is not what a real card does, and it
 * makes a mistyped PIN as bad as a lost card.
 *
 * The PUK exists to unblock the PIN, so the PUK cannot BE the PIN. It is a
 * separate reference (PIN_REF_UNBLOCK) with its own verifier, salt and
 * counter, and reference 2 has been reserved in the record layout since the
 * PIN landed for exactly this.
 *
 * ONE FORM IMPLEMENTED: P1 = 02, data = the PUK alone.
 *
 * The PIN's value is left untouched and only its counter is restored. That is
 * also the form usually wanted: a cardholder who mistyped their own PIN three
 * times knows it perfectly well, and forcing them to choose a new one to
 * recover is a worse outcome for no security gain.
 *
 * ISO also defines P1 = 00, where the data field carries the PUK followed by a
 * NEW PIN. Refused with 6A86, for the same reason CHANGE REFERENCE DATA
 * refuses its old||new form: two values in one field need a length to split
 * at, and this project imposes no PIN format.
 *
 * There is a tempting way to make it work -- store the PUK's length when the
 * PUK is set, and split there -- and it is rejected deliberately. The stored
 * length of a credential is information about that credential: it would tell
 * anyone who could read NVM exactly how long the PUK is, turning an unknown
 * search space into a known one. Paying that for a convenience form is a bad
 * trade, and the alternative is one extra command (RESET RETRY COUNTER then
 * CHANGE REFERENCE DATA) rather than a missing capability.
 *
 * THE ORDER OF OPERATIONS IS THE SECURITY PROPERTY
 *
 * The PUK is verified through pin_verify(), which spends a PUK try BEFORE
 * comparing -- so this command is not a way to attack the PUK for free either.
 * A wrong PUK costs a PUK attempt, and exhausting those blocks the PUK, at
 * which point the card really is terminal. That is the intended end state: the
 * recovery path is itself limited, or it would just be a second PIN with more
 * attempts.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "os/kernel.h"
#include "security/pin.h"

#define RRC_P1_WITH_NEW_PIN 0x00u /* PUK || new PIN -- refused, see header */
#define RRC_P1_PUK_ONLY     0x02u /* PUK alone                             */

uint16_t scos_cmd_reset_retry(scos_kernel *k, const apdu_command *cmd,
                              apdu_response *rsp)
{
    (void)rsp; /* returns no data */

    if (k == NULL || cmd == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    if (k->lifecycle == SCOS_LC_FS_ERROR) {
        return SW_MEMORY_FAILURE;
    }
    if (cmd->p1 != RRC_P1_PUK_ONLY) {
        /* Including RRC_P1_WITH_NEW_PIN, which is a real ISO form this card
         * does not implement rather than a malformed request -- see the header
         * for why the split it needs is not worth its cost. */
        return SW_INCORRECT_P1P2; /* 6A86 */
    }
    /*
     * P2 names the reference being UNBLOCKED, not the one being presented. The
     * PUK is implied: there is one unblocking credential on this card, and
     * letting a caller nominate which reference does the unblocking would let
     * a PIN unblock itself.
     */
    if (cmd->p2 != PIN_REF_USER) {
        return SW_REFERENCE_DATA_NOT_FOUND; /* 6A88 */
    }
    if (cmd->le_present) {
        return SW_WRONG_LENGTH; /* 6700 */
    }
    if (cmd->data == NULL || cmd->lc == 0u) {
        return SW_WRONG_LENGTH;
    }

    /* The PUK must exist before it can unblock anything. */
    pin_info         puk = { PIN_STATE_UNSET, 0u, 0u };
    const pin_status pst = pin_get(PIN_REF_UNBLOCK, &puk);
    if (pst != PIN_OK) {
        return SW_MEMORY_FAILURE;
    }
    if (puk.state == PIN_STATE_UNSET) {
        /*
         * No PUK, so no recovery -- and 6A88 says why: the reference data this
         * command needs is not there. NOT 6983, which would describe the PIN's
         * state rather than the reason this command cannot help.
         *
         * A card issued without a PUK has a terminal PIN. That is a
         * personalisation choice, not a bug, and the status word makes it
         * diagnosable.
         */
        return SW_REFERENCE_DATA_NOT_FOUND;
    }
    if (puk.state == PIN_STATE_BLOCKED) {
        /* The recovery path is exhausted. The card is now genuinely terminal
         * for this reference, which is the intended end of a limited recovery
         * path rather than a failure of one. */
        return SW_AUTH_METHOD_BLOCKED; /* 6983 */
    }

    /*
     * The whole data field is the PUK. Length checked HERE, before
     * pin_verify() -- which spends a try before it looks at the value, so a
     * length check inside it would let a caller exhaust the PUK with junk.
     * Same ordering rule as VERIFY.
     */
    const uint8_t puk_len = (uint8_t)cmd->lc;
    if (puk_len < PIN_MIN_LEN || puk_len > PIN_MAX_LEN) {
        return SW_WRONG_LENGTH;
    }

    /*
     * Verify the PUK. This SPENDS a PUK try before comparing, by design -- so
     * RESET RETRY COUNTER is not a free oracle against the PUK either.
     */
    pin_info         after = { PIN_STATE_UNSET, 0u, 0u };
    const pin_status vst =
        pin_verify(PIN_REF_UNBLOCK, cmd->data, puk_len, &after);
    if (vst != PIN_OK) {
        /* A failed unblock must not leave anything authenticated. */
        scos_clear_authenticated(k, PIN_REF_UNBLOCK);
        switch (vst) {
        case PIN_ERR_WRONG:
            return SW_NVM_CHANGED_PIN_TRIES(after.tries_left);
        case PIN_ERR_BLOCKED:
            return SW_AUTH_METHOD_BLOCKED;
        case PIN_ERR_UNSET:
        case PIN_ERR_NOT_FOUND:
            return SW_REFERENCE_DATA_NOT_FOUND;
        case PIN_ERR_PARAM:
            return SW_WRONG_LENGTH;
        case PIN_ERR_NVM:
        case PIN_ERR_CORRUPT:
        case PIN_ERR_ENTROPY:
        case PIN_OK:
        default:
            return SW_MEMORY_FAILURE;
        }
    }

    /*
     * The PUK was correct. Now unblock the PIN.
     *
     * pin_unblock() restores the counter and the ACTIVE state without touching
     * the salt or the verifier. It has to be a separate primitive from
     * pin_set(): the existing PIN value is unknown to this card -- only its
     * verifier is stored -- so there is nothing to re-derive a verifier from.
     */
    const pin_status sst = pin_unblock(PIN_REF_USER);

    /*
     * The PIN is usable again, and the session is NOT authenticated for it.
     *
     * Presenting the PUK proves entitlement to RESET the PIN; it does not prove
     * knowledge of the PIN. Granting PIN authentication here would make the PUK
     * a master key that opens every PIN-protected file -- which is a different
     * and much larger privilege than the one the cardholder was given it for.
     */
    scos_clear_authenticated(k, PIN_REF_USER);

    if (sst != PIN_OK) {
        return SW_MEMORY_FAILURE; /* 6581 -- the card failed, not the caller */
    }
    return SW_OK;
}
