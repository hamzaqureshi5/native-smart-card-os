/* SPDX-License-Identifier: MIT
 *
 * cmd_get_response.c -- GET RESPONSE (INS C0), ISO/IEC 7816-4 s.11.7.
 *
 * WHY THIS COMMAND EXISTS AT ALL
 *
 * It is not a feature; it is a workaround for T=0, and understanding that is
 * the difference between implementing it and cargo-culting it.
 *
 * T=0 is half-duplex and byte-oriented, and the reader must state in advance
 * how many bytes it will accept. So a Case 3 command -- header plus data, no
 * Le -- has no channel on which to return anything. If SELECT wants to hand
 * back a file's control information and the reader never asked for it, the
 * bytes simply cannot be sent.
 *
 * ISO's answer is a two-step: the card answers 61XX, meaning "I have XX bytes
 * for you", and the reader comes back with GET RESPONSE and a real Le. T=1 has
 * no such limitation, which is why a T=1-only card can omit this entirely.
 *
 * WHAT WE DO NOT DO
 *
 * We do not use GET RESPONSE for Case 4 command chaining, and we do not
 * synthesise 61XX for commands that were given a usable Le. If the reader
 * asked for data and the data fits, it gets the data. 61XX is reserved for the
 * case where the protocol genuinely cannot deliver -- otherwise every response
 * would cost two round trips for no reason.
 */
#include "apdu/dispatch.h"
#include "apdu/sw.h"
#include "os/kernel.h"
#include "os/os_mem.h"

uint16_t scos_cmd_get_response(scos_kernel *k, const apdu_command *cmd,
                               apdu_response *rsp)
{
    if (k == NULL || cmd == NULL || rsp == NULL) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }

    /* ISO/IEC 7816-4: P1-P2 shall be '0000'. Other values are reserved, so
     * accepting them would spend meanings we may need later. */
    if (cmd->p1 != 0x00u || cmd->p2 != 0x00u) {
        return SW_INCORRECT_P1P2;
    }

    /* GET RESPONSE carries no data field. An Lc here means the reader has
     * confused it with something else. */
    if (cmd->lc != 0u) {
        return SW_WRONG_LENGTH;
    }

    /*
     * Le is REQUIRED. GET RESPONSE is a Case 2 command whose whole purpose is
     * to say how many bytes the reader will now accept; without Le there is
     * nothing to act on. Answering "here is everything" would be a guess about
     * a buffer we cannot see.
     */
    if (!cmd->le_present) {
        return SW_WRONG_LENGTH;
    }

    const uint16_t remaining = scos_pending_remaining(k);
    if (remaining == 0u) {
        /*
         * Nothing pending.
         *
         * 6985 rather than 6D00: the instruction IS supported, so claiming
         * otherwise would tell a reader to stop trying it for good. What is
         * wrong is the sequence -- either no 61XX preceded this, or another
         * command intervened and dropped the data, which is exactly what
         * scos_process() is required to do.
         */
        return SW_CONDITIONS_NOT_SATISFIED;
    }

    /*
     * An EXTENDED Le on GET RESPONSE is refused rather than clamped.
     *
     * GET RESPONSE exists because T=0 cannot return data the reader did not
     * ask for, and the card announces the waiting amount in SW2 of a 61XX --
     * ONE byte, so never more than 256. A reader that can send an extended Le
     * has therefore been told, at most, that 256 bytes are waiting; asking for
     * 65536 of them is not a bigger request, it is a confused one.
     *
     * 6700 and not a clamp, because the exactness rule below is the whole
     * contract of this command: the reader states a length and gets that
     * length or a correction. Silently clamping an extended Le would be the
     * one thing the 6CXX path exists to avoid.
     */
    if (cmd->extended) {
        return SW_WRONG_LENGTH;
    }

    /* Comparison in uint32_t: cmd->le reaches 65536, remaining never exceeds
     * 256, and a uint16_t comparison would have to narrow one of them. */
    if (cmd->le > (uint32_t)remaining) {
        /*
         * The reader asked for more than exists. 6CXX tells it the exact right
         * length so the retry succeeds first time, and -- importantly -- does
         * NOT consume the data. A reader that gets 6C0A and asks again for 10
         * bytes must still find them there.
         *
         * The alternative, returning `remaining` bytes with 9000, is also seen
         * in the wild. It is rejected here because it silently changes the
         * length contract: the reader asked for Le and got fewer, with no
         * indication that it was the card's decision rather than a truncation.
         */
        return SW_WRONG_LE(remaining & 0xFFu);
    }

    /* Past the two checks above, le <= remaining <= SCOS_PENDING_MAX, so the
     * narrowing is provably safe. Stated as a local rather than cast inline so
     * the reason sits next to the conversion. */
    const uint16_t take = (uint16_t)cmd->le;

    /* Hand over exactly Le bytes from where the last collection stopped. */
    if (!apdu_rsp_put(rsp, &k->pending[k->pending_pos], take)) {
        return SW_NO_PRECISE_DIAGNOSIS;
    }
    k->pending_pos = (uint16_t)(k->pending_pos + take);

    const uint16_t left = scos_pending_remaining(k);
    if (left == 0u) {
        /* Fully collected. Zero the buffer rather than leaving the bytes in
         * RAM once they are no longer reachable through any command. */
        scos_pending_clear(k);
        return SW_OK;
    }

    /* More to come. Another 61XX, and the reader may keep going -- the data
     * survives because scos_process() only preserves it across GET RESPONSE. */
    return SW_MORE_DATA(left & 0xFFu);
}
