/* SPDX-License-Identifier: MIT
 *
 * ac.c -- the access-condition check.
 *
 * Small on purpose. This is the function that decides whether a command may
 * touch a file, so its whole body should be readable in one go and its default
 * should be visible without following a branch.
 */
#include "security/ac.h"

#include "security/pin.h"

static uint8_t condition_for(const fs_descriptor *d, ac_operation op)
{
    switch (op) {
    case AC_OP_READ:
        return d->ac_read;
    case AC_OP_UPDATE:
        return d->ac_update;
    case AC_OP_ADMIN:
        return d->ac_admin;
    default:
        /* An operation this function does not know about is not an operation it
         * can authorise. NEVER, so a new ac_operation added without a case
         * here fails closed rather than open. */
        return FS_AC_NEVER;
    }
}

bool scos_ac_permits(uint8_t auth, const fs_descriptor *d, ac_operation op)
{
    if (d == NULL) {
        return false;
    }

    const uint8_t ac = condition_for(d, op);

    if (ac == FS_AC_NEVER) {
        return false;
    }
    if (ac == FS_AC_ALWAYS) {
        return true;
    }
    if (!fs_ac_is_known(ac)) {
        /*
         * A byte the card cannot evaluate. Treated as NEVER, because the only
         * alternative is granting access on the strength of a value nobody
         * understands. CREATE FILE refuses unknown conditions before they
         * reach NVM, so this should be unreachable -- and "should be
         * unreachable" is not a security property, so it is handled.
         */
        return false;
    }

    /* 0x1N: PIN reference N must have been verified in THIS session. The
     * session state is volatile and scos_reset() clears it, which is what makes
     * this a session check rather than a card-lifetime one. */
    const uint8_t ref = (uint8_t)(ac & 0x0Fu);
    if (ref < 1u || ref > 8u) {
        return false;
    }
    return (auth & (uint8_t)(1u << (ref - 1u))) != 0u;
}
