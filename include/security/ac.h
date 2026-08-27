/* SPDX-License-Identifier: MIT
 *
 * ac.h -- evaluating a file's access conditions.
 *
 * One function, called from every command that touches a file. Deliberately
 * one place: an access check duplicated per handler is an access check that
 * will eventually differ per handler, and the one that differs is the one an
 * attacker uses.
 *
 * WHAT IS AND IS NOT CHECKED HERE
 *
 * This answers "is the current session entitled to do X to this file?" and
 * nothing else. It does not consider the file's life cycle -- a deactivated
 * file is refused by fs_ef_read/fs_ef_write regardless of who is asking --
 * because mixing "you may not" with "it is switched off" into one answer would
 * make both indistinguishable to an administrator.
 */
#ifndef SCOS_AC_H
#define SCOS_AC_H

#include <stdbool.h>
#include <stdint.h>

#include "filesystem/fs_types.h"

typedef enum {
    AC_OP_READ = 0, /* READ BINARY                                     */
    AC_OP_UPDATE,   /* UPDATE BINARY                                   */
    AC_OP_ADMIN     /* DELETE / ACTIVATE / DEACTIVATE; CREATE in a DF  */
} ac_operation;

/*
 * True if the session may perform `op` on `d`.
 *
 * An unknown condition byte returns FALSE. That is the only safe default: a
 * value the card cannot evaluate has to be treated as NEVER, because the
 * alternative is granting access on the strength of a byte nobody understands.
 * CREATE FILE refuses unknown conditions up front so this case should be
 * unreachable, and it is implemented anyway because "should be unreachable" is
 * not a security property.
 */
/*
 * `auth` is the session's authentication bitmask -- scos_kernel::auth, bit
 * (ref-1) per verified PIN reference.
 *
 * Passed as a plain byte rather than as the kernel, deliberately. The check
 * needs exactly one thing from the session, and taking the whole kernel would
 * let a future version of this function reach for the selection, the lifecycle
 * or the pending buffer -- and an access check whose answer depends on the
 * pending response buffer is a bug waiting for an author. It also makes the
 * function trivially testable: no card, no NVM, no HAL.
 */
bool scos_ac_permits(uint8_t auth, const fs_descriptor *d, ac_operation op);

#endif /* SCOS_AC_H */
