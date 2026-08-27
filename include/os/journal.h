/* SPDX-License-Identifier: MIT
 *
 * journal.h -- the transaction journal.
 *
 * This is the milestone that separates a card OS from an embedded database,
 * and the reason is that a card has no shutdown. It is a chip in someone's
 * pocket that a reader energises for a few hundred milliseconds at a time, and
 * the field can drop at any instant -- mid-command, mid-write, mid-page. There
 * is no "please wait, saving".
 *
 * So every multi-write operation needs to be all-or-nothing across power loss.
 * Creating a file writes a descriptor AND allocates data space AND updates the
 * superblock; if power goes after the first, the card comes back with a file
 * that points at bytes belonging to nobody, and every later allocation is
 * wrong.
 *
 * UNDO, NOT REDO, AND WHY
 *
 * Two standard designs:
 *
 *   redo (write-ahead)  Log the NEW bytes, then apply them. On recovery,
 *                       re-apply anything the log says was committed.
 *   undo (backup)       Log the OLD bytes, then write in place. On recovery,
 *                       restore anything the log says was not committed.
 *
 * This journal is UNDO, for two reasons that matter on this hardware:
 *
 *   1. Commit becomes a single byte. With undo, the data is already in place
 *      by the time the transaction ends, so committing is just marking the
 *      journal closed -- one byte, in byte-writable EEPROM, atomic. With redo,
 *      commit is followed by a second pass that copies the logged data into
 *      place, and that pass can itself be interrupted, so recovery has to be
 *      idempotent AND has to run before the card is usable.
 *   2. The failure path is the rare one. Undo costs an extra write of the old
 *      bytes on every transaction and nothing on recovery unless it is needed.
 *      Redo costs two writes of the new bytes always. On flash with limited
 *      endurance, doing the cheap thing in the common case is the right way
 *      round.
 *
 * The cost of undo is that a transaction must know the old bytes, so it reads
 * before writing. On this card that read is from EEPROM and costs nothing
 * worth counting.
 *
 * HOW A CALLER USES IT -- OR RATHER, DOES NOT
 *
 * Callers do NOT log anything by hand. They wrap their work in
 * scos_txn_begin()/scos_txn_commit() and use scos_nvm_write() instead of
 * hal_nvm_write(). The journaling happens inside that call.
 *
 * That is deliberate. An explicit "now log this" API is one a caller can
 * forget, and a forgotten log is invisible until a power cut in the field. The
 * transparent version cannot be forgotten by anyone who uses the write
 * function everything else uses -- and fs_store.c, which is the only place
 * that writes filesystem NVM, uses it.
 */
#ifndef SCOS_JOURNAL_H
#define SCOS_JOURNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "hal/hal.h"

typedef enum {
    SCOS_TXN_OK            = 0,
    SCOS_TXN_ERR_PARAM     = -1,
    SCOS_TXN_ERR_NESTED    = -2, /* begin while one is already open      */
    SCOS_TXN_ERR_NONE_OPEN = -3, /* commit or abort with nothing open    */
    SCOS_TXN_ERR_FULL      = -4, /* the undo log cannot hold this write  */
    SCOS_TXN_ERR_NVM       = -5, /* the device refused                   */
    SCOS_TXN_ERR_CORRUPT   = -6  /* the journal itself failed its checks */
} scos_txn_status;

/*
 * NO NESTING, and that is a decision rather than a simplification.
 *
 * Nested transactions need either savepoints -- a second mechanism with its
 * own recovery rules -- or reference counting, where an inner commit does
 * nothing and the outer one decides. The second is the cheap version and it
 * has a trap: an inner operation that "committed" has not committed, so a
 * caller that checked the return value and moved on is wrong. On a card, where
 * the consequence is a file that exists in one place and not another, that is
 * not a trap worth having for the sake of tidier call sites.
 *
 * So begin() inside an open transaction is an ERROR the caller must handle.
 * Every command in this OS performs one logical operation, so no command needs
 * nesting; if one ever does, this is the comment to argue with.
 */
scos_txn_status scos_txn_begin(void);
scos_txn_status scos_txn_commit(void);

/* Undo everything this transaction wrote and close it. Used when a command
 * fails part way through -- the same machinery recovery uses, so the rollback
 * path is exercised by ordinary error handling and not only by power cuts. */
scos_txn_status scos_txn_abort(void);

bool scos_txn_open(void);

/*
 * Write through the journal.
 *
 * With a transaction open: the old bytes are saved to the undo log and made
 * durable BEFORE the new bytes are written. That order is the whole guarantee
 * -- the reverse loses the ability to undo exactly when it is needed.
 *
 * With no transaction open: a straight pass-through to hal_nvm_write(). Not
 * every write needs a transaction (the PIN retry counter deliberately does
 * not; see below), and requiring one everywhere would mean a journal entry for
 * every counter decrement.
 */
hal_status scos_nvm_write(hal_nvm_region region, uint32_t offset,
                          const void *src, uint32_t len);

/*
 * Run recovery. Called once at boot, BEFORE anything reads NVM structures.
 *
 * If the journal is open, the transaction that was running when power went did
 * not finish, so its writes are undone. If it is committed or empty, nothing
 * happens. Either way the journal is left empty.
 *
 * Returns SCOS_TXN_OK when the card is consistent afterwards -- including the
 * case where there was nothing to do.
 */
scos_txn_status scos_txn_recover(void);

/* Format an empty journal. Blank chip only; DESTRUCTIVE. */
scos_txn_status scos_txn_format(void);

/* For tests and diagnostics: how many undo bytes a transaction may hold. A
 * write larger than this is REFUSED rather than performed unprotected. */
uint32_t scos_txn_capacity(void);

#endif /* SCOS_JOURNAL_H */
