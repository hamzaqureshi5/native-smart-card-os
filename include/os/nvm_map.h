/* SPDX-License-Identifier: MIT
 *
 * nvm_map.h -- who owns which bytes of EEPROM.
 *
 * Until M3 there was one owner, so fs_store.c could define its offsets
 * privately and be right. A second owner makes that arrangement a collision
 * waiting to happen: two subsystems each certain they own offset 0, and the
 * symptom would be a filesystem that corrupts when a PIN is changed.
 *
 * So the map lives in one place, and the regions are checked against each
 * other and against the configured EEPROM size at COMPILE time. A card whose
 * layout overlaps must not build.
 *
 *   EEPROM (byte-writable, high endurance -- metadata and counters)
 *
 *     0x0000  filesystem superblock            16 bytes
 *     0x0010  descriptor table                 FS_MAX_FILES * FS_DESC_SIZE
 *     ...     (gap, reserved for filesystem growth)
 *     0x0400  security store                   SEC_STORE_SIZE
 *     ...     (gap)
 *
 * The gap after the descriptor table is deliberate. FS_MAX_FILES is a
 * configuration knob, and if the security store began immediately after the
 * table then raising the file limit would silently move the PIN records --
 * turning a configuration change into a card that no longer recognises its own
 * PIN. The gap means the two grow independently, and the _Static_assert below
 * catches the day one outgrows it.
 */
#ifndef SCOS_NVM_MAP_H
#define SCOS_NVM_MAP_H

#include "filesystem/fs_types.h"
#include "os/scos_config.h"

/* --- filesystem: offsets fs_store.c has always used --------------------- */

#define SCOS_EE_FS_BASE 0u
#define SCOS_EE_FS_SIZE (FS_SUPERBLOCK_SIZE + (FS_MAX_FILES * FS_DESC_SIZE))

/* --- security store ------------------------------------------------------ */

/*
 * PIN records. Sized for SEC_MAX_PIN_REFS records of SEC_PIN_RECORD_SIZE.
 *
 * In EEPROM and not FLASH, and that is the single most important placement
 * decision in M3. The retry counter must be decremented durably BEFORE a PIN
 * is compared, so an attacker cannot cut power after a failed attempt to get
 * the try back. Decrementing means a write, and on page-erase FLASH the
 * smallest write is a page -- which would put the salt and verifier at risk on
 * every failed attempt, and take milliseconds. EEPROM is byte-writable, so
 * consuming a try is one byte.
 */
#define SCOS_EE_SEC_BASE 0x0400u
#define SCOS_EE_SEC_SIZE 256u

/* --- transaction journal (M4) -------------------------------------------- */
/*
 * The undo log. In EEPROM, next to the structures it protects, and for the
 * same reason the PIN counter is: byte-writable, so the journal's state can be
 * changed one byte at a time and a commit is atomic.
 *
 * SIZE IS A REAL LIMIT, NOT A GENEROUS GUESS. A transaction whose undo data
 * does not fit is REFUSED -- the write does not happen -- because performing it
 * unprotected would be the one outcome worse than failing: the caller would get
 * 9000 for an operation a power cut can now corrupt.
 *
 * 2 KB holds the largest single write the filesystem performs (a 1 KB extended
 * UPDATE BINARY) plus the descriptor and superblock updates around it, with
 * room to spare. It is not sized for "any conceivable transaction", which is
 * not a thing that can be sized for.
 */
#define SCOS_EE_TXN_BASE 0x0800u
#define SCOS_EE_TXN_SIZE 2048u

/* --- the checks that make this a map rather than a comment -------------- */

_Static_assert(SCOS_EE_FS_BASE + SCOS_EE_FS_SIZE <= SCOS_EE_SEC_BASE,
               "the filesystem descriptor table now overlaps the security "
               "store; raise SCOS_EE_SEC_BASE (and accept that existing cards "
               "will not find their PINs) or lower FS_MAX_FILES");

_Static_assert(SCOS_EE_SEC_BASE + SCOS_EE_SEC_SIZE <= SCOS_EE_TXN_BASE,
               "the security store now overlaps the transaction journal");

_Static_assert(SCOS_EE_TXN_BASE + SCOS_EE_TXN_SIZE <= (SCOS_EEPROM_KB * 1024u),
               "the transaction journal runs off the end of EEPROM");

#endif /* SCOS_NVM_MAP_H */
