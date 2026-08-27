/* SPDX-License-Identifier: MIT
 *
 * fs_types.h -- File types, lifecycle states and the file descriptor.
 *
 * WHAT MF / DF / EF ARE
 * ---------------------
 * ISO/IEC 7816-4 gives a card a tree of files, each identified by a two-byte
 * FILE IDENTIFIER (FID). There are no names and no paths in the POSIX sense,
 * and you cannot list a directory.
 *
 *   MF   Master File.      The root. Exactly one, FID 3F00 by definition.
 *   DF   Dedicated File.   A container -- the nearest thing to a directory.
 *                          An application normally owns one DF.
 *   EF   Elementary File.  A leaf holding actual data.
 *
 *   MF 3F00
 *    +-- EF 2F00                  an EF directly under the MF
 *    +-- DF 7F10                  an application
 *         +-- EF 6F01
 *         +-- EF 6F02
 *
 * The difference from a PC filesystem that matters most: ACCESS CONTROL IS PER
 * FILE AND ENFORCED BY THE CARD. Each file carries conditions -- "reading needs
 * PIN verification", "writing is forbidden forever". There is no privileged
 * mode that bypasses them, because the card itself is the enforcer rather than
 * a program that could be replaced. The ac_read/ac_update fields below are the
 * placeholders those conditions will occupy in M3.
 */
#ifndef SCOS_FS_TYPES_H
#define SCOS_FS_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---------------------------------------------------------------- limits -- */

/* Bounded on purpose. An unbounded table would mean unbounded NVM use and an
 * unbounded search, neither of which a card can afford. */
#define FS_MAX_FILES       32u
#define FS_DESC_SIZE       20u /* serialised size in NVM, NOT sizeof()     */
#define FS_SUPERBLOCK_SIZE 16u
#define FS_MAX_EF_SIZE     32767u /* READ BINARY's offset field is 15 bits   */
#define FS_MAX_DEPTH       8u     /* guards path walking against cycles       */

#define FS_FID_MF        0x3F00u
#define FS_INVALID_INDEX 0xFFFFu
#define FS_NO_PARENT     0xFFFFu

/* ------------------------------------------------- access conditions ------ */
/*
 * ONE BYTE PER OPERATION, and the encoding is OURS.
 *
 * ISO/IEC 7816-4 offers two FCP tags for security attributes: 8C, the
 * "compact format", and 86, "proprietary format". This project uses 86, and
 * that is a deliberate choice rather than laziness.
 *
 * The compact format's access-mode byte assigns specific bits to specific
 * operations, and implementing it means getting those bit positions exactly
 * right. This project does not have the specification text to state them
 * precisely, and the standing rule is not to invent protocol meanings that
 * conflict with ISO 7816 -- a card that answered 9000 to an 8C template while
 * misreading which operation each bit protected would create files whose
 * protection was not the protection that was asked for. That is worse than
 * refusing. So 8C is refused with 6A81 and 86 carries a format defined here.
 *
 * Using 86 is not a workaround: ISO defines 86 as proprietary, so a format of
 * our own is exactly what that tag is for. The same reasoning as the boot
 * loader's command set, which is also ours and also documented as such.
 *
 *   0x00      ALWAYS      no condition
 *   0x1N      PIN N       reference N (1..8) must be verified in this session
 *   0xFF      NEVER       no path through the command interface
 *
 * Anything else is refused at CREATE time rather than stored, so a descriptor
 * in NVM never holds a condition the card cannot evaluate. A stored value it
 * could not interpret would have to be treated as NEVER (the safe reading) and
 * would make the file unreachable for reasons nothing could explain.
 */
#define FS_AC_ALWAYS   0x00u
#define FS_AC_NEVER    0xFFu
#define FS_AC_PIN_BASE 0x10u /* 0x1N = PIN reference N                   */

#define FS_AC_PIN(n) ((uint8_t)(FS_AC_PIN_BASE | ((n) & 0x0Fu)))

/* True if `ac` is a value this card knows how to evaluate. */
static inline bool fs_ac_is_known(uint8_t ac)
{
    if (ac == FS_AC_ALWAYS || ac == FS_AC_NEVER) {
        return true;
    }
    /* 0x11..0x18: PIN references 1..8. Reference 0 is not a reference, and
     * above 8 there is no record to consult. */
    return (ac & 0xF0u) == FS_AC_PIN_BASE && (ac & 0x0Fu) >= 1u &&
           (ac & 0x0Fu) <= 8u;
}

/* ---------------------------------------------------------------- EF.ATR -- */
/*
 * ISO/IEC 7816-4 reserves file identifier 2F01 directly under the MF for card
 * capability information that does not fit in the ATR's historical bytes.
 *
 * Five bytes: the card-capabilities data object, tag 47, with a three-byte
 * value. Sized exactly, not rounded up: an EF.ATR longer than its content
 * reads as trailing 0xFF, which a BER-TLV parser sees as the start of a
 * malformed object rather than as end-of-data.
 */
#define FS_EF_ATR_FID  0x2F01u
#define FS_EF_ATR_SIZE 5u

/*
 * Byte 3 of the card-capabilities data object, ISO/IEC 7816-4.
 *
 * Only the bit this card can honestly claim is defined here. Command chaining
 * is NOT set, because apdu_check_cla() refuses the chaining bit with 6884, and
 * advertising a command the card rejects is worse than advertising nothing.
 */
#define FS_CARD_CAP_EXTENDED_LENGTH 0x40u
#define FS_NO_SFI                   0x00u

/* ------------------------------------------------------------ file types -- */
/*
 * INTERNAL type codes. These are NOT the ISO "file descriptor byte" -- that is
 * a bit-packed field we construct only when building an FCP template for a
 * SELECT response (see fs_iso_descriptor_byte). Keeping them separate means the
 * on-NVM format is ours to version, while the wire format stays exactly what
 * ISO specifies.
 *
 * 0xFF is FREE because erased NVM reads as 0xFF: a factory-blank chip is a
 * coherent empty table with no formatting pass required.
 */
typedef enum {
    FS_TYPE_MF             = 0x01,
    FS_TYPE_DF             = 0x02,
    FS_TYPE_EF_TRANSPARENT = 0x03,
    FS_TYPE_FREE           = 0xFF
} fs_file_type;

/* ------------------------------------------------------- lifecycle states -- */
/*
 * Values taken from the ISO/IEC 7816-4 life cycle status byte so the number we
 * store is the number we transmit in an FCP template. Inventing our own would
 * mean a translation table and a chance to get it wrong.
 */
typedef enum {
    FS_LC_CREATION    = 0x01, /* being created; not yet usable              */
    FS_LC_INITIALISED = 0x03, /* structure exists, being personalised       */
    FS_LC_ACTIVATED   = 0x05, /* operational: normal use                    */
    FS_LC_DEACTIVATED = 0x04, /* operational but blocked; reversible        */
    FS_LC_TERMINATED  = 0x0C  /* dead. IRREVERSIBLE by design.              */
} fs_lifecycle;

/* ---------------------------------------------------------- the descriptor -- */
/*
 * IMPORTANT: this struct is never written to NVM.
 *
 * Struct layout is compiler- and target-dependent -- padding and endianness
 * differ between this x86 build and any card MCU. A card whose filesystem
 * becomes unreadable after a toolchain change is a brick. So fs_store.c
 * serialises every field explicitly, byte by byte, big-endian, into the
 * FS_DESC_SIZE layout documented there.
 */
typedef struct {
    uint16_t     file_id;
    fs_file_type type;
    fs_lifecycle lifecycle;
    uint16_t     parent;      /* descriptor index, or FS_NO_PARENT for the MF */
    uint16_t     size;        /* EF data size in bytes; 0 for MF/DF          */
    uint32_t     data_offset; /* FLASH offset of the EF's data               */
    /*
     * Access conditions, one byte per operation. FS_AC_* above.
     *
     *   ac_read    READ BINARY
     *   ac_update  UPDATE BINARY
     *   ac_admin   the administrative operations ON this file: DELETE FILE,
     *              ACTIVATE / DEACTIVATE FILE, and -- for a DF -- CREATE FILE
     *              inside it. One byte rather than three because a caller
     *              entitled to delete a file is entitled to disable it, and
     *              splitting them would invite a card configured to allow the
     *              destructive operation and refuse the reversible one.
     */
    uint8_t ac_read;
    uint8_t ac_update;
    uint8_t ac_admin;
    uint8_t sfi; /* short EF identifier 1..30, or FS_NO_SFI      */
    uint8_t flags;
} fs_descriptor;

static inline bool fs_is_df(const fs_descriptor *d)
{ return d != NULL && (d->type == FS_TYPE_DF || d->type == FS_TYPE_MF); }

static inline bool fs_is_ef(const fs_descriptor *d)
{ return d != NULL && d->type == FS_TYPE_EF_TRANSPARENT; }

/* A file must be ACTIVATED to be used. Anything else is refused, which is what
 * makes deactivation a usable administrative control rather than advisory. */
static inline bool fs_is_usable(const fs_descriptor *d)
{ return d != NULL && d->lifecycle == FS_LC_ACTIVATED; }

/* ---------------------------------------------------------------- status --- */

typedef enum {
    FS_OK                = 0,
    FS_ERR_PARAM         = -1,
    FS_ERR_NOT_FOUND     = -2,
    FS_ERR_CORRUPT       = -3, /* CRC or structural check failed              */
    FS_ERR_NO_SPACE      = -4,
    FS_ERR_EXISTS        = -5,
    FS_ERR_NOT_USABLE    = -6, /* wrong lifecycle state                      */
    FS_ERR_WRONG_TYPE    = -7, /* e.g. READ BINARY on a DF                   */
    FS_ERR_RANGE         = -8, /* offset/length outside the file             */
    FS_ERR_NVM           = -9, /* the HAL refused                            */
    FS_ERR_NOT_FORMATTED = -10,
    FS_ERR_VERSION       = -11 /* on-NVM layout version we do not understand */
} fs_status;

#endif /* SCOS_FS_TYPES_H */
