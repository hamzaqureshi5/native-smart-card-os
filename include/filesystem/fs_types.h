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
#define FS_NO_SFI        0x00u

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
    uint8_t      ac_read;     /* access conditions: M3 placeholders, stored   */
    uint8_t      ac_update;   /*   now so the layout does not change later    */
    uint8_t      sfi;         /* short EF identifier 1..30, or FS_NO_SFI      */
    uint8_t      flags;
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
