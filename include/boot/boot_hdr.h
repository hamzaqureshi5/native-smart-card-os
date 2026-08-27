/* SPDX-License-Identifier: MIT
 *
 * boot_hdr.h -- the OS slot header.
 *
 * A blank SCV1 has an erased OSFLASH and an erased OSHDR page. The boot loader
 * has to answer one question on every reset: "is there a trustworthy OS here?"
 * This 16-byte record is the whole basis of that answer.
 *
 * Stored big-endian, by hand, byte at a time -- never as a C struct. The same
 * rule as the filesystem descriptors: a struct's layout is a property of the
 * compiler, and this record must be readable by the host tool, by the loader,
 * and by whatever compiler builds the next revision.
 *
 * Layout, at SCV1_OSHDR_BASE. The rest of the 1 KB page stays 0xFF.
 *
 *   off  size  field
 *   ---  ----  -------------------------------------------------------------
 *     0     4  magic 'S','C','O','S'
 *     4     2  header version, currently 1
 *     6     4  image length in bytes
 *    10     2  CRC-16/CCITT-FALSE over image[0 .. length)
 *    12     2  CRC-16/CCITT-FALSE over header bytes 0 .. 11
 *    14     2  state word -- NOT covered by the header CRC
 *
 * Why the state word is excluded from the CRC: it has to change after the
 * header is written, and code flash cannot rewrite a byte without erasing the
 * whole page. So the two states are chosen to be reachable by clearing bits
 * only, which flash always permits:
 *
 *   0xFFFF  LOADED  image present and CRC-verified, but will NOT be booted
 *   0x0000  ACTIVE  the loader will boot it
 *
 * Leaving it out of the CRC is safe in the direction that matters. Corrupting
 * 0xFFFF into anything other than 0x0000 leaves the card in the loader, which
 * is the fail-safe outcome; reaching ACTIVE by accident needs all sixteen bits
 * to drop, and even then the image CRC is still checked before the jump.
 *
 * What this header is NOT: authentication. CRC-16 detects accidental damage.
 * It stops nothing deliberate -- anyone who can drive the loader can compute a
 * matching CRC. Signed images are a milestone away and are tracked in
 * docs/threat-model.md as T11.
 */
#ifndef BOOT_HDR_H
#define BOOT_HDR_H

#include <stdbool.h>
#include <stdint.h>

#define BOOT_HDR_SIZE      16u
#define BOOT_HDR_MAGIC_0   0x53u /* 'S' */
#define BOOT_HDR_MAGIC_1   0x43u /* 'C' */
#define BOOT_HDR_MAGIC_2   0x4Fu /* 'O' */
#define BOOT_HDR_MAGIC_3   0x53u /* 'S' */
#define BOOT_HDR_VERSION   1u

#define BOOT_STATE_LOADED  0xFFFFu
#define BOOT_STATE_ACTIVE  0x0000u

/* The unit of a LOAD BLOCK command. 128 bytes keeps the whole APDU inside the
 * short-length form with room for the header, and matches the block size used
 * by real loaders. */
#define BOOT_BLOCK_SIZE    128u

typedef struct {
    uint32_t length;      /* image length in bytes                */
    uint16_t image_crc;   /* CRC-16 over the image                */
    uint16_t state;       /* BOOT_STATE_*                         */
    uint16_t version;     /* header version                       */
} boot_hdr;

/* Parse the 16 raw bytes. Returns false on bad magic, bad version, or a header
 * CRC mismatch -- i.e. false means "there is no usable slot description here",
 * which is exactly what a blank page produces. */
bool boot_hdr_parse(const uint8_t raw[BOOT_HDR_SIZE], boot_hdr *out);

/* Serialise everything EXCEPT the state word, which is left 0xFF so that the
 * page can later be moved to ACTIVE by clearing bits. */
void boot_hdr_serialise(const boot_hdr *in, uint8_t raw[BOOT_HDR_SIZE]);

#endif /* BOOT_HDR_H */
