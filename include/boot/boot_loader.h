/* SPDX-License-Identifier: MIT
 *
 * boot_loader.h -- the SCV1 boot loader's command set and boot decision.
 *
 * PURE LOGIC. Nothing in here touches a peripheral, a file, or a real address:
 * it operates on two byte regions handed in by the caller. On the chip those
 * pointers are OSFLASH and OSHDR; in the unit tests they are arrays. That is
 * what makes the loader testable under AddressSanitizer, which matters more
 * here than anywhere else in the project -- this code sits in mask ROM and
 * CANNOT BE PATCHED after the part is made.
 *
 * ----------------------------------------------------------------------------
 * THIS PROTOCOL IS OURS. It is not any vendor's loader protocol.
 *
 * The user's real card is driven by files named recycle.ldr and os.ldr through
 * a proprietary command set (INS 50 / 2E / 32 / 54). We are deliberately NOT
 * reimplementing that from a captured trace: doing so would mean guessing
 * undocumented behaviour, which is the one thing this project has agreed not
 * to do. What we copy is the SHAPE -- an erase script and an image script, one
 * APDU per line -- not the semantics.
 *
 * Commands, CLA 0x80 (a proprietary class, permitted by ISO/IEC 7816-4):
 *
 *   80 F2 00 00 00           GET STATUS   -> 16-byte record, below
 *   80 0E 00 00 00           ERASE        erase OSFLASH and OSHDR to 0xFF
 *   80 54 P1 P2 Lc <data>    LOAD BLOCK   P1P2 = block index, Lc <= 128
 *                                         offset = block index * 128
 *   80 A0 00 00 06 <len:4> <crc:2>
 *                            VERIFY       check the image, then write the
 *                                         header. Does NOT activate.
 *   80 44 00 00 00           ACTIVATE     mark the slot bootable
 *   80 F0 00 00 00           RESTART      re-run the boot decision now
 *
 * GET STATUS response:
 *   off size field
 *     0    1  loader protocol version (1)
 *     1    1  slot state: 0 blank, 1 loaded, 2 active, 3 header/image damaged
 *     2    4  OSFLASH capacity in bytes
 *     6    4  image length from the header, or 0
 *    10    2  image CRC from the header, or 0
 *    12    1  LOAD BLOCK block size (128)
 *    13    1  1 if ERASE has been issued since reset, else 0
 *    14    2  highest byte offset written since ERASE
 *
 * ----------------------------------------------------------------------------
 * A NOTE ON WHAT THIS DOES NOT DO
 *
 * There is no authentication. Any reader that can talk to a blank SCV1 can
 * load any image and activate it. On a real product that is unacceptable and
 * the loader would require a signed image and a one-way lock bit that disables
 * loading forever at issuance. Both are tracked in docs/threat-model.md and
 * neither is implemented, because signing needs the crypto abstraction (M5)
 * and a lock bit needs a real chip. Do not read this loader as a security
 * boundary; it is a programming interface.
 */
#ifndef BOOT_LOADER_H
#define BOOT_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "boot/boot_hdr.h"

/* CLA/INS values. */
#define BOOT_CLA            0x80u
#define BOOT_INS_GET_STATUS 0xF2u
#define BOOT_INS_ERASE      0x0Eu
#define BOOT_INS_LOAD       0x54u
#define BOOT_INS_VERIFY     0xA0u
#define BOOT_INS_ACTIVATE   0x44u
#define BOOT_INS_RESTART    0xF0u

#define BOOT_STATUS_RSP_LEN 16u

typedef enum {
    BOOT_SLOT_BLANK = 0,  /* no header: a fresh or freshly erased part      */
    BOOT_SLOT_LOADED,     /* header valid, image CRC good, not activated    */
    BOOT_SLOT_ACTIVE,     /* header valid, image CRC good, activated        */
    BOOT_SLOT_DAMAGED     /* header present but self-inconsistent           */
} boot_slot_state;

typedef enum {
    BOOT_ACT_NONE = 0,
    BOOT_ACT_RESTART      /* caller should re-run the boot decision         */
} boot_action;

typedef struct {
    uint8_t *osflash;
    uint32_t osflash_size;
    uint8_t *oshdr;
    uint32_t oshdr_size;
    uint32_t page_size;
    /* Chip geometry, supplied by the caller so this module never hardcodes an
     * address. Used only by the plausibility check -- see boot_image_plausible.
     * The unit tests pass the same SCV1 values, so the test and the chip agree
     * on what a well-formed image looks like. */
    uint32_t load_addr;   /* address OSFLASH is mapped at                   */
    uint32_t sram_base;
    uint32_t sram_size;
    uint32_t high_water;  /* highest offset+length written since ERASE      */
    bool     erased;      /* ERASE issued since reset                       */
} boot_ctx;

void boot_ctx_init(boot_ctx *ctx,
                   uint8_t *osflash, uint32_t osflash_size,
                   uint8_t *oshdr,   uint32_t oshdr_size,
                   uint32_t page_size,
                   uint32_t load_addr,
                   uint32_t sram_base, uint32_t sram_size);

/*
 * Handle one command APDU. Returns the status word; never returns 0x0000.
 *
 * cmd/len are the raw bytes off the link. rsp receives the response data only
 * -- the caller appends SW1 SW2, exactly as the OS's dispatcher does, so the
 * transport layer stays the single place that knows the framing.
 */
uint16_t boot_handle(boot_ctx *ctx,
                     const uint8_t *cmd, uint32_t len,
                     uint8_t *rsp, uint32_t rsp_cap, uint32_t *rsp_len,
                     boot_action *action);

/* Read the slot header and, when it claims an image, re-check the image CRC.
 * out may be NULL. This is the function the reset path calls. */
boot_slot_state boot_slot_check(const uint8_t *oshdr, uint32_t oshdr_size,
                                const uint8_t *osflash, uint32_t osflash_size,
                                boot_hdr *out);

/*
 * Does this image look like something an ARMv7-M core can be handed?
 *
 * A correct CRC only proves the bytes arrived intact; it says nothing about
 * whether they are an OS. Jumping into a valid-CRC image of garbage produces a
 * HardFault loop that looks like dead silicon. So before the jump we check the
 * two words the architecture defines:
 *
 *   word 0  initial stack pointer -- must land inside SRAM
 *   word 1  reset vector          -- must land inside the image, with bit 0
 *                                    set, because ARMv7-M has only Thumb state
 *
 * Both words are little-endian in the image. Read byte-wise so this function
 * gives the same answer on the host as on the chip.
 */
bool boot_image_plausible(const uint8_t *img, uint32_t len,
                          uint32_t load_addr,
                          uint32_t sram_base, uint32_t sram_size);

#endif /* BOOT_LOADER_H */
