/* SPDX-License-Identifier: MIT
 *
 * sw.h -- ISO/IEC 7816-4 status words (SW1 SW2).
 *
 * Every value below is defined by ISO/IEC 7816-4. We do not invent status
 * words and we do not reuse a standard one for a non-standard meaning: a
 * reader or test tool written against the standard must be able to interpret
 * our responses correctly.
 *
 * Proprietary conditions, when we eventually need them, belong in the
 * 63 CX / 6F XX ranges that the standard leaves to the card.
 */
#ifndef SCOS_SW_H
#define SCOS_SW_H

#include <stdint.h>

/* --- Normal processing (9x, 61) ------------------------------------------ */
#define SW_OK           0x9000u /* Success                    */
#define SW_MORE_DATA(n) ((uint16_t)(0x6100u | ((n) & 0xFFu))) /* 61 XX      */

/* --- Warning processing (62, 63) ---------------------------------------- */
#define SW_NVM_UNCHANGED_EOF        0x6282u /* End of file reached early  */
#define SW_NVM_CHANGED_PIN_TRIES(n) ((uint16_t)(0x63C0u | ((n) & 0x0Fu)))
/* 63 CX: verify failed,      */
/* X tries remaining          */

/* --- Execution errors (64, 65, 66) -------------------------------------- */
#define SW_NVM_UNCHANGED_ERROR 0x6400u /* State unchanged, no info   */
#define SW_MEMORY_FAILURE      0x6581u /* Memory write failed        */

/* --- Checking errors (67..6F) -------------------------------------------- */
#define SW_WRONG_LENGTH 0x6700u /* Lc/Le inconsistent         */
#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED  0x6881u
#define SW_SECURE_MESSAGING_NOT_SUPPORTED 0x6882u
#define SW_LAST_CMD_EXPECTED          0x6883u /* Chaining expected          */
#define SW_CHAINING_NOT_SUPPORTED     0x6884u
#define SW_CMD_INCOMPATIBLE_FILE      0x6981u /* Wrong file structure       */
#define SW_SECURITY_NOT_SATISFIED     0x6982u /* Not authenticated          */
#define SW_AUTH_METHOD_BLOCKED        0x6983u /* PIN blocked                */
#define SW_REFERENCE_DATA_INVALIDATED 0x6984u
#define SW_CONDITIONS_NOT_SATISFIED   0x6985u
#define SW_COMMAND_NOT_ALLOWED_NO_EF  0x6986u /* No current EF selected     */
#define SW_WRONG_DATA                 0x6A80u /* Bad data field parameter   */
#define SW_FUNC_NOT_SUPPORTED         0x6A81u
#define SW_FILE_NOT_FOUND             0x6A82u
#define SW_RECORD_NOT_FOUND           0x6A83u
#define SW_NOT_ENOUGH_SPACE           0x6A84u
#define SW_INCORRECT_P1P2             0x6A86u
#define SW_LC_INCONSISTENT_P1P2       0x6A87u
#define SW_REFERENCE_DATA_NOT_FOUND   0x6A88u
#define SW_FILE_ALREADY_EXISTS        0x6A89u
#define SW_WRONG_P1P2                 0x6B00u
#define SW_WRONG_LE(n) ((uint16_t)(0x6C00u | ((n) & 0xFFu))) /* 6C XX      */
#define SW_INS_NOT_SUPPORTED    0x6D00u
#define SW_CLA_NOT_SUPPORTED    0x6E00u
#define SW_NO_PRECISE_DIAGNOSIS 0x6F00u /* Internal error             */

static inline uint8_t sw1(uint16_t sw)
{ return (uint8_t)(sw >> 8); }
static inline uint8_t sw2(uint16_t sw)
{ return (uint8_t)(sw & 0xFFu); }

#endif /* SCOS_SW_H */
