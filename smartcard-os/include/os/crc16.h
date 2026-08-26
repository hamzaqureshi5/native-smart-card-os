/* SPDX-License-Identifier: MIT
 *
 * crc16.h -- CRC-16/CCITT-FALSE over NVM structures.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS NOT FOR
 *
 * It detects CORRUPTION: a torn write, a bit flip from an exhausted NVM cell,
 * a partially-written descriptor. That is a real and frequent failure mode on
 * a device that can lose power mid-write, and a filesystem that acts on a
 * half-written descriptor will compound the damage.
 *
 * It is NOT authentication and provides NO tamper resistance. An attacker who
 * can write NVM can recompute the CRC. Detecting deliberate modification needs
 * a MAC under a key the attacker cannot reach, which needs both cryptography
 * (M5) and hardware key storage. Recorded in docs/threat-model.md rather than
 * papered over.
 *
 * Computed bitwise rather than from a 512-byte table: ROM on a smart card is
 * scarcer than the cycles, and these structures are 20 bytes.
 */
#ifndef SCOS_CRC16_H
#define SCOS_CRC16_H

#include <stddef.h>
#include <stdint.h>

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final xor.
 * Known-answer: crc16("123456789") == 0x29B1. Checked in test_crc16. */
uint16_t crc16(const void *data, size_t len);

#endif /* SCOS_CRC16_H */
