/* SPDX-License-Identifier: MIT
 *
 * crypto_random.c -- entropy, and the ONLY part of the crypto seam that needs
 * the HAL.
 *
 * WHY THIS IS A SEPARATE TRANSLATION UNIT
 *
 * It is the same split as src/kernel/card_loop.c, made for the same reason and
 * discovered the same way -- by the linker.
 *
 * When crypto_random_bytes() shared a file with crypto_sha256(), any test that
 * linked libscos_core and touched a hash pulled in a reference to
 * hal_random_bytes, so the HAL-free unit tests stopped linking. That is not a
 * build inconvenience; it is the layering telling the truth. Hashing is pure
 * computation over buffers and needs no platform at all, while entropy is
 * irreducibly a platform service.
 *
 * Keeping them apart means the pure half stays testable with no hardware, no
 * simulator and no I/O -- which is the property the whole project is arranged
 * around.
 */
#include "crypto/crypto.h"

#include "hal/hal.h"

crypto_status crypto_random_bytes(void *dst, size_t len)
{
    if (dst == NULL) {
        return CRYPTO_ERR_PARAM;
    }
    if (len == 0u) {
        return CRYPTO_OK;
    }
    if (hal_random_bytes(dst, len) != HAL_OK) {
        /*
         * Wipe rather than leave a partial fill. A caller that ignores the
         * return value must not find plausible-looking bytes in its buffer --
         * that is precisely how a weak salt or key gets used, and it would be
         * indistinguishable from success at the point of the bug.
         */
        crypto_wipe(dst, len);
        return CRYPTO_ERR_ENTROPY;
    }
    return CRYPTO_OK;
}
