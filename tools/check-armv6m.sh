#!/bin/sh
# SPDX-License-Identifier: MIT
#
# check-armv6m.sh -- compile the OS core for ARMv6-M.
#
# WHY THIS EXISTS
#
# SCV1 is a Cortex-M3 (ARMv7-M) target, but the real parts this OS is aimed at
# are not all ARMv7-M. Samsung's S3M228A -- a SIM in mass production -- uses an
# ARM SecurCore SC000, which is Cortex-M0 class and implements ARMv6-M. See
# docs/hardware-port.md.
#
# ARMv6-M is a strict subset: no IT blocks, almost none of the 32-bit Thumb-2
# encodings, no hardware divide. Code that compiles for Cortex-M3 can fail on
# it, and the failure would only surface when a real port was attempted -- by
# which point the offending code could be anywhere.
#
# So this compiles the portable core for -mcpu=cortex-m0 on every push. It does
# NOT link and does NOT run: there is no ARMv6-M board target, and pretending
# otherwise would be worse than the honest compile-only check. What it proves is
# narrow and real -- that the OS core contains no ARMv7-M-only construct.
#
# NOT covered, deliberately: src/hal/arm-scv1/ is exempt. It is allowed to be
# ARMv7-M specific -- that is what a HAL is for. In particular boot_main.c
# writes SCB->VTOR, which Cortex-M0 does not have; making it portable is a real
# design question recorded in docs/hardware-port.md, not something to paper
# over here.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CROSS_CC:-arm-none-eabi-gcc}
GEN=${SCOS_GENERATED:-$ROOT/build/generated}

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "check-armv6m.sh: $CC not found" >&2
    exit 1
fi

if [ ! -f "$GEN/os/scos_config.h" ]; then
    cat >&2 <<MSG
check-armv6m.sh: generated config not found at $GEN/os/scos_config.h

Configure a native build first (it generates the header):
  cmake -S . -B build
MSG
    exit 1
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT INT TERM

# The PORTABLE core only. No HAL.
FILES=$(cd "$ROOT" && find src/kernel src/apdu src/filesystem src/boot \
        src/crypto src/security -name '*.c' 2>/dev/null | sort)

MBEDTLS="$ROOT/third_party/mbedtls"
MBEDTLS_CFG="$ROOT/config/scos_mbedtls_config.h"

fail=0
for f in $FILES; do
    # src/crypto includes mbedTLS headers; the rest do not, and giving them
    # the path anyway would let a future file reach the library without the
    # seam noticing. So the include path is added per-file.
    EXTRA=""
    case "$f" in
    src/crypto/*)
        EXTRA="-I $MBEDTLS/include -DMBEDTLS_CONFIG_FILE=\"$MBEDTLS_CFG\""
        ;;
    esac
    # shellcheck disable=SC2086
    if ! "$CC" -mcpu=cortex-m0 -mthumb -ffreestanding \
         -std=c11 -pedantic -Wall -Wextra -Werror \
         -I "$ROOT/include" -I "$GEN" $EXTRA \
         -c "$ROOT/$f" -o "$OUT/$(basename "$f").o"; then
        echo "check-armv6m.sh: FAILED $f" >&2
        fail=$((fail + 1))
    fi
done

#
# The vendored library, checked separately and NOT with -Werror.
#
# Its warnings are its authors' business -- patching them would make the
# submodule a fork. What matters here is only that it COMPILES for ARMv6-M,
# because that is the architecture a real SIM part uses (see
# docs/hardware-port.md) and a hash the card cannot build is a hash the card
# does not have.
#
if [ -f "$MBEDTLS/library/sha256.c" ]; then
    for f in "$MBEDTLS/library/sha256.c" "$MBEDTLS/library/platform_util.c"; do
        if ! "$CC" -mcpu=cortex-m0 -mthumb -std=c11 -w \
             -I "$MBEDTLS/include" -I "$MBEDTLS/library" \
             -DMBEDTLS_CONFIG_FILE="\"$MBEDTLS_CFG\"" \
             -c "$f" -o "$OUT/mbedtls_$(basename "$f").o"; then
            echo "check-armv6m.sh: FAILED (vendored) $f" >&2
            fail=$((fail + 1))
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    echo "check-armv6m.sh: $fail file(s) do not build for ARMv6-M" >&2
    exit 1
fi

n=$(ls "$OUT"/*.o 2>/dev/null | wc -l)
text=$("${CC%gcc}size" -t "$OUT"/*.o 2>/dev/null | tail -1 | awk '{print $1}')
echo "check-armv6m.sh: $n files build for ARMv6-M (Cortex-M0), ${text} bytes of text"
