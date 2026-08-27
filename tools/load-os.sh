#!/bin/sh
# SPDX-License-Identifier: MIT
#
# load-os.sh -- program an OS into an SCV1 card, whatever state the card is in.
#
#   tools/load-os.sh mycard                      load build-arm/smartcard-os.bin
#   tools/load-os.sh mycard path/to/other.bin    load a specific image
#   tools/load-os.sh --recycle mycard            erase the slot, load nothing
#
# This exists because doing it by hand has one sharp edge. An SCV1 whose slot is
# already ACTIVE boots the OS immediately, so a loader script piped at it
# reaches the OS rather than the boot loader, and the OS answers 6E00 to every
# line -- CLA 80 is not its class. The card is fine; the script just went to the
# wrong program. This script always holds BOOTSEL, so the boot loader is
# guaranteed to be the thing listening.
#
# It also checks the answers instead of printing them. A loader transcript is
# 100+ lines of 9000 and nobody reads it, which is exactly how a failure in the
# middle goes unnoticed.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
QEMU=${SCOS_QEMU:-qemu-system-arm}
BOOTROM=${SCOS_BOOTROM:-$ROOT/build-arm/scv1-boot.elf}
RECYCLE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --recycle) RECYCLE=1; shift ;;
        -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --) shift; break ;;
        -*) echo "load-os.sh: unknown option '$1'" >&2; exit 2 ;;
        *)  break ;;
    esac
done

if [ $# -lt 1 ]; then
    echo "usage: tools/load-os.sh [--recycle] <state-dir> [image.bin]" >&2
    exit 2
fi

STATE_DIR=$1
IMAGE=${2:-$ROOT/build-arm/smartcard-os.bin}

if [ ! -f "$BOOTROM" ]; then
    cat >&2 <<MSG
load-os.sh: boot ROM not found: $BOOTROM

Build it with:
  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
  cmake --build build-arm -j
MSG
    exit 1
fi

mkdir -p "$STATE_DIR"
SCRIPT=$(mktemp)
OUT=$(mktemp)
trap 'rm -f "$SCRIPT" "$OUT" "$STATE_DIR/card_bootsel.bin"' EXIT INT TERM

if [ "$RECYCLE" -eq 1 ]; then
    "$ROOT/tools/mkldr.py" recycle -o "$SCRIPT" >/dev/null
    WHAT="recycle"
else
    if [ ! -f "$IMAGE" ]; then
        echo "load-os.sh: image not found: $IMAGE" >&2
        exit 1
    fi
    # --no-restart: this script's job is to program the card, not to run it.
    # Leaving the OS unstarted means the final GET STATUS below is answered by
    # the boot loader, which is the thing whose opinion we want.
    "$ROOT/tools/mkldr.py" os "$IMAGE" -o "$SCRIPT" --no-restart >/dev/null
    WHAT="load $(basename "$IMAGE")"
fi

# BOOTSEL held for the whole run: the boot loader must be what answers, even on
# a card that already has an active OS.
: > "$STATE_DIR/card_bootsel.bin"

{ cat "$SCRIPT"; echo .quit; } | (
    cd "$STATE_DIR" && "$QEMU" \
        -M mps2-an385 -cpu cortex-m3 \
        -display none -monitor none -serial stdio \
        -semihosting-config enable=on,target=native \
        -kernel "$BOOTROM"
) > "$OUT" 2>&1 || true

rm -f "$STATE_DIR/card_bootsel.bin"

# --- check the answers ------------------------------------------------------

# Response lines are hex; banner lines are not. A status word is the last two
# bytes of each response line.
BAD=$(grep -E '^[0-9A-F]+$' "$OUT" | grep -vE '(9000|424F4F54|53434F53)$' || true)
SENT=$(grep -cE '^[0-9A-F]+$' "$OUT" || true)

if [ -n "$BAD" ]; then
    echo "load-os.sh: FAILED -- the card refused something." >&2
    echo >&2
    echo "$BAD" | head -5 | sed 's/^/  /' >&2
    echo >&2
    case "$BAD" in
        *6E00*)
            cat >&2 <<'MSG'
  6E00 is "CLA not supported". Loader commands use CLA 80, which belongs to
  the boot ROM -- so these reached the OS instead. That should not be possible
  with BOOTSEL held; check that semihosting is working (the boot ROM cannot see
  the strap file without it).
MSG
            ;;
        *6985*)
            echo "  6985 means a LOAD arrived before ERASE, or a block was" >&2
            echo "  written twice with different data. Flash cannot set a bit" >&2
            echo "  back to 1, so the loader refused rather than corrupt it." >&2
            ;;
        *6A80*)
            echo "  6A80 from VERIFY means the length or CRC did not match what" >&2
            echo "  the card actually stored. The image and the script disagree." >&2
            ;;
        *6984*)
            echo "  6984 from VERIFY means the bytes arrived intact but do not" >&2
            echo "  look like an ARMv7-M image for this chip. Was it linked for" >&2
            echo "  0x00002000?" >&2
            ;;
    esac
    echo >&2
    echo "  full transcript:" >&2
    sed 's/^/    /' "$OUT" >&2
    exit 1
fi

STATUS=$(grep -E '^01[0-9A-F]{30}9000$' "$OUT" | tail -1 || true)
if [ -z "$STATUS" ]; then
    echo "load-os.sh: the card never returned a status record." >&2
    sed 's/^/  /' "$OUT" >&2
    exit 1
fi

STATE=$(printf '%s' "$STATUS" | cut -c3-4)
LEN=$((0x$(printf '%s' "$STATUS" | cut -c13-20)))
CRC=$(printf '%s' "$STATUS" | cut -c21-24)

case "$STATE" in
    00) NAME="BLANK (no OS loaded)" ;;
    01) NAME="LOADED (not activated -- will not boot)" ;;
    02) NAME="ACTIVE" ;;
    03) NAME="DAMAGED" ;;
    *)  NAME="unknown ($STATE)" ;;
esac

echo "load-os.sh: $WHAT -- ok, $SENT responses, none refused"
echo "  slot  : $NAME"
if [ "$STATE" = "01" ] || [ "$STATE" = "02" ]; then
    echo "  image : $LEN bytes, CRC $CRC"
fi
echo "  card  : $STATE_DIR"
echo
if [ "$STATE" = "02" ]; then
    echo "Power it up with:"
    echo "  { echo .atr; echo .quit; } | tools/run-scv1.sh --state-dir $STATE_DIR --boot"
else
    echo "Nothing bootable in the slot; the card will come up in the loader."
fi
