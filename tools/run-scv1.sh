#!/bin/sh
# SPDX-License-Identifier: MIT
#
# run-scv1.sh -- run the SCV1 firmware on QEMU's ARM Cortex-M3.
#
#   tools/run-scv1.sh                      interactive, volatile NVM
#   tools/run-scv1.sh --state-dir mycard   persistent NVM in ./mycard
#   echo 00A40000023F00 | tools/run-scv1.sh --quiet
#
# Why these QEMU flags and not -nographic:
#   -nographic multiplexes the serial port with the QEMU monitor, and the
#   monitor swallows stdin. -display none -monitor none -serial stdio gives the
#   card an exclusive UART, which is what the transport needs.
#
#   -semihosting-config is used for ONE thing: letting the firmware read and
#   write its NVM images as host files. It is not part of the card.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FIRMWARE=${SCOS_FIRMWARE:-$ROOT/build-arm/smartcard-os.elf}
QEMU=${SCOS_QEMU:-qemu-system-arm}
STATE_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        --firmware)  FIRMWARE="$2";  shift 2 ;;
        --quiet)     shift ;;   # accepted for symmetry with smartcard-sim
        -h|--help)
            sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "run-scv1.sh: unknown option '$1'" >&2; exit 2 ;;
    esac
done

if [ ! -f "$FIRMWARE" ]; then
    cat >&2 <<MSG
run-scv1.sh: firmware not found: $FIRMWARE

Build it with:
  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
  cmake --build build-arm -j
MSG
    exit 1
fi

if [ -n "$STATE_DIR" ]; then
    mkdir -p "$STATE_DIR"
    cd "$STATE_DIR"
fi

exec "$QEMU" \
    -M mps2-an385 \
    -cpu cortex-m3 \
    -display none \
    -monitor none \
    -serial stdio \
    -semihosting-config enable=on,target=native \
    -kernel "$FIRMWARE"
