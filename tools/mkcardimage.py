#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
mkcardimage.py -- build a single SCV1 card image.

A production card is programmed once, with code AND a personalised filesystem
already in place. This tool combines them into one flat image laid out exactly
like the chip's address space, so a programmer (or QEMU's loader) can write it
in a single pass:

    offset 0x00000000  64 KB   CODE    <- smartcard-os.bin
    offset 0x00010000  16 KB   EEPROM  <- card_eeprom.bin  (or erased)
    offset 0x00014000 256 KB   DFLASH  <- card_flash.bin   (or erased)
                               total 336 KB

Erased regions are filled with 0xFF, which is what real flash and EEPROM read
as when blank -- so an image built with no filesystem produces a factory-blank
card that personalises itself on first boot.

    tools/mkcardimage.py --code build-arm/smartcard-os.bin -o card.bin
    tools/mkcardimage.py --code build-arm/smartcard-os.bin \
                         --eeprom mycard/card_eeprom.bin \
                         --dflash mycard/card_flash.bin -o card.bin

Inspect one:
    tools/mkcardimage.py --inspect card.bin
"""

import argparse
import sys

# Must match src/hal/arm-scv1/scv1.h and scv1.ld.
CODE_BASE, CODE_SIZE = 0x00000000, 64 * 1024
EEPROM_BASE, EEPROM_SIZE = 0x00010000, 16 * 1024
DFLASH_BASE, DFLASH_SIZE = 0x00014000, 256 * 1024
IMAGE_SIZE = DFLASH_BASE + DFLASH_SIZE          # 0x54000 = 344064

ERASED = 0xFF
FS_MAGIC = b"SCOS"


def place(image: bytearray, base: int, size: int, path: str, what: str) -> None:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) > size:
        raise SystemExit(
            f"mkcardimage: {what} is {len(data)} bytes but the region is "
            f"{size} ({path})"
        )
    image[base:base + len(data)] = data
    pct = (len(data) * 100) // size
    print(
        f"  {what:<7} 0x{base:08X}  {len(data):>7} / {size:>7} bytes ({pct:>2}%)"
        f"  <- {path}"
    )


def build(args) -> int:
    image = bytearray([ERASED]) * IMAGE_SIZE
    print(f"SCV1 card image, {IMAGE_SIZE} bytes ({IMAGE_SIZE // 1024} KB)")
    place(image, CODE_BASE, CODE_SIZE, args.code, "CODE")
    if args.eeprom:
        place(image, EEPROM_BASE, EEPROM_SIZE, args.eeprom, "EEPROM")
    else:
        print(f"  {'EEPROM':<7} 0x{EEPROM_BASE:08X}  erased (0xFF)")
    if args.dflash:
        place(image, DFLASH_BASE, DFLASH_SIZE, args.dflash, "DFLASH")
    else:
        print(f"  {'DFLASH':<7} 0x{DFLASH_BASE:08X}  erased (0xFF)")

    with open(args.output, "wb") as f:
        f.write(image)
    print(f"\nwrote {args.output}")
    return 0


def inspect(path: str) -> int:
    with open(path, "rb") as f:
        image = f.read()
    print(f"{path}: {len(image)} bytes")
    if len(image) != IMAGE_SIZE:
        print(f"  WARNING: expected {IMAGE_SIZE} bytes for an SCV1 image")

    if len(image) >= 8:
        sp = int.from_bytes(image[0:4], "little")
        pc = int.from_bytes(image[4:8], "little")
        print(f"  vector[0] initial SP = 0x{sp:08X}", end="")
        print("  (SRAM top)" if sp == 0x20004000 else "  (unexpected)")
        print(f"  vector[1] reset PC   = 0x{pc:08X}", end="")
        print("  (Thumb)" if pc & 1 else "  (NOT Thumb -- suspicious)")

    code = image[CODE_BASE:CODE_BASE + CODE_SIZE]
    used = len(code.rstrip(bytes([ERASED])))
    print(f"  CODE   {used} bytes used of {CODE_SIZE}")

    if len(image) >= EEPROM_BASE + 16:
        sb = image[EEPROM_BASE:EEPROM_BASE + 16]
        if sb[0:4] == FS_MAGIC:
            version = int.from_bytes(sb[4:6], "big")
            max_files = int.from_bytes(sb[6:8], "big")
            data_top = int.from_bytes(sb[8:12], "big")
            print(f"  EEPROM filesystem present: layout v{version}, "
                  f"{max_files} slots, {data_top} bytes of file data")
        elif all(b == ERASED for b in sb):
            print("  EEPROM erased -- a factory-blank card; it will "
                  "personalise itself on first boot")
        else:
            print("  EEPROM has no filesystem magic and is not erased")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build or inspect an SCV1 card image.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--code", help="OS flash image (smartcard-os.bin)")
    ap.add_argument("--eeprom", help="EEPROM image (card_eeprom.bin)")
    ap.add_argument("--dflash", help="data-flash image (card_flash.bin)")
    ap.add_argument("-o", "--output", default="card.bin")
    ap.add_argument("--inspect", metavar="IMAGE", help="describe an image")
    args = ap.parse_args()

    if args.inspect:
        return inspect(args.inspect)
    if not args.code:
        ap.error("--code is required (or use --inspect)")
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
