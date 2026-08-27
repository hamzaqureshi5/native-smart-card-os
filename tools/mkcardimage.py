#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
mkcardimage.py -- build a single SCV1 card image.

A production card is programmed once, with code AND a personalised filesystem
already in place. This tool combines them into one flat image laid out exactly
like the chip's address space, so a programmer (or QEMU's loader) can write it
in a single pass:

    offset 0x00000000   8 KB   BOOTROM <- scv1-boot.bin
    offset 0x00002000  55 KB   OSFLASH <- smartcard-os.bin  (or erased)
    offset 0x0000FC00   1 KB   OSHDR   <- card_oshdr.bin    (or erased)
    offset 0x00010000  16 KB   EEPROM  <- card_eeprom.bin   (or erased)
    offset 0x00014000 256 KB   DFLASH  <- card_flash.bin    (or erased)
                               total 336 KB

Erased regions are filled with 0xFF, which is what real flash and EEPROM read
as when blank -- so an image with only a boot ROM produces a genuinely BLANK
card: it comes up in the loader, answers with the boot ROM's ATR, and waits for
an OS. That is the state a part leaves the factory in.

Note that supplying --os alone is not enough to make a card boot: the boot ROM
will not start an image with no valid ACTIVE slot header. Use
`tools/mkldr.py slot` to produce card_oshdr.bin, or leave OSHDR erased and load
the OS over APDUs.

    # a blank card
    tools/mkcardimage.py --bootrom build-arm/scv1-boot.bin -o blank.bin

    # a fully programmed card
    tools/mkldr.py slot build-arm/smartcard-os.bin -d slot/
    tools/mkcardimage.py --bootrom build-arm/scv1-boot.bin \
                         --os build-arm/smartcard-os.bin \
                         --oshdr slot/card_oshdr.bin \
                         --eeprom mycard/card_eeprom.bin \
                         --dflash mycard/card_flash.bin -o card.bin

Inspect one:
    tools/mkcardimage.py --inspect card.bin
"""

import argparse
import sys

# Must match src/hal/arm-scv1/scv1.h, scv1.ld and scv1_boot.ld.
BOOTROM_BASE, BOOTROM_SIZE = 0x00000000, 8 * 1024
OSFLASH_BASE, OSFLASH_SIZE = 0x00002000, 55 * 1024
OSHDR_BASE, OSHDR_SIZE = 0x0000FC00, 1024
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
    place(image, BOOTROM_BASE, BOOTROM_SIZE, args.bootrom, "BOOTROM")
    if args.os:
        place(image, OSFLASH_BASE, OSFLASH_SIZE, args.os, "OSFLASH")
    else:
        print(f"  {'OSFLASH':<7} 0x{OSFLASH_BASE:08X}  erased (0xFF) -- blank card")
    if args.oshdr:
        place(image, OSHDR_BASE, OSHDR_SIZE, args.oshdr, "OSHDR")
    else:
        print(f"  {'OSHDR':<7} 0x{OSHDR_BASE:08X}  erased (0xFF) -- no bootable slot")
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

    code = image[BOOTROM_BASE:BOOTROM_BASE + BOOTROM_SIZE]
    used = len(code.rstrip(bytes([ERASED])))
    print(f"  BOOTROM {used} bytes used of {BOOTROM_SIZE}")
    hdr = image[OSHDR_BASE:OSHDR_BASE + 16]
    if hdr[0:4] == FS_MAGIC:
        length = int.from_bytes(hdr[6:10], "big")
        state = int.from_bytes(hdr[14:16], "big")
        name = {0x0000: "ACTIVE", 0xFFFF: "LOADED"}.get(state, f"?{state:04X}")
        print(f"  OSHDR   slot {name}, image {length} bytes, "
              f"CRC {int.from_bytes(hdr[10:12], 'big'):04X}")
    else:
        print("  OSHDR   no slot header -- the card will come up in the loader")

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
    ap.add_argument("--bootrom", help="boot ROM image (scv1-boot.bin)")
    ap.add_argument("--os", help="OS image (smartcard-os.bin)")
    ap.add_argument("--oshdr", help="OS slot header (from tools/mkldr.py slot)")
    ap.add_argument("--eeprom", help="EEPROM image (card_eeprom.bin)")
    ap.add_argument("--dflash", help="data-flash image (card_flash.bin)")
    ap.add_argument("-o", "--output", default="card.bin")
    ap.add_argument("--inspect", metavar="IMAGE", help="describe an image")
    args = ap.parse_args()

    if args.inspect:
        return inspect(args.inspect)
    if not args.bootrom:
        ap.error("--bootrom is required (or use --inspect).\n"
                 "A card image without a boot ROM has nothing at the reset "
                 "vector; the core would read whatever is at address 0 as its "
                 "stack pointer and fault immediately.")
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
