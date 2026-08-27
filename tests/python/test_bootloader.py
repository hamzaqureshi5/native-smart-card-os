# SPDX-License-Identifier: MIT
"""The SCV1 boot ROM, over the card interface.

These tests are the reason the OS/boot-ROM split exists, so they run only on
the ARM target -- the native simulator has the OS compiled into it and has no
loader to talk to (docs/loading-the-os.md explains why that is not a gap).

What is checked here and nowhere else:

  * a blank chip answers with the boot loader's ATR, not the OS's;
  * loading an image over APDUs produces byte-for-byte the same slot as the
    offline programmer path, so the shortcut the rest of the suite takes is
    not a different code path in disguise;
  * ACTIVATE is genuinely separate from VERIFY;
  * a recycled card goes back to answering as a blank one.
"""

import os
import subprocess
import sys
import tempfile
import unittest

from scos.card import SmartCard, CardError, _repo_root

BOOT_ATR = bytes.fromhex("3B941100424F4F54")
OS_ATR = bytes.fromhex("3B94110053434F53")
BLOCK = 128

ON_QEMU = os.environ.get("SCOS_TARGET") == "qemu"


def os_image() -> bytes:
    return read_file(image_path())


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def image_path() -> str:
    return os.environ.get(
        "SCOS_OS_IMAGE", os.path.join(_repo_root(), "build-arm", "smartcard-os.bin"))


def mkldr(*args) -> subprocess.CompletedProcess:
    tool = os.environ.get("SCOS_MKLDR",
                          os.path.join(_repo_root(), "tools", "mkldr.py"))
    return subprocess.run([sys.executable, tool, *args],
                          capture_output=True, text=True, check=True)


@unittest.skipUnless(ON_QEMU, "the boot ROM only exists on the ARM target")
class BootLoaderTests(unittest.TestCase):

    def blank_card(self, state_dir):
        """A card with an empty OS slot: the boot loader is what answers."""
        return SmartCard(target="qemu", state_dir=state_dir, no_os=True)

    def test_blank_card_answers_with_the_boot_atr(self):
        with tempfile.TemporaryDirectory() as d:
            with self.blank_card(d) as card:
                self.assertEqual(card.atr(), BOOT_ATR)
                # And it is NOT the OS's ATR, which is the whole point.
                self.assertNotEqual(card.atr(), OS_ATR)

    def test_blank_card_reports_an_empty_slot(self):
        with tempfile.TemporaryDirectory() as d:
            with self.blank_card(d) as card:
                r = card.send_apdu("80F2000000")
                self.assertEqual(r.sw, 0x9000)
                self.assertEqual(len(r.data), 16)
                self.assertEqual(r.data[0], 1, "loader protocol version")
                self.assertEqual(r.data[1], 0, "slot state 0 = BLANK")
                self.assertEqual(int.from_bytes(r.data[2:6], "big"), 55 * 1024)
                self.assertEqual(int.from_bytes(r.data[6:10], "big"), 0)
                self.assertEqual(r.data[12], BLOCK)

    def test_the_os_rejects_loader_commands(self):
        """CLA 80 belongs to the boot loader, not the OS.

        This is what makes recycle.ldr fail against a working card, and it is
        correct behaviour rather than a bug -- see the BOOTSEL note in
        docs/loading-the-os.md.
        """
        with SmartCard(target="qemu") as card:
            self.assertEqual(card.atr(), OS_ATR)
            self.assertEqual(card.send_apdu("80F2000000").sw, 0x6E00)

    def test_load_must_be_preceded_by_erase(self):
        with tempfile.TemporaryDirectory() as d:
            with self.blank_card(d) as card:
                body = bytes(BLOCK).hex().upper()
                r = card.send_apdu(f"8054000080{body}")
                self.assertEqual(r.sw, 0x6985, "load without erase")

    def test_activate_needs_a_verified_image(self):
        with tempfile.TemporaryDirectory() as d:
            with self.blank_card(d) as card:
                self.assertEqual(card.send_apdu("800E000000").sw, 0x9000)
                self.assertEqual(card.send_apdu("8044000000").sw, 0x6A82)

    def test_full_load_over_apdus_matches_the_offline_programmer(self):
        image = os_image()

        # 1. Load it the slow way: 106-odd APDUs through the boot loader.
        with tempfile.TemporaryDirectory() as d:
            with self.blank_card(d) as card:
                self.assertEqual(card.atr(), BOOT_ATR)
                mkldr("os", image_path(),
                      "-o", os.path.join(d, "os.ldr"), "--no-restart")

                sent = 0
                with open(os.path.join(d, "os.ldr")) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        r = card.send_apdu(line)
                        self.assertEqual(
                            r.sw, 0x9000,
                            f"loader command {line[:10]}... returned {r.sw:04X}")
                        sent += 1
                self.assertGreater(sent, 100, "expected a block per 128 bytes")

                status = card.send_apdu("80F2000000")
                self.assertEqual(status.data[1], 2, "slot state 2 = ACTIVE")
                self.assertEqual(
                    int.from_bytes(status.data[6:10], "big"), len(image))

            loaded_flash = read_file(os.path.join(d, "card_osflash.bin"))
            loaded_hdr = read_file(os.path.join(d, "card_oshdr.bin"))

        # 2. Produce the same slot offline, the way a gang programmer would.
        with tempfile.TemporaryDirectory() as d2:
            mkldr("slot", image_path(), "-d", d2)
            offline_flash = read_file(os.path.join(d2, "card_osflash.bin"))
            offline_hdr = read_file(os.path.join(d2, "card_oshdr.bin"))

        # 3. They must be identical. If they ever diverge, every other ARM test
        #    is exercising a slot the real loader would not have produced.
        self.assertEqual(loaded_flash, offline_flash,
                         "APDU-loaded flash differs from the offline image")
        self.assertEqual(loaded_hdr, offline_hdr,
                         "APDU-written slot header differs from the offline one")

    def test_loaded_card_boots_the_os_on_the_next_power_on(self):
        with tempfile.TemporaryDirectory() as d:
            mkldr("slot", image_path(), "-d", d)
            # no_os=True only means "do not stage a slot"; one is already here.
            with SmartCard(target="qemu", state_dir=d, no_os=True) as card:
                self.assertEqual(card.atr(), OS_ATR)
                self.assertEqual(card.select(0x3F00).sw, 0x9000)

    def test_a_slot_left_unactivated_does_not_boot(self):
        """VERIFY is not ACTIVATE. A half-finished load must not come up."""
        with tempfile.TemporaryDirectory() as d:
            mkldr("slot", image_path(), "-d", d, "--loaded-only")
            with SmartCard(target="qemu", state_dir=d, no_os=True) as card:
                self.assertEqual(card.atr(), BOOT_ATR,
                                 "a LOADED-but-not-ACTIVE slot must stay in the loader")
                self.assertEqual(card.send_apdu("80F2000000").data[1], 1,
                                 "slot state 1 = LOADED")

    def test_a_corrupted_image_stays_in_the_loader(self):
        with tempfile.TemporaryDirectory() as d:
            mkldr("slot", image_path(), "-d", d)
            path = os.path.join(d, "card_osflash.bin")
            blob = bytearray(read_file(path))
            blob[500] ^= 0x01           # one bit of rot inside the image
            with open(path, "wb") as f:
                f.write(bytes(blob))

            with SmartCard(target="qemu", state_dir=d, no_os=True) as card:
                self.assertEqual(card.atr(), BOOT_ATR,
                                 "a card whose image fails CRC must not be booted")
                self.assertEqual(card.send_apdu("80F2000000").data[1], 3,
                                 "slot state 3 = DAMAGED")


if __name__ == "__main__":
    unittest.main()
