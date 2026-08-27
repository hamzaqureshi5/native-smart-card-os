# SPDX-License-Identifier: MIT
"""CREATE FILE (E0) and DELETE FILE (E4), over the card interface.

The C unit tests in tests/unit/test_create.c cover the FCP parser and the
structural rules exhaustively. What is here instead is what C cannot reach on
this HAL:

  * persistence across a real power cycle -- the unit-test HAL runs with no
    state directory and erases NVM on power-on, correctly, because an in-RAM
    card with nowhere to flush to IS blank once power is removed;
  * the same behaviour on the ARM chip as on x86, from one test body.

Templates are BUILT here, never hand-written. Hand-counting BER length bytes
was wrong three times while developing this feature -- including writing 0x83
as a length, which BER reads as "three length bytes follow".
"""

import os
import tempfile
import unittest

from scos.card import SmartCard

FDB_EF_TRANSPARENT = 0x01
FDB_DF = 0x38

SW_OK = 0x9000
SW_FILE_NOT_FOUND = 0x6A82
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA = 0x6A80
SW_FUNC_NOT_SUPPORTED = 0x6A81
SW_FILE_ALREADY_EXISTS = 0x6A89
SW_NO_CURRENT_EF = 0x6986


def tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 0x80, "long-form lengths are not needed here"
    return bytes([tag, len(value)]) + value


def fcp(*objects: bytes) -> bytes:
    return tlv(0x62, b"".join(objects))


def ef_template(fid: int, size: int, sfi: int = 0) -> bytes:
    objs = [
        tlv(0x82, bytes([FDB_EF_TRANSPARENT])),
        tlv(0x83, fid.to_bytes(2, "big")),
        tlv(0x80, size.to_bytes(2, "big")),
    ]
    if sfi:
        # ISO puts the SFI in b8..b4, so it is shifted left by 3.
        objs.append(tlv(0x88, bytes([sfi << 3])))
    return fcp(*objs)


def df_template(fid: int) -> bytes:
    return fcp(tlv(0x82, bytes([FDB_DF])), tlv(0x83, fid.to_bytes(2, "big")))


def apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"") -> str:
    return (bytes([cla, ins, p1, p2, len(data)]) + data).hex().upper()


class CreateFileTests(unittest.TestCase):

    # --- helpers ----------------------------------------------------------

    def create(self, card, template: bytes):
        return card.send_apdu(apdu(0x00, 0xE0, 0x00, 0x00, template))

    def delete(self, card, fid: int):
        return card.send_apdu(
            apdu(0x00, 0xE4, 0x00, 0x00, fid.to_bytes(2, "big")))

    def select(self, card, p1: int, fid: int):
        return card.send_apdu(
            apdu(0x00, 0xA4, p1, 0x0C, fid.to_bytes(2, "big")))

    # --- the shape of the feature ----------------------------------------

    def test_create_an_ef_and_use_it(self):
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            # SFI 3: 1 and 2 belong to the factory layout.
            self.assertEqual(self.create(card, ef_template(0x2801, 32, 3)).sw, SW_OK)

            self.assertEqual(self.select(card, 0x02, 0x2801).sw, SW_OK)
            self.assertEqual(card.send_apdu(
                apdu(0x00, 0xD6, 0x00, 0x00, b"created")).sw, SW_OK)
            r = card.send_apdu("00B0000007")
            self.assertEqual(r.sw, SW_OK)
            self.assertEqual(r.data, b"created")

    def test_create_a_df_and_nest_a_file(self):
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.create(card, df_template(0x7F20)).sw, SW_OK)
            self.assertEqual(self.select(card, 0x01, 0x7F20).sw, SW_OK)
            # SFI 1 is free inside this DF even though the MF uses it: short
            # identifiers are scoped to their DF, not to the card.
            self.assertEqual(self.create(card, ef_template(0x6F31, 8, 1)).sw, SW_OK)
            self.assertEqual(self.select(card, 0x02, 0x6F31).sw, SW_OK)

            # Not reachable from the MF by identifier -- creating files must not
            # open a hole in the cross-DF isolation SELECT enforces.
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.select(card, 0x02, 0x6F31).sw, SW_FILE_NOT_FOUND)

    def test_a_created_file_survives_a_power_cycle(self):
        """The test the C suite cannot run: real NVM behind the card."""
        with tempfile.TemporaryDirectory() as d:
            with SmartCard(state_dir=d) as card:
                self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
                self.assertEqual(
                    self.create(card, ef_template(0x2802, 16, 4)).sw, SW_OK)
                self.assertEqual(self.select(card, 0x02, 0x2802).sw, SW_OK)
                self.assertEqual(card.send_apdu(
                    apdu(0x00, 0xD6, 0x00, 0x00, bytes.fromhex("C0FFEE"))).sw,
                    SW_OK)

            # A brand new process, same card.
            with SmartCard(state_dir=d) as card:
                self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
                self.assertEqual(self.select(card, 0x02, 0x2802).sw, SW_OK)
                r = card.send_apdu("00B0000003")
                self.assertEqual(r.sw, SW_OK)
                self.assertEqual(r.data, bytes.fromhex("C0FFEE"))

    def test_a_deleted_file_stays_deleted_across_a_power_cycle(self):
        with tempfile.TemporaryDirectory() as d:
            with SmartCard(state_dir=d) as card:
                self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
                # The factory DF 7F10 holds two EFs; empty it, then remove it.
                self.assertEqual(self.select(card, 0x01, 0x7F10).sw, SW_OK)
                self.assertEqual(self.delete(card, 0x6F01).sw, SW_OK)
                self.assertEqual(self.delete(card, 0x6F02).sw, SW_OK)
                self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
                self.assertEqual(self.delete(card, 0x7F10).sw, SW_OK)

            with SmartCard(state_dir=d) as card:
                self.assertEqual(self.select(card, 0x01, 0x7F10).sw,
                                 SW_FILE_NOT_FOUND)
                # And the card did NOT quietly re-personalise itself: EF 2F00
                # is still there, so fs_init() mounted rather than reformatted.
                self.assertEqual(self.select(card, 0x02, 0x2F00).sw, SW_OK)

    # --- refusals ---------------------------------------------------------

    def test_delete_refuses_a_non_empty_df_and_the_mf(self):
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.delete(card, 0x7F10).sw,
                             SW_CONDITIONS_NOT_SATISFIED)
            self.assertEqual(self.delete(card, 0x3F00).sw,
                             SW_CONDITIONS_NOT_SATISFIED)
            # The card is still mountable, which is the part that matters.
            self.assertEqual(self.select(card, 0x02, 0x2F00).sw, SW_OK)

    def test_duplicates_are_refused(self):
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.create(card, ef_template(0x2803, 8)).sw, SW_OK)
            self.assertEqual(self.create(card, ef_template(0x2803, 8)).sw,
                             SW_FILE_ALREADY_EXISTS)
            # SFI 1 is taken by factory EF 2F00.
            self.assertEqual(self.create(card, ef_template(0x2804, 8, 1)).sw,
                             SW_FILE_ALREADY_EXISTS)

    def test_the_iso_compact_security_format_is_refused(self):
        """Tag 8C carries access conditions in ISO's compact format.

        Now 6A81 rather than 6A80, and the change is the point rather than a
        relaxation: 8C is a valid tag, so "bad data field" was never true.
        6A81 says the card understands the tag and does not implement it, which
        tells a caller to use tag 86 instead of hunting for an error in a
        template that has none.

        Still refused. 8C's access-mode byte assigns bits to operations, this
        project does not have the specification text to state those positions
        precisely, and a card that accepted the template while misreading them
        would create a file whose protection is not the protection that was
        requested -- and answer 9000 while doing it.
        """
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            template = fcp(
                tlv(0x82, bytes([FDB_EF_TRANSPARENT])),
                tlv(0x83, (0x2805).to_bytes(2, "big")),
                tlv(0x80, (16).to_bytes(2, "big")),
                tlv(0x8C, bytes.fromhex("01FF")),
            )
            self.assertEqual(self.create(card, template).sw,
                             SW_FUNC_NOT_SUPPORTED)
            # Nothing was created, so the client cannot end up holding an
            # unprotected file it believes is protected.
            self.assertEqual(self.select(card, 0x02, 0x2805).sw, SW_FILE_NOT_FOUND)

    def test_a_genuinely_unknown_tag_is_still_6a80(self):
        """The other half: a tag the card has no opinion about at all. 6A80,
        because that IS a bad data field -- and it must stay distinguishable
        from 6A81, which means "valid, unimplemented"."""
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            template = fcp(
                tlv(0x82, bytes([FDB_EF_TRANSPARENT])),
                tlv(0x83, (0x2807).to_bytes(2, "big")),
                tlv(0x80, (16).to_bytes(2, "big")),
                tlv(0x9E, bytes.fromhex("AA")),   # not an FCP tag at all
            )
            self.assertEqual(self.create(card, template).sw, SW_WRONG_DATA)
            self.assertEqual(self.select(card, 0x02, 0x2807).sw, SW_FILE_NOT_FOUND)

    def test_unsupported_iso_file_types_are_distinguishable(self):
        """6A81, not 6A80: the template is fine, the card lacks the feature."""
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            linear = fcp(
                tlv(0x82, bytes([0x02])),           # working EF, linear fixed
                tlv(0x83, (0x2806).to_bytes(2, "big")),
                tlv(0x80, (16).to_bytes(2, "big")),
            )
            self.assertEqual(self.create(card, linear).sw, SW_FUNC_NOT_SUPPORTED)

    def test_create_does_not_move_the_selection(self):
        """Deliberate divergence from ISO/IEC 7816-9.

        ISO permits selecting the new file. We do not: a command that quietly
        moves the current EF turns the client's next UPDATE BINARY into a write
        to a different file than it intended.
        """
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.select(card, 0x02, 0x2F00).sw, SW_OK)
            self.assertEqual(self.create(card, ef_template(0x2807, 8)).sw, SW_OK)
            # Writes still land in 2F00.
            self.assertEqual(card.send_apdu(
                apdu(0x00, 0xD6, 0x00, 0x00, bytes.fromhex("5A5A"))).sw, SW_OK)
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.select(card, 0x02, 0x2807).sw, SW_OK)
            r = card.send_apdu("00B0000002")
            self.assertEqual(r.data, bytes.fromhex("FFFF"))

    def test_deleting_the_current_ef_clears_the_selection(self):
        with SmartCard() as card:
            self.assertEqual(self.select(card, 0x00, 0x3F00).sw, SW_OK)
            self.assertEqual(self.create(card, ef_template(0x2808, 8)).sw, SW_OK)
            self.assertEqual(self.select(card, 0x02, 0x2808).sw, SW_OK)
            self.assertEqual(self.delete(card, 0x2808).sw, SW_OK)
            # Not a read of a freed slot.
            self.assertEqual(card.send_apdu("00B0000004").sw, SW_NO_CURRENT_EF)


if __name__ == "__main__":
    unittest.main()
