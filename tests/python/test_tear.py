# SPDX-License-Identifier: MIT
"""Power failure across sessions.

tests/unit/test_journal.c sweeps interruptions within one process. What is here
is the case that process cannot reach: an interrupted write that is STILL
interrupted after the reader takes the card away and puts it back, so the thing
that has to put the card right is boot recovery rather than the same session's
error handling.

Three transport controls make it possible, all simulator-only:

  .fault SKIP N   let SKIP NVM writes through, then cut the next after N bytes
  .hold           keep failing every write after the cut
  .tear           remove power WITHOUT the orderly flush

`.hold` is the one that matters and the reason is not obvious. A single-shot
fault is always followed, in the same session, by the command's own rollback --
the simulator cannot stop the process half way through a C function the way a
real card stops when the field drops. So without hold the journal is always
closed before power goes, and the next boot has nothing to recover: the test
passes while exercising the in-session path only. That is exactly the mistake
the first version of these tests made.
"""

import os
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIM = os.environ.get("SCOS_SIM", os.path.join(REPO, "build", "smartcard-sim"))


def session(state_dir: str, *lines: str) -> list:
    """Run one card session and return its response lines."""
    script = "".join(l + "\n" for l in lines)
    p = subprocess.run(
        [SIM, "--quiet", "--state-dir", state_dir],
        input=script, capture_output=True, text=True, timeout=60,
    )
    return [l for l in p.stdout.splitlines() if l.strip()]


@unittest.skipUnless(os.path.isfile(SIM), f"simulator not built at {SIM}")
class TearTests(unittest.TestCase):

    SELECT_2F00 = "00A4020C022F00"
    READ4 = "00B0000004"

    def seed(self, d):
        """A card with a known 4 bytes in 2F00, durably."""
        out = session(d, self.SELECT_2F00, "00D6000004AABBCCDD", ".quit")
        self.assertEqual(out, ["9000", "9000"], out)

    def test_an_interrupted_write_is_undone_at_the_next_power_on(self):
        with tempfile.TemporaryDirectory() as d:
            self.seed(d)

            # Cut the DATA write (write #5 of the command) after 2 bytes, and
            # hold, so the rollback cannot run in this session.
            out = session(d, self.SELECT_2F00, ".hold", ".fault 4 2",
                          "00D6000004EEFFEEFF", ".fired", ".tear")
            self.assertIn("FIRED", out,
                          "the arming never fired -- the test proved nothing")

            # Boot recovery is now the only thing that can put this right.
            out = session(d, self.SELECT_2F00, self.READ4, ".quit")
            self.assertEqual(
                out[-1], "AABBCCDD9000",
                "the interrupted write was not undone at power-on")

    def test_the_partial_write_really_did_reach_nvm(self):
        """The test above is only meaningful if the cut left something behind.
        This checks the premise directly: with the journal's recovery having
        nothing to do -- a committed transaction -- the new bytes stand."""
        with tempfile.TemporaryDirectory() as d:
            self.seed(d)
            out = session(d, self.SELECT_2F00, "00D6000004EEFFEEFF", ".quit")
            self.assertEqual(out, ["9000", "9000"], out)
            out = session(d, self.SELECT_2F00, self.READ4, ".quit")
            self.assertEqual(out[-1], "EEFFEEFF9000",
                             "a committed write did not survive a power cycle")

    def test_a_tear_before_any_data_write_changes_nothing(self):
        """Cutting the journal's own header write, which is the FIRST write any
        command makes. Nothing has been modified at that point, so there is
        nothing to undo -- and the card must still come up."""
        with tempfile.TemporaryDirectory() as d:
            self.seed(d)
            out = session(d, self.SELECT_2F00, ".hold", ".fault 0 1",
                          "00D6000004EEFFEEFF", ".fired", ".tear")
            self.assertIn("FIRED", out)
            out = session(d, self.SELECT_2F00, self.READ4, ".quit")
            self.assertEqual(out[-1], "AABBCCDD9000")

    def test_a_torn_create_file_leaves_no_file(self):
        """The metadata case. CREATE FILE writes a descriptor AND the
        superblock's allocation pointer; coming back with one and not the other
        is a file pointing at bytes nobody owns."""
        with tempfile.TemporaryDirectory() as d:
            self.seed(d)
            create = "00E00000" + "0D" + "620B" + "820101" + "83022B01" \
                     + "80020010"
            out = session(d, "00A4000C023F00", ".hold", ".fault 4 3",
                          create, ".fired", ".tear")
            self.assertIn("FIRED", out)

            out = session(d, "00A4000C023F00", "00A4020C022B01", ".quit")
            self.assertEqual(out[-1], "6A82",
                             "a torn CREATE FILE left the file behind")

    def test_the_card_survives_a_tear_at_every_write_of_a_command(self):
        """A sweep over write indices. At every one, the card must come up and
        the file must hold either the old value or the new one -- never a
        mixture. Half a record is the outcome that must be impossible."""
        for skip in range(0, 8):
            with tempfile.TemporaryDirectory() as d:
                self.seed(d)
                session(d, self.SELECT_2F00, ".hold", f".fault {skip} 2",
                        "00D6000004EEFFEEFF", ".tear")
                out = session(d, self.SELECT_2F00, self.READ4, ".quit")
                self.assertEqual(len(out), 2, f"card did not come up (skip={skip})")
                self.assertIn(
                    out[-1], ("AABBCCDD9000", "EEFFEEFF9000"),
                    f"skip={skip}: the file holds a MIXTURE, not old or new")


if __name__ == "__main__":
    unittest.main()
