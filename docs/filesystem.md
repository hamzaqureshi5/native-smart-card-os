# Filesystem

**Status: M2a implemented.** MF/DF/EF tree, selection, READ/UPDATE BINARY,
persistence. `CREATE FILE` / `DELETE FILE` / `GET RESPONSE` are M2b.

## What MF / DF / EF are

ISO/IEC 7816-4 gives a card a tree of files, each identified by a **two-byte
file identifier**. There are no names, no paths in the POSIX sense, and no way
to list a directory.

```
MF 3F00                    Master File -- the root. Exactly one.
 +-- EF 2F00               Elementary File: actual data. 32 bytes, SFI 1
 +-- EF 2F01               EF.ATR: what the card can do. 5 bytes, no SFI
 +-- DF 7F10               Dedicated File: a container ("an application")
      +-- EF 6F01          64 bytes, SFI 1
      +-- EF 6F02          16 bytes, SFI 2
```

That is the factory layout this card ships with, from `fs_personalise()`.

`2F01` is the only one of those whose *contents* mean something to a reader:
ISO/IEC 7816-4 reserves that identifier under the MF for card capability
information that does not fit in the ATR. Every other file here ships in the
erased state (`0xFF`), which is what a real un-personalised EF reads as. See
the EF.ATR entry in [roadmap.md](roadmap.md) for what it asserts and, more
importantly, what it deliberately does not.

The difference from a PC filesystem that matters most: **access control is per
file and enforced by the card itself.** There is no privileged mode that
bypasses it, because the card *is* the enforcer rather than a program that could
be replaced. (The conditions themselves arrive in M3 -- see the limitations
below.)

Note that SFI 1 appears twice. **Short EF identifiers are scoped to their parent
DF, not global** -- and that scoping is a security boundary, not a convenience.

## Layering

Your §11 requires logical filesystem code separated from physical NVM, and the
separation earns its keep in a specific way.

```
  cmd_select.c / cmd_binary.c    APDU semantics: P1/P2 rules, status words
          |
  fs.c        LOGICAL     tree, selection, file semantics
          |               knows parents and children. knows NO NVM offsets.
  fs_store.c  PHYSICAL    descriptors, superblock, CRC, allocation
          |               knows NVM offsets. knows NOTHING about trees.
  hal_nvm_*
```

M4 has to insert a transaction journal between the logical and physical layers
so that "update three descriptors" becomes atomic. With this seam, M4 changes
`fs_store.c` and nothing above it. Without it, M4 would mean rewriting the
filesystem.

The physical layer is deliberately *dumb*: it will happily store a descriptor
whose parent index is nonsense. Structural validity is the logical layer's job.

## On-NVM layout

**EEPROM -- metadata.** Byte-writable and high-endurance, which is what makes
updating a descriptor in place safe.

```
0x0000  16     superblock
0x0010  20*32  descriptor table
```

Superblock (16 bytes, big-endian):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `'S' 'C' 'O' 'S'` |
| 4 | 2 | layout version |
| 6 | 2 | max_files this image was created with |
| 8 | 4 | `data_top` -- next free FLASH offset |
| 12 | 2 | reserved |
| 14 | 2 | CRC-16 over bytes 0..13 |

Descriptor (20 bytes, big-endian):

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | file_id |
| 2 | 1 | type (`0xFF` = free slot) |
| 3 | 1 | lifecycle (ISO life cycle status byte) |
| 4 | 2 | parent index (`0xFFFF` for the MF) |
| 6 | 2 | size (EF data bytes) |
| 8 | 4 | data_offset (FLASH) |
| 12 | 1 | `ac_read` — **M3** |
| 13 | 1 | `ac_update` — **M3** |
| 14 | 1 | sfi (short EF identifier, 0 = none) |
| 15 | 1 | flags |
| 16 | 2 | reserved |
| 18 | 2 | CRC-16 over bytes 0..17 |

**FLASH -- EF contents**, bump-allocated upward from 0.

### Three decisions in that layout worth explaining

**No C struct is ever written to NVM.** Struct layout is compiler- and
target-dependent: padding and endianness differ between an x86 build and a card
MCU. A card whose filesystem becomes unreadable after a toolchain change is a
brick. Every field is serialised by hand, so the format is a contract rather
than an accident. `descriptor_roundtrip_survives_serialisation` checks every
field, because a serialisation bug typically loses exactly one.

**Big-endian**, because everything on the ISO 7816 wire is -- file identifiers
included. No byte-swapping between the APDU and the descriptor, and one fewer
place to invert something.

**A free slot is `0xFF`**, recognised by its type byte alone with *no CRC
check*. Erased NVM is all-`FF` and would fail any CRC, so this is what lets a
factory-blank chip present a coherent empty table with no formatting pass.

## Integrity

Every superblock and descriptor carries a CRC-16 (CCITT-FALSE), checked **before
any other field is interpreted**. Acting on a half-written descriptor compounds
the damage: a corrupt `data_top` would hand out overlapping allocations and
quietly destroy file contents.

**A CRC detects corruption. It is not authentication and gives no tamper
resistance** -- an attacker who can write NVM can recompute it. Detecting
deliberate modification needs a MAC under a key the attacker cannot reach, which
needs both cryptography (M5) and hardware key storage. Recorded in
`docs/threat-model.md`.

### Corruption is reported, never repaired

A corrupt or unknown-version image makes the card come up in `SCOS_LC_FS_ERROR`,
answering `6581` (memory failure) to everything. It is **not** auto-formatted,
for two reasons: reformatting destroys the data most worth recovering, and it
would hand anyone able to corrupt a single byte a reliable card-wipe primitive.

The simulator prints a warning and keeps serving, because a real card cannot
exit -- it must answer *something* so a reader can tell "corrupt filesystem"
from "dead card". (`main.c` originally exited here; the Python persistence test
caught it.)

## Selection

The current selection is the card's most important volatile state: `READ BINARY`
does not name a file, it reads *the current EF*. Almost every command is
implicitly scoped by it, so getting the transitions wrong is a security bug.

ISO rules implemented in `fs.c`:

* selecting a DF makes it current and **clears the current EF** — without this,
  a later `READ BINARY` could act on an EF belonging to a different application
  than the DF now selected
* selecting an EF sets the current EF; the current DF becomes its parent
* a reset returns to the MF with no current EF
* **a failed selection changes nothing** — required by ISO, and a card that
  cleared its selection on a failed lookup would let an attacker drop the
  security context with a junk APDU

### Search order for P1=00 — fixed and documented

ISO leaves this to the card, so an *undocumented* order becomes an accidental
part of the interface that clients come to depend on. Ours:

1. the MF, if the identifier is `3F00`
2. a direct child of the current DF
3. the current DF itself
4. the parent of the current DF

**Deliberately absent: a global search of the tree.** That would let one
application reach another's files by identifier alone, which is exactly the
isolation the DF hierarchy exists to provide. `selection_search_order_is_scoped`
pins it down.

### Path selection is atomic

`fs_select_by_path()` walks a *scratch* copy and commits only on full success.
A path that fails half way must leave the selection untouched — otherwise an
attacker chooses which intermediate DF the card lands in.
(`failed_path_walk_is_atomic`.)

## Commands

| Command | INS | Supported |
|---|---|---|
| SELECT | A4 | P1 = 00, 01, 02, 03, 08, 09. FCI (`6F`) and FCP (`62`) templates |
| READ BINARY | B0 | offset form and short-EF-identifier form |
| UPDATE BINARY | D6 | offset form and short-EF-identifier form |
| SELECT by DF name | A4 P1=04 | **no** — AIDs belong to the Card Manager (M7) |
| CREATE / DELETE FILE | E0 / E4 | **no** — M2b, needs a TLV parser |
| GET RESPONSE | C0 | **no** — M2b |

### The READ/UPDATE BINARY P1-P2 encoding

ISO overloads P1/P2 with two meanings, chosen by the top bit of P1:

* **b8 = 0** — `P1||P2` is a 15-bit **offset** into the current EF (0..32767).
  Requires a current EF, else `6986`.
* **b8 = 1** — b7 b6 must be zero, b5..b1 are a **short EF identifier**
  (1..30), and P2 alone is the offset (0..255). This selects the EF
  *implicitly*: one APDU instead of a SELECT plus a READ. It is why files carry
  an SFI.

Note the asymmetry that follows: the SFI form can only address the first 256
bytes of a file. That is ISO's constraint, not ours.

### Short reads return 6282, not 9000

When fewer bytes remain than Le, ISO says return what exists with `6282`, "end
of file reached before reading Le bytes" — a *warning*, so the data in the
response is valid and the caller should use it. Returning `9000` would be a
small lie a client cannot detect, since it has no other way to learn the file
was shorter.

### Writes are all-or-nothing

An `UPDATE BINARY` that would cross the end of the file is refused **entirely**,
not truncated. Without transactions there is no way to undo half a write, so a
partial update would leave the file in a state the caller cannot reason about.

## Known limitations

Stated plainly rather than left to be discovered.

**No access control is enforced.** Any reader that can reach the card can read
and write any file. `ac_read`/`ac_update` are stored in every descriptor but
nothing checks them. **This card currently protects nothing.** M3.

**No tear-resistance.** `hal_nvm_write()` is still an atomic `memcpy` — the
optimistic case. A power failure mid-write is not yet modelled, so no claim
about recovery is justified. Ordering helps a little (`fs_store_format()` writes
the superblock *last*, so an interrupted format leaves the card readable as
unformatted), but that is a mitigation, not a guarantee. M4.

**No space reclamation.** Allocation is a bump pointer with no free list. Space
released by a deleted file is not reclaimed until a compaction pass exists — and
compaction cannot be written safely before transactions, because a power loss
mid-compaction without a journal would destroy the filesystem.

**No descriptor cache.** Every lookup re-reads NVM, so a search is O(32) reads.
A cache would cost ~640 bytes of RAM and introduce a coherence problem: two
copies of the truth, with a window in which a power failure leaves them
disagreeing. Correctness first; this is a measured optimisation for later.

**Transparent EFs only.** ISO also defines linear-fixed, linear-variable and
cyclic record structures. Not implemented, and refused rather than half-done.

**32 files maximum, 32767 bytes per EF.** Bounded on purpose: an unbounded table
means unbounded NVM use and an unbounded search, neither of which a card can
afford. The EF limit is ISO's — `READ BINARY`'s offset field is 15 bits.

## Tests

| Test | Layer |
|---|---|
| `crc16_known_answer` | CCITT-FALSE check value `0x29B1` |
| `descriptor_roundtrip_survives_serialisation` | physical: every field |
| `corrupt_descriptor_is_detected_not_used` | physical: flips a real NVM byte |
| `corrupt_superblock_refuses_to_mount` | physical: no auto-format |
| `unknown_layout_version_refuses_to_mount` | physical: forward compatibility |
| `allocation_is_bounded_and_monotonic` | physical: no overlap, no wrap |
| `selection_search_order_is_scoped` | logical: cross-DF isolation |
| `failed_path_walk_is_atomic` | logical: partial failure changes nothing |
| `ef_access_cannot_escape_the_file` | logical: bounds, both directions |
| `files_do_not_overlap_in_flash` | logical: allocation isolation |
| `binary_never_escapes_under_a_p1p2_sweep` | command: 4k+ P1/P2 pairs under ASan |
| `test_data_survives_a_power_cycle` | Python: two processes, real NVM files |
| `test_superblock_corruption_bricks_the_card_safely` | Python: corrupts the image on disk |
