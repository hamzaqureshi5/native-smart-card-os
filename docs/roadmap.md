# Roadmap

Each milestone follows the same loop: explain, implement the smallest useful
version, test, build, run, show real results, and state what was learned. No
milestone starts before the previous one's tests pass.

---

## M1 -- Foundation :: DONE

HAL contract, simulator HAL, kernel skeleton, APDU parser/dispatcher/response
builder, simulator executable, SELECT of the Master File, automated tests.

**Result:** 7 tests, 116,429 C assertions, all passing under ASan + UBSan.
OS core: 3,936 B ROM (12% of budget), 536 B RAM (7%). The core's complete
external dependency list is `hal_card_receive`, `hal_card_send`.

Deliberately excluded: filesystem, crypto, applets, secure messaging, Samsung
support, extended APDUs, fuzzing.

---

## M2a -- Filesystem core :: DONE

MF/DF/EF tree with on-NVM descriptors and CRC integrity, the logical/physical
split, selection (P1 = 00/01/02/03/08/09) with FCI and FCP templates, READ and
UPDATE BINARY in both the offset and short-EF-identifier forms, and persistence
across a real power cycle.

**Result:** 7 tests, 143,793 C assertions, 53 Python tests, all passing under
ASan + UBSan. See `docs/filesystem.md`, including its Known Limitations.

Decision taken: "file not found" (6A82) and "not usable" (6985) are kept
distinguishable. Revisit in M3 when access conditions make the trade-off real.

---

## M2b -- Dynamic filesystem :: IN PROGRESS

**Why split from M2a:** `CREATE FILE` needs a BER-TLV parser to read FCP
templates. That is a second untrusted-input parser and deserves its own tests
and fuzz targets rather than being tacked onto a working milestone.

* **BER-TLV parser** :: DONE -- tag, length (short and long form), value;
  bounded, no recursion. `include/apdu/tlv.h`. Swept exhaustively over all
  16,777,216 three-byte inputs under ASan.
* **fuzzing** :: DONE -- APDU parser, TLV parser, command dispatch, filesystem
  descriptor images, boot loader, and FCP create/delete sequences.
  `tests/fuzz/`. The `fcp` target biases toward templates that PARSE, because
  `fuzz_command` emits INS E0 but its random data never forms a valid FCP --
  measured at 27% successful creates, so the mutating paths are genuinely
  reached rather than assumed to be.
* **`CREATE FILE` (E0) from an FCP template; `DELETE FILE` (E4)** :: DONE --
  `src/filesystem/cmd_create.c`. Unknown FCP tags are REFUSED, not ignored:
  tags 86 and 8C carry access conditions, so a card that ignored them would
  create an unprotected file while answering 9000. One documented deviation
  from ISO/IEC 7816-9: the new file is not selected.
* **refuse deleting a non-empty DF** :: DONE -- a recursive delete cannot be
  rolled back before M4, so a power cut part way through would leave orphaned
  descriptors pointing at a reused parent slot.
* **KNOWN LIMITATION**: `DELETE FILE` frees the descriptor slot but NOT the
  EF's data bytes. `fs_store`'s data area is a bump allocator, so deleting
  leaks space. Compaction needs atomic data movement, which needs M4. Asserted
  in `test_create.c` so it cannot regress silently.
* `ACTIVATE FILE` / `DEACTIVATE FILE` (44 / 04) :: TODO -- a file can be
  *created* deactivated today, but not moved between states afterwards.
* **`GET RESPONSE` (C0) and `61XX`** :: DONE -- `src/apdu/cmd_get_response.c`.
  This was not a checklist item: before it, a Case 3 SELECT answered `9000`
  with **no data**, so a conformant reader sending the project's own canonical
  first APDU
  ```
  00 A4 00 00 02 3F 00
  ```
  got success and no file information, with nothing to indicate the card had
  more to say. It now answers `610C` and the reader collects the FCI.

  The mechanism is a 256-byte staging buffer in `scos_kernel`, cleared by ANY
  command other than GET RESPONSE -- enforced once in `scos_process()` rather
  than per handler. ISO requires GET RESPONSE to immediately follow its `61XX`,
  and the reason is security, not tidiness: a card that kept the data would let
  a later unrelated command collect an earlier one's output, from M3 possibly
  across a change of authentication state.

  One deliberate exception: a frame that fails the structural parse or the
  class check does NOT clear it. Those never reached a handler, so from the
  reader's point of view no command intervened -- and a card that dropped
  pending data on line noise would make GET RESPONSE unusable on a noisy link,
  where retransmission is the reader's only recourse.

  **Bug found while wiring it up**, worth recording because it is the kind that
  survives review: `61XX` is a SUCCESS status, and `scos_cmd_select` treated
  any non-`9000` as failure. So a Case 3 SELECT staged its FCI, answered
  `61XX`, and never committed the selection -- the card handed back control
  information for a file it had not selected, and the reader's next READ BINARY
  would have acted on the previous one. Caught by an existing M1 test asserting
  the selection had moved.
* **extended APDUs** :: DONE -- `src/apdu/apdu_parse.c`, and a documented
  ceiling in `include/os/scos_config.h.in`.

  The encoding is implemented in full: Case 2E/3E/4E, the three-byte length
  field, and both zero-normalisations (`Le` of `0x00` means 256 in the short
  form, `0x0000` means 65536 in the extended one). The five-byte boundary is
  the one that matters and it has its own test: `00 A4 00 00 00` is a SHORT
  Case 2 with `Le`=256, *not* the start of an extended APDU, because the
  extended form needs three bytes of length field and there is one. That is
  the project's own canonical first APDU, so misreading it would break the
  command the card is asked most.

  **The two directions are not symmetric, and treating them the same is the
  mistake this design avoids.**

  `Lc` costs RAM: the card must hold the whole data field before acting on it.
  So `Lc` has a ceiling -- `SCOS_APDU_EXT_DATA_MAX`, 1 KB -- and above it the
  parser returns `APDU_PARSE_LC_TOO_LARGE` and the card answers `6700`. Not
  `6A81` "function not supported", because extended length *is* supported:
  telling a reader otherwise would make it abandon the encoding instead of
  sending a smaller `Lc`. 1 KB rather than 255 because a ceiling at 255 would
  make the extended encoding carry nothing the short form cannot -- a feature
  that ticks a conformance box without making the card better.

  `Le` costs nothing: it is a MAXIMUM, and ISO permits returning fewer bytes.
  So an extended `Le` of 65536 is honoured as written and the card answers
  with what it has. No ceiling, no refusal, no buffer.

  That asymmetry produced the one genuinely subtle rule here. `READ BINARY`
  can now return fewer bytes than `Le` for two different reasons, and a reader
  that cannot tell them apart cannot behave correctly:

  | | meaning | what the reader should do |
  |---|---|---|
  | `6282` | the **file** ended | stop; there is nothing further |
  | `9000` | the **card** clamped | read again from `offset + received` |

  Collapsing them into one answer is wrong in both directions: `6282` after a
  clamp reports a file as shorter than it is, and `9000` at real end-of-file
  sends a reader round a loop that never terminates.

  **Still not 65535, and it never will be by buffering.** As
  [hardware-port.md](hardware-port.md) records, a real SIM part has 5 KB of
  RAM shared with the stack; 65535 bytes is not a tight fit there, it is
  impossible, and raising `SCOS_SIM_RAM_KB` would not change it. The only
  mechanism that ever reaches the ISO maximum is command chaining (CLA bit
  b5), which sends a large field as several short APDUs and needs no large
  buffer at all. `apdu_check_cla()` already reports `6884` for the chaining
  bit, so the refusal is precise rather than a blanket `6E00`.

  Two supporting changes worth recording, because neither is where anyone
  would look for extended-length work:

  * `READ BINARY` reads through a 64-byte stack buffer in a loop instead of
    one buffer sized for the ceiling. Stack is the one kind of RAM the project
    does **not** account for -- `_Static_assert` measures
    `sizeof(scos_kernel)` -- so a 1 KB local would have been invisible to the
    budget it blows.
  * the simulator transport used to DROP a command longer than the receive
    buffer, printing to stderr and answering nothing, which is
    indistinguishable from a dead card. It now hands the OS the leading bytes
    that did fit and lets the parser reach its own verdict, which is the shape
    of a real T=0 exchange: the reader sends the header and the card can
    refuse before a single data byte moves.

  Cost: `sizeof(scos_kernel)` 796 -> 2336 bytes of the 8 KB budget, OS text
  17,480 -> 17,780. Coverage: 90,368 assertions in `test_apdu_parse.c`
  including an exhaustive sweep of every (declared Lc, frame length) pair,
  9 end-to-end tests in `tests/python/test_extended_apdu.py` that move real
  payloads of 600, 700 and 1024 bytes, and a new extended-form generator in
  the fuzz driver -- `gen_apdu_like` writes `Lc` as one byte at `buf[4]` and
  so could never produce this shape at all.
* EF.ATR (`2F01`) :: TODO

---

## M2c -- Boot loader :: DONE

**Why this happened here:** the OS was compiled into whatever ran it, so there
was no such thing as a blank chip. "Loading an OS" had no meaning, and neither
did the question of whether the ATR changes afterwards.

* **CODE split into BOOTROM / OSFLASH / OSHDR** -- the boot loader lives in
  8 KB of mask ROM at address 0 and cannot be replaced; the OS is relinked to
  run from `0x00002000`. See [chip-scv1.md](chip-scv1.md).
* **`libscos_boot`** -- pure loader logic over two byte regions, so it is
  host-testable under ASan. It links `scos_util`, never `scos_core`: a loader
  that depended on the OS could not load an OS onto a blank part, and the link
  enforces it.
* **Code-flash semantics** (`cflash.h`) -- page erase to `0xFF`, programming
  can only clear bits. A loader bug that works in QEMU and bricks a real part
  is the class of bug this exists to catch.
* **OS slot header** -- magic, length, image CRC, header CRC, and a state word
  deliberately outside the CRC so LOADED -> ACTIVE is reachable by clearing
  bits without an erase.
* **Loader command set** (CLA 80): GET STATUS, ERASE, LOAD BLOCK, VERIFY,
  ACTIVATE, RESTART. Ours, documented in `include/boot/boot_loader.h`. NOT
  derived from any captured trace of a real card.
* **Image plausibility check** -- a correct CRC proves the bytes arrived, not
  that they are code. The initial SP must land in SRAM and the reset vector
  must land in the image with the Thumb bit set, or VERIFY returns 6984.
* **BOOTSEL strap** -- forced loader entry, because otherwise an ACTIVE slot is
  a one-way door and the part can never be reprogrammed.
* **`tools/mkldr.py`** -- generates `os.ldr` / `recycle.ldr`, and can write a
  pre-programmed slot offline the way a gang programmer would.
* **Tests** -- 21 host unit tests, a sequence-driven fuzz target asserting that
  an ACTIVE slot can never be a lie, and 9 QEMU integration tests including one
  that proves the APDU-loaded slot is byte-identical to the offline one.

**Not done, and deliberately:** the loader has no authentication and no lock
bit. Anyone who can reach a blank card can load and activate any image. Signed
images wait on M5; a one-way fuse needs real silicon. Tracked in
[threat-model.md](threat-model.md).

---

## M3 -- Security

* PIN object with verifier (**never the plaintext PIN in NVM**), salted hash
* retry counter **decremented before verification** -- otherwise cutting power
  after a failed attempt restores the try, a real and repeatedly-exploited
  attack. This is why the counter lives in byte-writable EEPROM.
* blocked state, and whether it is recoverable (PUK) or terminal
* `VERIFY`, `63CX` (X tries remaining), `6983` when blocked
* authentication state, cleared on reset
* per-file access conditions enforced in the command path
* tests: correct/incorrect PIN, decrement, exhaustion, blocked, reset behaviour,
  brute force, unauthorized file access, and **power-cut-after-failed-verify**
* License should be verified in order to use OS ... create a static license key initially later we will make it proper dynamic license key.
Depends on M4 for that last one to be fully honest.

---

## M4 -- Transactions and power failure

The highest-risk milestone, and the one that distinguishes a card OS from an
embedded database.

* `POWER_FAILURE` in the simulator: **skips the durability flush** and can stop
  part way through a write, unlike `POWER_OFF`
* fault-injection hook in `hal_nvm_write()`: stop after N bytes, mark power lost
* journal in EEPROM: BEGIN / UPDATE / COMMIT / ABORT
* recovery at boot: roll forward a committed transaction, roll back an
  incomplete one
* transaction depth and size limits, and correct behaviour at them
* tests: commit, abort, interrupted write at **every byte offset**, corrupted
  journal metadata, corrupted records, and rollback of a failed multi-write
  command

Until this lands, **no tear-resistance claim in this project is justified.**

---

## M5 -- Cryptography

* abstraction only -- **no primitive implemented here**: `crypto_random`,
  `crypto_aes_*`, `crypto_sha256`, `crypto_hmac`, `crypto_ec_*`
* backed by an established library in the simulator; by the accelerator on
  hardware
* `KeyObject`: type, algorithm, size, usage, lifecycle, exportable
* **private keys non-exportable, with no API path to raw material** -- tested by
  attempting extraction
* known-answer tests from the specifications' published vectors

**Open design question:** if the target chip has hardware key slots, a
`KeyObject` should reference a slot rather than hold material. That changes the
abstraction substantially, so it is a question for `docs/hardware-port.md` to
answer first.

---

## M6 -- Applets

* native applet interface: `install` / `select` / `deselect` / `process`
* `HelloApplet` (responds to GET DATA), then `PINApplet`, `StorageApplet`
* applet-scoped storage, reached only through OS APIs
* **the isolation limitation documented plainly**: native applets are linked C
  code in the same address space. There is no enforced boundary. A malicious
  applet can read anything. This is a *prototype interface*, not a security
  boundary, and will be labelled as such everywhere it appears.

Real isolation requires either an MPU (a hardware question) or a bytecode VM
(M8). Investigating which is appropriate is part of this milestone, not a
promise made in advance.

---

## M7 -- Card Manager

* application registry, selection, installation, deletion, lifecycle
* card lifecycle states, persisted, with TERMINATED honoured at boot
* security domain concept
* **structured ATR historical bytes**: replace the current proprietary `"SCOS"`
  label with `80` + COMPACT-TLV card service data / capabilities / lifecycle.
  Deferred to here because there is nothing worth advertising until the
  capabilities exist.

**Called a "GlobalPlatform-inspired prototype" until verified against the actual
specification.** No compliance claim.

---

## M8 -- Beyond

Each needs its own investigation before any commitment:

* **SCP03** secure messaging -- from the specification and its published test
  vectors only. No invented protocol details. Requires M5.
* **SCP11**, later.
* **Bytecode VM / applet firewall** -- the real answer to M6's limitation.
* **Contactless (ISO 14443)**.
* **Common Criteria** -- what the process actually demands, before assuming any
  of this would survive it.

Explicitly not planned: EMV / payment functionality. It would be built only for
a stated reason, not because it exists.

---

## Standards this project follows

The normative references. Everything the OS does on the wire is supposed to
come from one of these, and where it does not, that is a documented deviation
rather than an accident.

| Area | Standard / specification | What it covers | Status here |
|---|---|---|---|
| Card interface | **ISO/IEC 7816-3** | electrical interface, ATR, transmission protocols T=0/T=1 | ATR structure followed; **T=0/T=1 framing is NOT implemented** -- the simulator carries APDUs over a line protocol and the chip over a UART. See below. |
| APDU & commands | **ISO/IEC 7816-4** | APDU structure, command/response pairs, file organisation, security environment | the backbone of the project. Cases 1-4 short **and extended**, status words, MF/DF/EF, FCI/FCP templates, BER-TLV, SELECT / READ BINARY / UPDATE BINARY, GET RESPONSE / 61XX. Extended `Lc` is capped at 1 KB by a documented ceiling, not at 65535 -- see M2b. Command chaining, secure messaging and logical channels are refused with the specific status word for each (6884 / 6882 / 6881) rather than a blanket 6E00. |
| Administrative commands | **ISO/IEC 7816-9** | CREATE FILE, DELETE FILE, ACTIVATE / DEACTIVATE, life cycle | CREATE FILE and DELETE FILE done (M2b), with one documented deviation: we do not select the newly created file. ACTIVATE/DEACTIVATE FILE not yet. |
| Data objects | **ISO/IEC 7816-5 / -6** | application identifiers (AID), interindustry data elements | not implemented. SELECT by DF name (P1=04) returns 6A81 and is deferred to M7, where AIDs first mean something. |
| Cryptographic data | **ISO/IEC 7816-15** | cryptographic information application, key and certificate objects | not started. Depends on M5. |
| Multi-application OS | **GlobalPlatform Card Specification** | application load / install / delete, Security Domains, life cycle, SCP secure channels | not started. M7. **No compliance will be claimed** -- see the standing rule below. |
| Secure application runtime | **Java Card** | the VM, API and applet model | deliberately NOT the first target. The native applet interface comes first (M6) so that isolation is understood before a VM is added. |
| Security evaluation | **Common Criteria** | formal security evaluation and certification | out of scope for a software project. Relevant because it dictates what evidence a real product must produce -- which is why docs/threat-model.md names a test for every mitigation. |
| Contactless | **ISO/IEC 14443** | proximity card communication | not implemented and not planned before hardware. It is a link layer; the HAL is where it would attach, and `hal_card_send/receive` already hides the difference. |
| Banking | **EMV** | payment application and transaction requirements | **will not be implemented merely because it exists.** A payment applet is an application on top of a card OS, not part of one. |
| SIM / UICC | **ETSI TS 102 221 / 223 / 225 / 226** | UICC architecture, APDUs, telecom security, OTA | not implemented. 102 221 is the most realistic first *application* profile for this OS, since it is ISO 7816-4 plus a defined file tree, and needs no new crypto. A candidate for M8. |
| Authentication tokens | **FIDO**, GlobalPlatform configurations | secure-element authentication use cases | not started. Needs M5 (ECC) and M6 (applets) first. |

### Two honest notes on the table above

**ISO/IEC 7816-3 is only partly honoured, and that is the biggest gap.** The
ATR we emit is structurally valid and documented byte by byte in
docs/simulator.md, but there is no T=0 or T=1 state machine: no TPDU
segmentation, no procedure bytes, no NAD/PCB/LEN framing, no block
retransmission, no guard-time or waiting-time handling. Those live below
`hal_card_send/receive` on purpose -- on a real card the interface block
implements them in hardware -- but it means **no reader driver has ever spoken
to this OS**, and a PC/SC reader would not work today. The first thing real
hardware will test is exactly this layer.

**"Follows" is not "complies with".** Reading a specification and implementing
what it says is not the same as being verified against it, and neither is the
same as certification. This project claims the first only. Where a deviation is
deliberate it is stated at the point of the code -- for example CREATE FILE not
selecting the created file, or SELECT's fixed and documented search order,
which ISO leaves to the card.

## Standing rules

* No invented protocol semantics. If it is not in the specification, it is not
  implemented.
* No compliance claim without verification against the actual document. The
  standards table above says "follows", never "complies with" -- and
  GlobalPlatform work stays labelled "GlobalPlatform-inspired prototype" until
  checked against the real specification.
* Every threat-model mitigation names its test.
* Nothing hardware-specific is written for hardware whose documentation has not
  been read.
* A test that fails is reported, never skipped.
