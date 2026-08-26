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

## M2b -- Dynamic filesystem :: NEXT

**Why split from M2a:** `CREATE FILE` needs a BER-TLV parser to read FCP
templates. That is a second untrusted-input parser and deserves its own tests
and fuzz targets rather than being tacked onto a working milestone.

* **BER-TLV parser** -- tag, length (short and long form), value; bounded,
  no recursion. A fuzz target from the start.
* `CREATE FILE` (E0) from an FCP template; `DELETE FILE` (E4)
* refuse deleting a non-empty DF (safer than a recursive delete that cannot be
  rolled back before M4)
* `GET RESPONSE` (C0) and `61XX`, so a Case 3 SELECT can return its FCI
* extended APDUs -- parsing, buffers, and the 65535-byte bounds
* EF.ATR (`2F01`)
* **fuzzing**: APDU parser, TLV parser, filesystem metadata, descriptor images

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

## Standing rules

* No invented protocol semantics. If it is not in the specification, it is not
  implemented.
* No compliance claim without verification against the actual document.
* Every threat-model mitigation names its test.
* Nothing hardware-specific is written for hardware whose documentation has not
  been read.
* A test that fails is reported, never skipped.
