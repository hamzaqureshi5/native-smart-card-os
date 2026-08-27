# Threat model

## Scope and honesty

This document covers **Milestone 1 only**: the HAL, the simulator, the kernel,
the APDU engine and SELECT. It grows with each milestone.

Two rules it follows:

1. Every mitigation claimed here is **implemented and tested**, with the test
   named. Planned mitigations are marked as planned.
2. Where a threat cannot be addressed in software, the "Hardware dependency"
   column says so. A simulator cannot mitigate a power-analysis attack, and
   claiming otherwise would be the most dangerous thing this document could do.

## Assets

| Asset | Why it matters | Exists yet? |
|---|---|---|
| Card lifecycle state | controls whether the card functions at all | yes (RAM only) |
| Selection state | later commands act on the selected file | yes |
| PIN and retry counter | gates all user authentication | M3 |
| Key material | the card's reason to exist | M5 |
| File contents | the data the card protects | M2 |
| Applet code and data | isolation between applications | M6 |
| Transaction journal | integrity of every update | M4 |

## Adversaries

| Adversary | Capability |
|---|---|
| **Malicious reader** | sends arbitrary APDUs, cuts power at any instant, resets at will, replays |
| **Malicious applet** | runs code on-card; tries to escape its sandbox | M6 |
| **Local physical attacker** | holds the chip: power/EM traces, glitching, probing, decapsulation |
| **Compromised host application** | legitimate credentials, hostile intent |

Note the asymmetry that defines this whole field: **the attacker owns the
device.** There is no trusted operator, no network perimeter, no ability to
revoke. Unlike a server, a smart card is designed to be secure while physically
in the hands of the person attacking it.

---

## T1 -- Malformed APDU causes memory corruption

* **Component:** `src/apdu/apdu_parse.c`
* **Attack:** Craft an APDU whose `Lc` claims more data than was sent, or whose
  length arithmetic overflows, so the parser reads or writes out of bounds. The
  classic version: `Lc = 0xFF` with two data bytes.
* **Mitigation (implemented):**
  - length validated before any indexing, never after
  - all length arithmetic in `uint32_t` so `5 + 255 + 1` cannot wrap
  - the parser copies nothing; `cmd->data` aliases the caller's buffer
  - the output structure is zeroed on every failure path, so a caller that
    ignores the status cannot read stale fields
* **Tests:** `reject_lc_longer_than_data`, `reject_lc_shorter_than_data`,
  `reject_too_short`, `exhaustive_length_consistency` (every Lc x length pair,
  under ASan)
* **Residual risk:** Low for short APDUs. Extended APDUs are refused rather than
  parsed, so their risk is deferred, not accepted. Fuzzing (M2) is required
  before this can be called settled.
* **Hardware dependency:** No.

## T2 -- Extended APDU misparsed as short

* **Component:** `apdu_parse()`
* **Attack:** Send `00 A4 00 00 00 00 02 3F 00`. A parser that reads `Lc = 0`
  and then treats the rest as a short APDU processes a length it never
  validated.
* **Mitigation (implemented):** `Lc == 0` with bytes following is explicitly
  identified as the extended encoding and refused with `6A81`. The output is
  zeroed.
* **Test:** `reject_extended_length`,
  `test_extended_apdu_refused_not_misparsed`
* **Residual risk:** None while extended APDUs are unimplemented. When they are
  implemented (M2+), this becomes T1 again with 3-byte lengths and a 65535-byte
  bound -- and needs the same treatment.
* **Hardware dependency:** No.

## T3 -- Card stops answering (denial of service / oracle)

* **Component:** kernel, response builder
* **Attack:** Find an input that makes the card return nothing. A silent card is
  indistinguishable from a dead one, which is a serious failure mode in the
  field; and if silence is reachable for *some* inputs only, silence itself
  becomes an information oracle.
* **Mitigation (implemented):**
  - handlers return a status word and never write one; the dispatcher writes it,
    so a handler cannot omit it
  - the response builder reserves two bytes for SW before accepting payload
  - internal overflow degrades to `6F00` rather than truncating
* **Tests:** `never_fails_to_answer` (48,785 checks over a CLA x INS x length
  sweep, asserting SW1 is always a valid ISO class),
  `test_hostile_inputs_all_get_a_status_word`, `test_card_survives_a_flood`
* **Residual risk:** Low. An infinite loop inside a future handler would still
  hang the card; real hardware also has a watchdog, which the simulator does not
  model.
* **Hardware dependency:** Partial -- a watchdog is a hardware feature.

## T4 -- Status words leak information

* **Component:** kernel validation order, command handlers
* **Attack:** Use the *difference* between error codes to map the card. If
  SELECT of a nonexistent file returns `6A82` but an unsupported selection
  method also returns `6A82`, an attacker cannot tell them apart -- but the
  reverse case is worse: if an unsupported CLA reveals whether the INS inside it
  exists, the attacker enumerates the command set of classes the card does not
  even serve.
* **Mitigation (implemented):**
  - fixed validation order: structure -> class -> instruction -> parameters ->
    security -> execute
  - CLA is validated before INS, so all instructions in an unsupported class
    give an identical answer
  - unimplemented-but-legal selection methods return `6A86` ("incorrect
    parameters"), **not** `6A82` ("file not found"): we never looked for the
    file, and saying otherwise would mislead
* **Tests:** `cla_checked_before_ins`, `select_unsupported_p1_is_6a86`,
  `test_class_diagnostics`
* **Residual risk:** Medium and inherent. ISO status words are *designed* to be
  diagnostic, so some information disclosure is required by the standard. The
  discipline is to leak only what the standard intends. Needs re-examination
  when file access conditions arrive (M3), where "file not found" versus "access
  denied" is a genuine and much-debated design tension.
* **Hardware dependency:** No.

## T5 -- Failed command corrupts state

* **Component:** command handlers
* **Attack:** Send a SELECT that fails late, and hope the card has already
  discarded its previous selection -- clearing a security context with a garbage
  APDU.
* **Mitigation (implemented):** State is committed only after every check
  passes. `scos_cmd_select()` writes `k->selected_fid` as its final act.
* **Tests:** `failed_select_preserves_previous_selection`,
  `select_unknown_file_is_6a82` (asserts no selection was created),
  `test_failed_select_keeps_the_previous_one`
* **Residual risk:** Low now; grows with handler complexity. This is precisely
  what the transaction system (M4) generalises -- validate-then-commit does not
  scale to multi-write commands by discipline alone.
* **Hardware dependency:** No.

## T6 -- Out-of-range NVM access

* **Component:** `src/hal/simulator/hal_sim_nvm.c`
* **Attack:** Reach a HAL call with a hostile offset -- e.g.
  `offset = 0xFFFFFFF0, len = 0x20`, where a naive `offset + len > size` check
  written in `uint32_t` **wraps** and passes.
* **Mitigation (implemented):** Bounds computed in `uint64_t`. Both endpoints of
  every range checked. An undefined region is refused rather than mapped
  somewhere.
* **Test:** `out_of_range_access_is_refused` (includes the wrapping cases, and
  asserts the exact boundary still *succeeds* -- an off-by-one the other way is
  equally a bug)
* **Residual risk:** Low in the simulator. **The real HAL must repeat this
  independently** -- on hardware a bad offset either faults or silently corrupts
  a neighbouring structure that fails a thousand power cycles later.
* **Hardware dependency:** Yes, for the real implementation.

## T7 -- Timing side channel in comparison

* **Component:** `src/kernel/os_mem.c`
* **Attack:** Time a PIN or MAC comparison. An early-exit `memcmp` leaks the
  length of the matching prefix, turning a 10^6-guess search for a 6-digit PIN
  into roughly 60 guesses.
* **Mitigation (implemented):** `os_memeq_ct()` accumulates all differences with
  `|=` and branches once, at the end. The core does not use `memcmp` for
  anything security-relevant -- one reason it provides its own primitives instead
  of including `<string.h>`.
* **Test:** `constant_time_equality_is_correct`, including every single-bit
  difference at every position (an accumulator built with `+` instead of `|`
  could cancel out).
* **Residual risk:** **Substantial, and software cannot close it.** This
  addresses a *remote* timing observer. An attacker holding the chip has power
  and EM traces, cache and branch-predictor effects, and can glitch the
  comparison outright. Constant-time code is necessary and nowhere near
  sufficient.
* **Hardware dependency:** Yes -- needs hardware countermeasures, and the
  compiler must not undo the constant-time property (verifiable only by
  inspecting generated code, which is not yet part of the build).

## T8 -- Weak randomness

* **Component:** `hal_random_bytes()` (simulator)
* **Attack:** Predict challenges, nonces or generated keys.
* **Mitigation:** **NONE, AND NONE IS POSSIBLE HERE.** The simulator uses a
  seeded xorshift PRNG, deliberately deterministic so tests reproduce.
* **Residual risk:** **TOTAL.** Anyone who learns the seed predicts every value
  the card will ever produce. This is documented at the call site, in
  `docs/simulator.md`, and here.
* **Consequence for the project:** No security property depending on
  unpredictability may be validated in the simulator. Only the *logic* around it
  can be. The API is designed so the real implementation can report health-test
  failure (`HAL_ERR_IO`), and callers are written to check -- because a HAL that
  silently substitutes weak entropy for a failed TRNG is how real products ship
  predictable keys.
* **Hardware dependency:** **Yes, absolutely.** Requires a certified TRNG with
  continuous health testing.

## T9 -- Layering violation makes the OS unportable

* **Component:** the build
* **Attack:** Not an attacker -- entropy. Someone adds `#include <stdlib.h>` and
  a `malloc()`. Everything compiles and every functional test passes on a PC.
  The defect surfaces only at the cross-build, where the port becomes a rewrite.
* **Mitigation (implemented):** The `core_no_host_deps` test runs `nm` over
  `libscos_core.a` and fails the build on any symbol that is not a HAL function,
  one of the core's own, or a compiler-emitted memory intrinsic. The core is
  also compiled `-ffreestanding`.
* **Test:** `core_no_host_deps`. It caught a real issue on first run, and the
  linker separately forced `scos_card_loop()` out of `kernel.c` into its own
  translation unit.
* **Residual risk:** Low. The intrinsic allowlist (`memcpy`, `memset`,
  `memmove`, `memcmp`) is a deliberate, documented hole: compilers emit these
  from ordinary struct assignment even under `-ffreestanding`, and every real
  bare-metal target provides them.
* **Hardware dependency:** No.

## T10 -- Power failure corrupts persistent state

* **Component:** NVM, filesystem, transactions
* **Attack:** Cut power during a write. Leave a file half-updated, a PIN counter
  un-decremented (infinite guesses), or filesystem metadata inconsistent.
* **Mitigation:** **NOT YET IMPLEMENTED.** Milestone 4. Today
  `hal_nvm_write()` is an atomic `memcpy` -- the *optimistic* case -- so
  **nothing in this project may currently claim tear-resistance.**
  Groundwork in place: `hal_nvm_sync()` exists as an explicit durability
  barrier, so the OS is written against a device that buffers writes; and the
  EEPROM/FLASH split with distinct page sizes is modelled, because a retry
  counter in page-erased flash is a different and harder problem.
* **Residual risk:** **HIGH and unmitigated.** The most important open item.
* **Hardware dependency:** Yes -- the journal design depends on what a real
  interrupted page program leaves behind, which is a datasheet question.

---

## T11 -- Unauthenticated OS load

**The largest hole in the project as it stands, and it is wide open.**

A blank SCV1 comes up in a boot loader that will accept and activate any image
from anyone. There is no signature, no authentication, and no lock. The CRC-16
in the slot header detects accidental corruption only -- anyone able to drive
the loader can compute a matching CRC in a millisecond.

What an attacker gets: they replace the OS with one that reports PIN success
unconditionally, or that dumps EEPROM through a proprietary APDU, and the card
still answers with a plausible ATR. Every other control in this document is
downstream of the OS being the OS, so this defeats all of them at once.

Made worse by [BOOTSEL](chip-scv1.md#bootsel), which lets an attacker holding
the card put a *working* card back into the loader.

**Mitigated by:** nothing. This is a development target.

**What a real product needs, both of them:**

1. **A signature over the image**, checked before ACTIVATE, against a public
   key in mask ROM. Needs the crypto abstraction, so it waits on M5. Note that
   the check must be over the image *as stored*, after programming, not over
   what arrived on the wire.
2. **A one-way lock**, blown at issuance, that disables the loader permanently.
   This is a fuse or an OTP bit and it cannot be simulated honestly -- software
   can always un-set a variable. Needs real silicon.

Partial hardening that *is* implemented, and is worth being clear is not a
substitute: ACTIVATE is separate from VERIFY, so a card interrupted mid-load
does not boot a partial image; the image CRC and vector table are re-checked on
every reset, so a damaged image stays in the loader rather than faulting; and
the loader refuses to program unerased flash, so it cannot be tricked into
writing the AND of two images.

## T16 -- Unauthorized file access

**Attacker:** anyone who can reach the card with a reader.

**Mitigated as of M3.** Every file carries three access-condition bytes
(read / update / admin) and the five commands that touch files check them,
answering `6982` when the session is not entitled. A condition of `0x1N`
requires PIN reference N to have been verified **in this session**, and the
authentication state is volatile -- so removing power revokes it.

**Two residual holes, both real.**

*A factory card has no protection on its root.* The MF ships with
`ac_admin = ALWAYS`, because a card whose root cannot be written has no way to
receive its first file. Anyone who reaches a card before it is personalised can
create files in the MF, and can therefore create an unprotected file. Real
cards close this by personalising before issuance behind a secure channel to a
security domain -- M7. Until then, an unpersonalised card should be treated as
untrusted.

*Conditions are set at creation and cannot be changed afterwards.* There is no
command to tighten or loosen an existing file's conditions, so a file created
permissively stays permissive. That is safer than the alternative would have
been -- a `CHANGE SECURITY ATTRIBUTES` command is itself an administrative
operation needing its own gate, and getting that wrong would be a way to
unlock every file on the card -- but it means the only route to a correctly
protected file is to create it that way.

**Not mitigated at all:** anything below the command interface. An attacker who
can read or write EEPROM directly bypasses all of this, because the conditions
are bytes in the same EEPROM. That is the chip's memory protection's job and
this project models no chip.

---

## T13 -- PIN recovered from NVM

**Attacker:** anyone who can read the card's EEPROM -- through a debug
interface, a decapsulated die, or a simulator state directory.

**Mitigated in part.** The PIN is never stored; EEPROM holds
`SHA-256(salt || PIN)` and a 16-byte per-reference salt. A unit test scans the
whole EEPROM for the PIN's own bytes and fails if it finds them.

**What this does NOT do, stated plainly.** A 4-digit PIN behind a salted
SHA-256 is ten thousand hashes to an attacker who can read NVM and compute,
which is instant. The salt stops one precomputed table breaking a whole batch;
it does not make a short PIN hard to recover. **The real protection is the
retry counter plus the chip's memory protection, and this project models
neither the chip nor its protection.**

Read the verifier as making casual disclosure ineffective, not as making
offline attack hard. An iterated KDF would raise the cost, and on a 14 MHz core
that cost falls on the cardholder too; that trade needs a real part's timings
before it can be made honestly.

**Depends on hardware:** memory protection, and a real TRNG for the salt --
the simulator's is a seeded PRNG, so cross-card salt uniqueness is a hardware
requirement (see `docs/hardware-port.md`).

---

## T14 -- Retry counter reset by removing power

**Attacker:** anyone holding the card and a reader they control.

**The attack:** present a wrong PIN, and cut power before the card can record
the failure. If the counter comes back, the retry limit is infinite and a
4-digit PIN falls in ten thousand attempts. This is not hypothetical; it has
been used against real products.

**Mitigated.** Three things together, and all three are load-bearing:

1. The counter is decremented and **synced to NVM before the PIN is compared**.
   Every other order is broken -- compare-then-decrement hands the try back on
   exactly this attack.
2. It lives in **byte-writable EEPROM**, so consuming a try is one byte. On
   page-erase flash the smallest write is a page, which would put the salt and
   verifier at risk on every failed attempt.
3. It is a **unary tally**: spending a try clears the lowest set bit, so the
   write is atomic and can only ever *lose* tries. A glitched or partial write
   fails in the safe direction.

The cost is that a power cut during a *correct* attempt loses a try. That is
the right direction to fail.

**Residual risk.** The tally sits outside the record's CRC -- it has to, so it
can change without rewriting its container. A fault that *sets* a bit therefore
gains a try. Setting bits in EEPROM is a harder fault to induce than clearing
them, but the honest statement is: the counter resists **power interruption**
and says nothing about active fault injection.

**Not yet proven.** A power cut in the middle of a verify, between the commit
and the comparison, is untested -- it needs M4's fault-injection hook in
`hal_nvm_write()`. Today's claim is "resists power interruption at command
granularity", not "tear-resistant".

---

## T15 -- PIN replaced instead of guessed

**Attacker:** anyone holding the card and a reader.

**The attack:** ignore the PIN entirely. Use `CHANGE REFERENCE DATA` to set a
PIN you know, then authenticate with it. Every counter, blocked state and
constant-time comparison becomes decoration.

**Mitigated.** Changing an ACTIVE reference requires that reference to have
been verified in this session (`6982` otherwise), and a BLOCKED one cannot be
changed at all (`6983`) -- otherwise exhausting the counter would be a route to
a fresh PIN. Setting an UNSET reference is allowed, because that is initial
personalisation and no credential exists yet to authorise it.

**Residual risk.** A card that has never had a PIN set can have one set by
anyone who reaches it first. Real cards close this by personalising before
issuance, behind a secure channel to a security domain; that is M7.

---

## T12 -- Boot loader bug bricks the part

The loader lives in mask ROM. It cannot be patched after the wafer is made, so
a crash or memory-safety bug in it is not a bug report, it is scrap.

**Mitigated by:**

* the loader logic is **pure** -- it operates on two caller-supplied byte
  regions and knows no addresses, so all of it runs on the host under
  AddressSanitizer (`tests/unit/test_boot_loader.c`, 21 tests);
* a fuzz target drives it as a *sequence* of commands, with guard bands either
  side of both regions, asserting after every command that an ACTIVE slot can
  never be a lie (`tests/fuzz/fuzz_boot.c`);
* it does **not** reuse the OS's ISO 7816-4 parser. That parser is good and
  fuzzed, but linking it would mean the OS's future changes reach into
  unpatchable code. The loader accepts only the two APDU shapes it needs;
* `scv1_boot.ld` fails the link if the loader outgrows its 8 KB.

**Not mitigated:** the jump itself, the VTOR write and the flash driver cannot
be host-tested -- they need the chip. They are covered by QEMU integration
tests, which is weaker than a proof and is the best available.

## Deferred threats

Not addressed because the subsystems do not exist yet. Listed so they are not
forgotten.

| Threat | Milestone | Note |
|---|---|---|
| PIN brute force / lockout | M3 | counter must decrement *before* the check, and survive power loss |
| Retry-counter rollback | M3/M4 | cut power after a failed verify to restore tries -- a real, repeatedly-exploited attack |
| Unauthorized file access | M3 | access conditions per file |
| Replay | M5+ | needs secure messaging (SCP03) and a session counter |
| Key extraction via API | M5 | private keys marked non-exportable; no API path to raw material |
| Malicious applet escape | M6 | **the initial native applet interface provides NO enforced isolation** -- applets are linked C code. To be documented as a known limitation, not a solved problem. Real isolation needs a bytecode VM or an MPU. |
| Unauthorized installation | M7 | Card Manager, security domains |
| Side-channel (power/EM) | hardware | cannot be simulated |
| Fault injection | hardware | software consequences testable (M4); the attack is not |
| Invasive probing | hardware | |
| Signed OS images | M5 | see T11; needs the crypto abstraction first |
| Loader lock bit at issuance | hardware | see T11; software cannot honestly simulate a one-way fuse |

## Notes on what makes this different from software security

Worth stating explicitly, because it drives design choices that look strange
otherwise:

* **The attacker owns the device.** No perimeter, no operator, no revocation.
* **Power is the attacker's to give.** Every algorithm must be correct when
  interrupted at an arbitrary instruction. This is why transactions are an OS
  primitive rather than a library.
* **There is no trusted time.** The card is clocked by the reader. Rate limiting
  by elapsed time is meaningless; PIN limits are *counters in NVM*, because
  counters survive power loss and clocks do not.
* **Physical secrets cannot be rotated.** A key extracted from one card is
  extracted for that card's lifetime, and possibly for a whole product family if
  keys are not diversified per device.
* **Failure must be safe, not graceful.** The correct response to a detected
  attack is to stop -- block the PIN, terminate the card -- not to retry, log and
  continue.
