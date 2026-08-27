# Fuzzing

Every byte a smart card receives is chosen by whoever holds the reader. The
APDU parser, the TLV parser and the boot loader are all fed exclusively by an
adversary, so they are the parts most worth attacking on purpose.

## What this is, and what it is not

**It is randomised stress testing, run under AddressSanitizer and
UndefinedBehaviorSanitizer. It is not coverage-guided fuzzing.**

The driver in `tests/fuzz/fuzz_driver.c` has no feedback loop: it generates
inputs, it does not learn from them. That finds shallow bugs efficiently and
deep ones only by luck. Calling it "fuzzing" without this paragraph would
oversell it.

The targets are written to libFuzzer's shape so that gap can be closed with
three lines and a `clang -fsanitize=fuzzer` build:

```c
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return scos_fuzz_apdu(d, n); }
```

## Targets

| Target | Under attack | Key invariant |
|---|---|---|
| `apdu` | `apdu_parse()` | never reads outside the buffer; output zeroed on every failure path |
| `tlv` | `tlv_next()`, `tlv_find()` | any `TLV_OK` describes a value inside the buffer; a reader is exhausted on error so callers cannot spin |
| `command` | the full dispatcher on a live card | SW1 is always `6x` or `9x`; the MF descriptor in slot 0 is never damaged |
| `fs_image` | `fs_init()` over a corrupted descriptor region | mounts or reports corruption; never auto-repairs, never faults |
| `boot` | the boot loader, as a *sequence* of commands | **an ACTIVE slot can never be a lie** |
| `fcp` | CREATE FILE / DELETE FILE, biased toward templates that parse | **no two EFs' data ranges overlap**; no orphans, no duplicate FID or SFI within a parent |

## Running them

```sh
ctest --test-dir build -R fuzz          # the CI runs: 20000 inputs, seed 1
./build/fuzz_driver apdu 5000000 12345  # a longer hunt
./build/fuzz_driver boot --file crash   # replay one saved input
```

The seed is fixed in CI so a failure is reproducible from the log line alone.

Each target starts from a fixed hostile corpus — the cases from the project
spec plus every off-by-one around `Lc`/`Le`, the extended-length marker, and
the ISO padding bytes — and then generates. The corpus runs first so a
regression in a known case fails immediately rather than after ten thousand
random inputs.

## Why `fcp` exists when `command` already emits INS E0

`fuzz_command` does send CREATE FILE -- `0xE0` and `0xE4` are in its
instruction list. But its data fields are random bytes, and random bytes
essentially never form a valid BER-TLV FCP template, so it hammers the parser's
reject paths and almost never reaches `fs_create_file()` at all.

That gap would have gone unnoticed if "the fuzzer covers CREATE FILE" had been
left as an assumption. It was checked instead: instrumenting a run showed
**279,207 successful CREATE FILEs out of 1,052,357 commands, a 27% success
rate** for `fcp`. If `build_create()` is ever changed, re-measure -- a template
generator that quietly stops producing valid templates turns the target into a
slower copy of `fuzz_command`.

What `fcp` asserts is not status words but **tree invariants**, because a bug in
a mutating command does not produce a wrong answer. It produces a card whose
structure is quietly wrong and stays wrong across every later power-on. The one
that matters most:

> No two elementary files' data ranges overlap.

An allocator bug there means writing file A silently corrupts file B, and
nothing in the APDU interface would ever report it. The target also drives
UPDATE BINARY between creates, so the invariant is not merely bookkeeping --
if two EFs did overlap, the writes would prove it.

It runs at 3000 iterations in CI rather than 20000: re-personalising a card per
input and re-walking all 32 descriptors after every command is O(n^2), which is
the point, and it is an order of magnitude slower than the others.

## Why the `boot` target is shaped differently

The others take one input and parse it. `boot` treats its input as a sequence
of length-prefixed commands:

```
[len][len bytes of APDU][len][len bytes of APDU]...
```

Because the bugs worth finding in a loader are *ordering* bugs: LOAD after
ACTIVATE, VERIFY over a half-erased slot, ERASE between two blocks. A
single-command target cannot reach them.

It also plants 64-byte guard bands either side of both flash regions and checks
them after every command. ASan would catch a wild pointer, but a one-byte
overrun into adjacent *valid* memory would otherwise pass silently — and this
is code that ships in mask ROM.

The central assertion is worth stating in full, because it is the property the
reset path stakes the whole card on:

> If `boot_slot_check()` reports `ACTIVE`, then the header's length is in
> range, the image's CRC really matches, and the image's first two words really
> are a plausible ARMv7-M vector table.

If any sequence of commands can make that report a lie, the card is brickable
by a hostile reader.

## Findings so far

Nothing from the random driver yet. The bugs found during this work came from
the **exhaustive** sweep and from ordinary unit tests:

* `test_tlv.c` walks all 16,777,216 possible three-byte inputs and asserts any
  `TLV_OK` result points inside the buffer. It reported 4 failures, which
  turned out to be **wrong test data** — an FCP template declaring outer length
  `0x0A` for 11 bytes of content. The parser was right; the test and a doc
  comment in `tlv.h` were wrong. Both fixed.
* Three failures in the first run of `test_boot_loader.c` were likewise my test
  data, not the code: an entry point at offset `0x40` in a 64-byte image
  (legitimately out of bounds), a corruption using `&= 0xFE` on a byte whose
  bit 0 was already clear (a no-op that corrupted nothing), and an expectation
  that rewriting a block with *identical* data should fail — which real flash
  permits, so the loader permits it too.

Recording these rather than quietly fixing them is the point. A test suite that
has never accused the code wrongly is a test suite that is not being pushed
hard enough, and a "failure" that turns out to be bad test data is still
information about which of the two you trust.

## Gaps

* No coverage-guided run has ever been done. That is the single highest-value
  next step and it needs a clang build.
* No corpus is persisted between runs, so nothing accumulates.
* The `command` target drives a card whose filesystem starts from the factory
  layout every time; it never explores a card that has been running for a
  while. Transactions (M4) will make that worth fixing.
* Nothing fuzzes the *transport* — malformed hex lines, absurdly long lines,
  split frames. The transport is HAL-side, so a bug there is a simulator bug
  rather than an OS bug, but on a real card the link layer is attacker-facing
  too.
