# APDUs

## What is an APDU?

**Application Protocol Data Unit** -- the only way anything talks to a smart
card. There is no other interface. No shell, no network stack, no file API. A
reader sends a command APDU, the card sends back a response APDU. That is the
entire external surface of the device.

Two consequences worth absorbing early:

1. **The card is passive.** It cannot initiate anything. It has no power until a
   reader gives it some, so it cannot poll, retry on its own schedule, or run a
   background task. Everything it does is a reply.
2. **The APDU parser is the attack surface.** Every byte arrives from a device
   you do not control. `src/apdu/apdu_parse.c` is the most heavily tested file
   in the project for that reason.

## Command APDU structure

    CLA INS P1 P2 [Lc] [ data ... ] [Le]
    \____ header ___/  \______ body ______/
         4 bytes         shape varies

| Field | Meaning |
|---|---|
| CLA | class: which command family, plus channel / secure-messaging / chaining bits |
| INS | instruction: *which* command (A4 = SELECT, B0 = READ BINARY, ...) |
| P1 P2 | parameters, meaning defined per instruction |
| Lc | length of the command data field, 1..255 (short form) |
| data | Lc bytes sent *to* the card |
| Le | length expected *from* the card, 1..256 (short form) |

## The four cases

Because Lc and Le are each optional, a command APDU has four possible shapes.
ISO/IEC 7816-4 names them:

| Case | Length | Data in | Data out | Example |
|---|---|---|---|---|
| 1 | 4 | no | no | `00 A4 00 00` |
| 2 | 5 | no | up to Le | `00 B0 00 00 08` |
| 3 | 5 + Lc | Lc bytes | no | `00 A4 00 00 02 3F 00` |
| 4 | 6 + Lc | Lc bytes | up to Le | `00 A4 04 00 02 3F 00 10` |

### Trap 1: at five bytes, byte 5 is Le -- not Lc

This is the classic smart-card parser bug.

    00 B0 00 00 08     <- Case 2. Le = 8. "Return 8 bytes."
                          NOT "Lc = 8" with a missing data field.

Why: a command with zero data bytes is by definition Case 1 or Case 2, so `Lc =
0` is not encodable. The standard therefore assigns the fifth byte to Le. Get
this backwards and every Case 2 command is misread.

Pinned by `case2_le_only` and `case2_le_zero_means_256` in
`tests/unit/test_apdu_parse.c`.

### Trap 2: Le = 0 means 256

    00 B0 00 00 00     <- "give me up to 256 bytes", not "give me nothing"

256 does not fit in one byte, so zero is reused to mean the maximum. Asking for
nothing would be pointless, so no meaning is lost. `apdu_parse()` normalises
this: callers see `le == 256` and never have to remember the rule.

### Trap 3: Lc = 0 with more bytes following is the *extended* encoding

    00 A4 00 00 00 00 02 3F 00
                 ^^^^^^^^ extended Lc: 00 followed by a 2-byte length

We do not implement extended APDUs yet, so we **detect and refuse** them rather
than misparse them as short. Silently treating an extended APDU as short would
let a caller smuggle in a length that was never validated -- the shape of a real
memory-corruption bug.

The refusal is `6A81` ("function not supported"), not `6700` ("wrong length"):
the length is perfectly well-formed, we simply do not implement the function.
Saying `6700` would be a false statement about the caller's APDU.

## Response APDU

    [ data ... ] SW1 SW2

**A card always answers, and the answer always ends in a status word.** There is
no "no response" -- a reader waiting on a silent card just times out, which is
indistinguishable from a dead card and a terrible failure mode.

This project makes that structural rather than conventional:

* handlers return a status word; the dispatcher writes it (a handler cannot
  forget to)
* the response builder reserves two bytes for SW before accepting any payload,
  so appending SW can never fail
* if a handler produces more data than the buffer holds, the payload is
  discarded and the status becomes `6F00` -- an internal error is reported rather
  than a truncated response returned, because truncation is a correctness lie
* `never_fails_to_answer` (48,785 checks) and the Python
  `test_hostile_inputs_all_get_a_status_word` verify it against junk

## Status words implemented

Values from ISO/IEC 7816-4; see `include/apdu/sw.h` for the full table.

| SW | Meaning | When this card sends it |
|---|---|---|
| 9000 | Success | SELECT of the MF |
| 6700 | Wrong length | APDU shorter than 4 bytes; Lc disagrees with the bytes present |
| 6881 | Logical channel not supported | CLA requests channel != 0 |
| 6882 | Secure messaging not supported | CLA sets the SM bits |
| 6884 | Chaining not supported | CLA sets the chaining bit |
| 6985 | Conditions not satisfied | card is TERMINATED |
| 6A81 | Function not supported | extended APDU; FCP/FMD templates |
| 6A82 | File not found | SELECT of a file identifier we do not have |
| 6A86 | Incorrect P1-P2 | unimplemented selection method; reserved P2 bits set |
| 6A87 | Lc inconsistent with P1-P2 | SELECT with Lc that is neither 0 nor 2 |
| 6D00 | INS not supported | unknown or not-yet-implemented instruction |
| 6E00 | CLA not supported | proprietary class, or FF |

Planned but not yet emitted: `61XX` (more data available, arrives with GET
RESPONSE in M2), `6CXX` (wrong Le, arrives with READ BINARY), `63CX` (verify
failed, X tries left, arrives with VERIFY in M3).

## Parser rules

From `src/apdu/apdu_parse.c`, applied without exception:

* **Validate length before indexing.** Never index and then check.
* **Compute in a wider type.** All length arithmetic is `uint32_t` even though
  the fields are `uint16_t`, so `5 + 255 + 1` cannot wrap anywhere.
* **Zero the output on every failure path.** A caller that ignores the return
  value must not be able to read a half-filled structure. Tested.
* **Copy nothing.** `cmd->data` aliases the caller's receive buffer. One buffer,
  one lifetime, no double-buffering bugs.

`exhaustive_length_consistency` sweeps every (declared Lc, actual length) pair
and asserts the parser accepts exactly the two legal lengths and that the data
field always lies inside the input. Run under ASan, that sweep is also an
out-of-bounds hunt.
