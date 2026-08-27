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

## GET RESPONSE and 61XX

`GET RESPONSE` is not a feature. It is a workaround for T=0, and knowing that
is the difference between implementing it and cargo-culting it.

T=0 is half-duplex and byte-oriented: the reader must state in advance how many
bytes it will accept. So a **Case 3** command -- header plus data, no Le -- has
no channel on which to return anything. If `SELECT` wants to hand back a file's
control information and the reader never sent an Le, the bytes simply cannot go
anywhere.

ISO/IEC 7816-4's answer is a two-step:

```
-> 00 A4 00 00 02 3F 00          Case 3 SELECT, no Le
<- 61 0C                         "I have 12 bytes for you"
-> 00 C0 00 00 0C                GET RESPONSE, Le = 12
<- 6F 0A 82 01 38 83 02 3F 00 8A 01 05   90 00
```

With an Le present the card just returns the data, and no `61XX` is involved:

```
-> 00 A4 00 00 02 3F 00 00       Case 4, Le = 0 meaning 256
<- 6F 0A 82 01 38 ... 90 00
```

T=1 has no such limitation, which is why a T=1-only card can omit the command
entirely.

### The rules that matter

| Situation | Answer | Why |
|---|---|---|
| Nothing pending | `6985` | The instruction *is* supported; the **sequence** is wrong. `6D00` would tell a reader to stop trying it for good. |
| Any other command ran first | data discarded, then `6985` | ISO requires GET RESPONSE to immediately follow its `61XX`. A card that kept the data would let a later command collect an earlier one's output. |
| A malformed frame arrived | data **kept** | It never reached a handler, so no command intervened. Dropping it would make GET RESPONSE unusable on a noisy link. |
| Le smaller than pending | that many bytes + a fresh `61XX` | The reader may collect in chunks. |
| Le larger than pending | `6CXX`, nothing consumed | Names the exact length so the retry succeeds first time. Returning fewer bytes with `9000` would silently change the length contract. |
| Card reset | data discarded | A reset clears all volatile state. |

### `61XX` is a success status

Worth stating on its own, because getting it wrong is easy and the symptom is
subtle. `61XX` means **the command executed** and its output is waiting.
`6CXX` means the command did **not** execute. So a `SELECT` answering `61XX`
must commit its selection, and one answering `6CXX` must not.

Conflating the two was a real bug here: a Case 3 `SELECT` staged its FCI,
returned `61XX`, and left the previous selection in place -- so the card
described one file and would have read another.
