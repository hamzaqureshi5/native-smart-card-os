# The simulator

## What it is

A model of smart-card hardware, sufficient to run a real card OS against.

    +-------------------------------------------+
    |  simulator/main.c                         |  argument parsing, the card's
    |    static scos_kernel s_card;             |  RAM (allocated ONCE, no heap)
    +-------------------------------------------+
    |  simulator/transport.c                    |  hal_card_send / _receive
    |    line-oriented hex over stdin/stdout    |  the "reader link"
    +-------------------------------------------+
    |  simulator/virtual_card.c                 |  the pretend silicon:
    |    EEPROM/FLASH arrays, power state,      |  memory, persistence, ATR
    |    backing store, PRNG, ATR              |
    +-------------------------------------------+
    |  src/hal/simulator/*.c                    |  thin adapters onto hal.h
    +-------------------------------------------+

## What a simulator can and cannot model

Being honest about this is the difference between a useful tool and a
false sense of security.

### Faithfully modelled

* **Memory geometry** -- region sizes, page sizes, and the distinction between
  byte-writable EEPROM and page-erased flash. This shapes the filesystem and
  the transaction design, so getting it right matters more than it looks.
* **The erased state.** Fresh NVM reads as `0xFF`, as real flash and EEPROM do.
  Filesystem code that treats `FF` as "free" behaves identically on hardware.
* **Protocol behaviour** -- every APDU, every status word, every state machine.
* **Persistence across power cycles**, including loss of RAM.
* **Torn writes and interrupted transactions** (from Milestone 4, via a
  fault-injection hook in `hal_nvm_write`).
* **All OS logic** -- filesystem, PIN handling, access conditions, applet
  isolation rules, card lifecycle. This is the large majority of a card OS,
  which is why the approach works at all.

### Not modelled, and not modellable in software

* **Timing.** `hal_timer_get_ms()` returns host time. Real NVM writes take
  milliseconds; crypto takes longer. Nothing here reflects real performance.
* **Power and EM emissions.** Simple power analysis, differential power
  analysis, EM probing -- invisible to a simulator by construction.
* **Fault injection.** Voltage glitching, clock glitching, laser fault
  injection. The *software* consequences can be simulated (see M4), but neither
  the attack nor the hardware's sensor response can be.
* **Memory encryption and integrity.** Real secure MCUs encrypt RAM and NVM with
  per-chip keys and detect tampering in hardware.
* **Randomness.** The simulator PRNG is a **seeded xorshift**, deterministic on
  purpose so tests reproduce. That makes it worthless for security: anyone who
  learns the seed predicts every nonce and key the card will produce. **No
  security property that depends on unpredictability can be validated here.**
* **Tamper detection.** Light, voltage, temperature and glitch sensors, and the
  active shield.

The rule this project follows: **the simulator validates logic; silicon
validates resistance.** Where a claim needs hardware, `docs/threat-model.md`
records it in the "Hardware dependency" column rather than pretending otherwise.

## Virtual memory

| Region | Default | Page | Character | Used for |
|---|---|---|---|---|
| RAM | 16 KB | -- | volatile | the `scos_kernel` struct |
| ROM | 32 KB | -- | read-only | OS code (a build-time budget) |
| EEPROM | 16 KB | 4 B | byte-writable, high endurance | OS metadata, counters, journal |
| FLASH | 256 KB | 256 B | page-erased, lower endurance | file contents |

All configurable at configure time (`-DSCOS_SIM_FLASH_KB=512`), and the usable
sizes are overridable at run time (`--flash 65536`) up to the compile-time
capacity.

**These are simulator defaults. They are plausible for a secure MCU; they
describe no specific real part.** Page sizes especially: a real port must read
them out of a datasheet.

Why the EEPROM/FLASH split is worth modelling: a PIN retry counter *must* be
decremented before the PIN is checked and must survive power loss at any
instant. Byte-writable, high-endurance memory makes that straightforward.
Doing the same thing in page-erased flash requires a wear-levelling scheme, and
getting it wrong produces a card whose retry counter can be reset by cutting
power at the right moment -- a real and repeatedly-exploited class of attack.

### Persistence

With `--state-dir DIR`, NVM is loaded from `DIR/card_{eeprom,flash}.bin` at
power-up and written back at power-down. Without it, NVM lives in RAM and
vanishes -- the default, so tests are hermetic.

**The OS never sees a file.** It calls `hal_nvm_read`/`hal_nvm_write`/
`hal_nvm_sync`. Files exist only inside `virtual_card.c`.

## The transport

Real ISO/IEC 7816-3 is a character protocol: T=0 echoes a procedure byte per
data byte, with guard times, parity and a NAK/retry mechanism; T=1 is
block-oriented with an epilogue checksum. Neither is implemented, because both
carry the same APDU and the OS above `hal_card_*` cannot tell the difference by
design.

So the simulator uses line-oriented ASCII hex, which buys something real: a
human can drive the card by typing, and a test can drive it in two lines.

    -> 00A40000023F00      command APDU, hex, whitespace ignored
    <- 9000                response APDU, hex

Malformed hex is a **transport** error, not a card error: it is reported on
stderr and the OS never sees it. On real hardware the link layer would reject
such a frame, so answering it with a status word would teach the test client
something false about the card. Verified by
`test_malformed_hex_is_a_transport_error_not_a_card_response`.

## The ATR

    3B 94 11 00 53 43 4F 53

**Answer To Reset**: the first thing a card says when powered, before any
command. It advertises the electrical conventions and protocols the card
supports, so the reader knows how to talk to it. Byte by byte:

| Byte | Name | Meaning |
|---|---|---|
| `3B` | TS | direct convention (bit order and polarity of the encoding) |
| `94` | T0 | `Y1=1001` -> TA1 and TD1 present; `K=4` -> four historical bytes |
| `11` | TA1 | `FI=1` (F=372, f_max 5 MHz), `DI=1` (D=1) -- the ISO default rate |
| `00` | TD1 | `Y2=0` -> no further interface bytes; `T=0` -> character protocol |
| `53 43 4F 53` | historical | ASCII `"SCOS"` |

TCK (the check byte) is correctly **absent**: ISO/IEC 7816-3 requires it only
when a protocol other than T=0 is indicated.

### The historical bytes are the only part we actually chose

Everything before them is dictated by hardware: TS by the interface block's
encoding, TA1 by the real clock and timing capability, TD1 by which protocols
the interface block implements. On silicon the ATR is clocked out *before any OS
code runs*, which is why `hal_card_atr()` lives in the HAL -- the OS receives
this fact about its platform rather than producing it.

The historical bytes are ours. Note what ours are **not**: ISO/IEC 7816-4 gives
the first historical byte as a *category indicator*, where `00` or `80`
introduces COMPACT-TLV encoded card service data, card capabilities and
lifecycle information. Our first byte is `53` (`'S'`), which falls in the
"proprietary format" range. That is legal, and it is also an admission: these
four bytes are a human-readable label carrying no machine-readable meaning.

Structured historical bytes are a real design task, deferred to M7 (Card
Manager) because there is nothing worth advertising until there are capabilities
and a lifecycle to advertise. Doing it earlier would mean inventing claims about
a card that cannot yet back them.

### EF.ATR

ISO/IEC 7816-4 defines file identifier `2F01` (EF.ATR) under the MF for the
information that does not fit in the ATR's ~15 historical bytes. That file *is*
the OS's responsibility, and it is a natural M2 candidate once a filesystem
exists.

**This ATR describes this simulator.** It is not any real card's ATR, it does
not represent any Samsung product, and it must not be copied onto real hardware,
where these values have to be derived from the actual clock, guard times and
supported protocols.

Note the honest gap: the ATR advertises T=0, but the simulator implements no
T=0 character framing at all -- it moves whole APDUs over a pipe. The protocol
byte is a statement of intent, not an emulated link layer.

`test_atr_is_well_formed` checks the internal consistency that *is* meaningful:
TS is a legal convention byte, the length is within the ISO maximum of 33, and
T0's historical-byte count matches the bytes actually present.

## Power lifecycle

Implemented in Milestone 1:

| Event | Effect |
|---|---|
| power on | load NVM, seed the PRNG, `scos_init()` -> OPERATIONAL |
| warm reset (`.reset`) | clear volatile state, keep NVM, re-emit the ATR |
| power off (`.quit`, EOF) | flush NVM durably, exit 0 |

`vcard_power_failure()` differs from power-off in exactly the way that
matters: it **skips the durability flush**, so unflushed writes are lost. And
`vcard_fault_after_bytes(n)` makes the next `hal_nvm_write()` store `n` bytes
and then report `HAL_ERR_POWER` -- the bytes before the cut are **real and stay
in the array**, because that is what a half-programmed page looks like. The OS
has to recover from partial data, not from an untouched region.

Together they are what makes tear resistance measurable rather than asserted.
Without the byte-level cut, an interruption test can only check offset 0 and
offset N, which is close to checking nothing;
`tests/unit/test_journal.c` cuts CREATE FILE and UPDATE BINARY at **every**
byte offset.

Two limits worth stating. This model discards the whole session's unflushed
writes where a real chip loses only the write in flight, which makes it
**stricter** than the hardware -- the safe direction for a test, but a pass
here is not a substitute for silicon. And fault injection is simulator-only, so
the ARM target runs the same OS code and cannot cut a write mid-flight; an ARM
equivalent needs the hook in `hal_arm_nvm.c`.
