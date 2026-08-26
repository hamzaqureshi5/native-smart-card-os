# smartcard-os

A smart-card operating system written from scratch in C, developed against a
**software simulator of smart-card hardware** so that it can be built and tested
on a PC with no card hardware of any kind.

The architecture is designed so the simulated hardware layer can later be
replaced by a real secure MCU without rewriting the OS.

> **Status: Milestone 1 complete.** HAL, simulator HAL, kernel skeleton, APDU
> parser and dispatcher, the simulator executable, one command (SELECT), and an
> automated test suite. No filesystem, cryptography, applets, secure messaging
> or hardware support yet -- see `docs/roadmap.md`.

## Quick start

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Then talk to the card:

```sh
$ ./build/smartcard-sim
SmartCard OS Simulator
Version: 0.1.0

RAM:     16 KB   (budget; not enforced at run time)
ROM:     32 KB   (budget; checked against the build)
EEPROM:  16 KB   page 4 B
FLASH:   256 KB   page 256 B
State:   (volatile, RAM-backed)
ATR:     3B 94 11 00 53 43 4F 53

Waiting for APDU...
00 A4 00 00 02 3F 00
9000
```

That command is `SELECT` of the Master File, and `9000` is ISO 7816-4 for
success. Type `.help` for the control commands, `.quit` to power down.

## Running it -- the four ways

### 1. Interactively

```sh
./build/smartcard-sim
```

Type APDUs as hex; spaces are ignored. Lines beginning with `.` are simulator
controls rather than card traffic, because they model things a reader does to
the card *electrically*, which have no APDU:

| Line | Meaning |
|---|---|
| `00 A4 00 00 02 3F 00` | send a command APDU |
| `.atr` | print the Answer To Reset |
| `.reset` | warm reset -- clears volatile state, keeps NVM |
| `.quit` | power down and exit |
| `.help` | list controls |
| `# ...` | comment |

Responses go to **stdout**; the banner and diagnostics go to **stderr**. That
split is what lets a test client read stdout as a clean response stream.

### 2. Piped (scripting)

```sh
printf '00A40000023F00\n' | ./build/smartcard-sim --quiet
# 9000

printf '00A40000023F00\n.atr\n00EE0000\n' | ./build/smartcard-sim --quiet
```

### 3. With `cardctl`

```sh
export SMARTCARD_SIM=$PWD/build/smartcard-sim

$ ./tools/cardctl/cardctl 00A40000023F00
> 00 A4 00 00 02 3F 00
< 90 00

$ ./tools/cardctl/cardctl --atr 00A40000023F00 00A4000002DEAD
3B 94 11 00 53 43 4F 53
> 00 A4 00 00 02 3F 00
< 90 00
> 00 A4 00 00 02 DE AD
< 6A 82
```

Exit status is 0 only if every APDU returned 9000, so `cardctl` works in a shell
script or CI check.

### 4. From Python

```python
import sys; sys.path.insert(0, "tests/python")
from scos import SmartCard

with SmartCard() as card:                      # powers up, powers down
    r = card.send_apdu("00A40000023F00")
    assert r.sw == 0x9000
    print(r)                                   # 9000

    print(card.atr().hex())                    # 3b94110053434f53
    card.reset()                               # warm reset
    print(card.select(0x3F00).ok)              # True
```

`SmartCard` plays the part a physical reader plays. When real hardware arrives,
only the transport inside `tests/python/scos/card.py` changes -- swap the
subprocess pipe for `pyscard` against a PC/SC reader -- and every test written
against it keeps working.

## Simulator options

```
--state-dir DIR   persist virtual EEPROM/FLASH in DIR
                  (default: none -- NVM is volatile, which is what tests want)
--eeprom BYTES    usable EEPROM size
--flash BYTES     usable FLASH size
--seed N          PRNG seed, for reproducible runs
--quiet           suppress the banner
--help
```

With `--state-dir`, the virtual chip's memory is written to
`DIR/card_eeprom.bin` and `DIR/card_flash.bin` at power-down and reloaded at
power-up. The OS never sees a file: it goes through `hal_nvm_*`, so the same code
runs against real NVM later.

## Build options

| Option | Default | Purpose |
|---|---|---|
| `SCOS_HAL` | `simulator` | HAL implementation: `simulator` or `samsung` |
| `SCOS_SANITIZE` | `ON` | AddressSanitizer + UndefinedBehaviorSanitizer |
| `SCOS_WERROR` | `ON` | warnings are errors |
| `SCOS_STATIC_ANALYSIS` | `OFF` | GCC `-fanalyzer` |
| `SCOS_SIM_RAM_KB` | 16 | virtual RAM |
| `SCOS_SIM_ROM_KB` | 32 | virtual ROM (the code-size budget) |
| `SCOS_SIM_EEPROM_KB` | 16 | virtual EEPROM |
| `SCOS_SIM_FLASH_KB` | 256 | virtual FLASH |

The memory sizes are **simulator defaults**. They are plausible for a secure
MCU; they do not describe any specific real part.

A release build additionally runs the ROM-budget check, which is disabled under
sanitizers because instrumentation inflates code size several-fold:

```sh
cmake -S . -B build-rel -DCMAKE_BUILD_TYPE=Release -DSCOS_SANITIZE=OFF
cmake --build build-rel -j && ctest --test-dir build-rel --output-on-failure
```

## The architectural rule

**The OS core depends on `include/hal/hal.h` and nothing else.** Not libc, not
the host OS, not sockets, not files, not `malloc`.

This is machine-checked, not aspirational. The `core_no_host_deps` test runs
`nm` over `libscos_core.a` and fails the build on any symbol that is not a HAL
function, one of the core's own, or a compiler-emitted memory intrinsic. Today
the core's complete external dependency list is:

```
hal_card_receive
hal_card_send
```

That bounded surface is what makes a hardware port a known quantity rather than
a rewrite.

```
                       Card OS
                          |
                         HAL          <- include/hal/hal.h, the contract
              +-----------+-----------+
              |                       |
        Simulator HAL           Samsung HAL
              |                       |
             PC                 real secure MCU
```

Selection is at link time (`-DSCOS_HAL=...`), not through function pointers: a
writable dispatch table in RAM is both overhead and an attack surface on a chip
where one write primitive should not become control-flow hijacking.

## Layout

```
include/hal/hal.h     the contract -- the most important file here
include/hal/sim/      virtual-chip internals (simulator only)
src/kernel/           kernel; card_loop.c is the only core file touching the HAL
src/apdu/             parser, dispatcher, response builder, SELECT
src/hal/simulator/    HAL over the virtual chip
src/hal/samsung/      placeholder -- contains no Samsung-specific code
simulator/            virtual chip, transport, main()
tests/unit/           core tests (link no HAL) + HAL contract tests
tests/integration/    layering and budget guards
tests/python/         reader-side integration tests
tools/cardctl/        command-line APDU tool
docs/                 architecture, APDU, threat model, roadmap, ...
```

## Test suite

| Test | What it covers |
|---|---|
| `test_apdu_parse` | the four ISO cases, malformed input, an exhaustive length sweep |
| `test_select` | SELECT, dispatch, validation order, lifecycle, robustness |
| `test_os_mem` | bounds-checked copy, constant-time compare |
| `test_hal_sim` | the `hal.h` **contract** -- should pass against real hardware too |
| `core_no_host_deps` | the layering rule |
| `os_fits_in_rom` | code size against the ROM budget |
| `python_integration` | the real binary over its real transport |

116,429 assertions in the C tests, all under ASan + UBSan with
`halt_on_error=1`.

## Documentation

Start with `docs/architecture.md`. `docs/apdu.md` is a tutorial on APDUs if the
protocol is new to you. `docs/hardware-port.md` is the checklist for moving to
real silicon. `docs/roadmap.md` says what is done and what is next.

## On Samsung hardware

`src/hal/samsung/` exists and is **deliberately unimplemented**. It contains no
register addresses, no memory map, no boot sequence, no crypto peripheral
interface -- nothing derived from any Samsung documentation, because no such
documentation has been consulted. Every function returns
`HAL_ERR_UNSUPPORTED`, and the file refuses to compile without an explicit
acknowledgement flag, because a HAL that quietly returns plausible values is
far more dangerous than one that will not build.

Its purpose is to prove the seam is real: it is a second, independent
implementation of `hal.h`, and the OS links against it cleanly.

## Standards

Implemented against ISO/IEC 7816-4 (APDUs, status words, SELECT) and 7816-3
(ATR structure). No status word is invented, and none is reused for a
non-standard meaning.

Referenced but **not** implemented, and not claimed: ISO/IEC 14443,
GlobalPlatform, SCP03, SCP11, Java Card, Common Criteria, EMV. Where such work
begins it will be built from the actual specifications and their published test
vectors -- see `docs/roadmap.md`.

## License

MIT. See `LICENSE`.
