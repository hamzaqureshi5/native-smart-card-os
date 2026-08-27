# Loading an OS onto a blank chip

This is the factory flow: start with an empty part, program an OS into it over
the card interface, and end up with a card that comes up running that OS on
every power-on.

It only works on the **ARM SCV1 target**. The native `smartcard-sim` cannot do
it, and the reason is worth understanding before you start — see
[Why not the native simulator](#why-not-the-native-simulator) at the end.

## What you need

```sh
arm-none-eabi-gcc --version     # any recent version
qemu-system-arm --version       # 6.0 or later
```

## The short version

```sh
tools/card load        # blank chip -> running OS  (builds the firmware if needed)
tools/card shell       # talk to it
tools/card status      # what is in the OS slot
tools/card recycle     # back to blank
```

That is the whole flow. `tools/card` is a facade over the tools the rest of
this document uses directly -- `mkldr.py`, `load-os.sh`, `run-scv1.sh` -- and
it exists because those three had three different argument shapes, and using a
card meant remembering which took `--state-dir`, which took a positional,
which needed `--boot`, and that piping APDUs into a UART hangs unless the input
ends with `.quit`. Four things to remember to do one thing.

Sending commands:

```sh
$ tools/card apdu 00A40000023F00 00C000000C
> 00A40000023F00
< 610C
> 00C000000C
< 6F0A82013883023F008A01059000
```

`card apdu` exits non-zero if any APDU did not answer `9000` or `61XX`, so it
works in a shell script. It also checks each APDU's length field **before**
sending and says which byte is wrong, because a hand-written `Lc` is wrong
remarkably often and the card can only answer `6700`:

```sh
$ tools/card apdu 00D600000004AABBCCDD
card: 00D600000004AABBCCDD: extended Lc=1194 (0x04AA) so the frame should be
      1201 (Case 3E) or 1203 (Case 4E) bytes, but it is 10
      looks like Lc was written as ONE byte; the extended form needs two
```

Cards live in `cards/<name>/` and persist between invocations, exactly as real
silicon would. `tools/card list` shows them; the name defaults to `default`.

**The rest of this document is the long version**, and it is worth reading
once: `tools/card` hides the steps, and the steps are the interesting part.

## Step 0 — build

Two programs come out of the ARM build, and they are genuinely separate:

```sh
cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
cmake --build build-arm -j
```

| Artefact | What it is | Where it runs |
|---|---|---|
| `build-arm/scv1-boot.bin` | the boot ROM | mask ROM, `0x00000000`, 8 KB |
| `build-arm/smartcard-os.bin` | **the OS** | OS slot, `0x00002000`, 55 KB |

`smartcard-os.bin` is the file you load. It is raw ARM Thumb machine code with
its vector table at offset 0.

## Step 1 — make the loader scripts

```sh
./tools/mkldr.py os build-arm/smartcard-os.bin -o os.ldr
./tools/mkldr.py recycle -o recycle.ldr
```

`os.ldr` is a text file of APDUs, one per line, with `#` comments:

```
$ ./tools/mkldr.py inspect os.ldr
     1  ERASE
   106  LOAD BLOCK
     1  VERIFY
     1  ACTIVATE
     1  GET STATUS
     1  RESTART
 13612  bytes of image data
```

## Step 2 — look at the blank chip first

```sh
mkdir mycard
printf '.atr\n.quit\n' | ./tools/run-scv1.sh --state-dir mycard --boot
```

> **Always end a piped script with `.quit`.** A UART has no end-of-file: when
> your input runs out the card is still powered and still waiting, exactly as a
> real card would be, and QEMU will sit there forever. `.quit` is the
> simulator's stand-in for pulling the card out of the reader.

```
SCV1 BOOT ROM v1  (mask ROM, 8 KB at 0x00000000)
OS slot: 0x00002000  55 KB
State:   BLANK (no OS loaded)
ATR:     3B 94 11 00 42 4F 4F 54
Waiting for loader APDUs (CLA 80)...
3B941100424F4F54
```

The historical bytes are `42 4F 4F 54` — **BOOT**. Nothing is loaded, so the
boot ROM is what is answering.

## Step 3 — load it

```sh
{ cat os.ldr; echo .quit; } | ./tools/run-scv1.sh --state-dir mycard --boot
```

You get 109 × `9000`, then a status record, then the OS takes over:

```
01020000DC000000352C79C58001352C9000
SmartCard OS on SCV1 (ARM Cortex-M3)
OSFLASH 0x00002000  55 KB
ATR: 3B 94 11 00 53 43 4F 53
Started by the SCV1 boot ROM from an ACTIVE OS slot.
Waiting for APDU...
```

Reading that status record, field by field:

| Bytes | Meaning |
|---|---|
| `01` | loader protocol version |
| `02` | slot state — **2 = ACTIVE** |
| `0000DC00` | slot capacity, 56320 bytes |
| `0000352C` | image length, 13612 bytes |
| `79C5` | image CRC-16 |
| `80` | block size, 128 |
| `01` | ERASE was issued this session |
| `352C` | highest offset written |
| `9000` | success |

## Step 4 — power-cycle, and it is still there

```sh
printf '.atr\n00A4000C023F00\n.quit\n' | ./tools/run-scv1.sh --state-dir mycard --boot
```

```
SCV1 BOOT ROM: OS slot ACTIVE, starting OS
SmartCard OS on SCV1 (ARM Cortex-M3)
...
3B94110053434F53
9000
```

No loader script this time. The boot ROM found an ACTIVE slot, checked the CRC
and the vector table, and jumped. The ATR is now `53 43 4F 53` — **SCOS**.

## The easy way, by hand

Steps 1–3 by hand have one sharp edge, and it is worth knowing *why* before
using the shortcut. `tools/load-os.sh` does the whole thing safely:

```sh
./tools/load-os.sh mycard                    # load build-arm/smartcard-os.bin
./tools/load-os.sh mycard other-os.bin       # load a specific image
./tools/load-os.sh --recycle mycard          # erase the slot
```

```
load-os.sh: load smartcard-os.bin -- ok, 111 responses, none refused
  slot  : ACTIVE
  image : 13612 bytes, CRC 79C5
  card  : mycard
```

It differs from doing it by hand in three ways that all came out of getting it
wrong first:

* **It always holds BOOTSEL.** A card whose slot is already ACTIVE boots the OS
  immediately, so a loader script piped at it reaches the *OS*, which answers
  `6E00` to all 110 lines — `CLA 80` is not its class. The card is fine; the
  script went to the wrong program.
* **It checks the answers instead of printing them.** A transcript of 110
  `9000`s is not read by anyone, which is exactly how a failure in the middle
  goes unnoticed. On failure it prints the offending status word and what it
  means.
* **It validates the image before erasing anything.** `ERASE` is the first
  command and it is irreversible.

That last one was a genuine bug in the first version of these tools: `mkldr`
detected that an image was not ARM code, printed three warnings, and the script
erased the card's working OS anyway — the failure only surfaced later, at
`VERIFY`, with `6984`, leaving a blank card. The host knew and destroyed the
card regardless. `mkldr.py os` now refuses:

```
$ ./tools/load-os.sh mycard zeros.bin
mkldr: refusing to build a loader script for zeros.bin:
  - initial SP 0x00000000 is not inside SCV1 SRAM (0x20000000..0x20004000)
  - reset vector 0x00000000 has the Thumb bit clear; ARMv7-M has no ARM state,
    so this would fault immediately

The card would erase its current OS and then reject this image, leaving a blank
card. Pass --force if you really mean it.
```

## Step 5 — recycle it

An ACTIVE card boots the OS immediately, so `recycle.ldr` sent to a working
card reaches the *OS*, which answers `6E00` (wrong CLA) because `CLA 80` is not
its. You have to force the boot ROM to stay put:

```sh
./tools/load-os.sh --recycle mycard
# or, by hand:
{ cat recycle.ldr; echo .quit; } | ./tools/run-scv1.sh --state-dir mycard --boot --bootsel
```

```
State:   ACTIVE
BOOTSEL: held -- staying in the loader
01020000DC00000034E4A257800000009000     <- state 02, before
9000                                     <- ERASE
01000000DC00000000000000800100009000     <- state 00, after
```

`--bootsel` models a strap pin held during reset — BOOT0, RECOV, the name
varies by vendor. Without something like it the part is a one-way door.

## Does the ATR really change?

Yes, on this chip — but **not for the reason people usually assume**, and it is
not an ISO requirement.

ISO/IEC 7816-3 says nothing about an ATR having to change when software is
loaded. What happens here is simpler: the ATR is sent by whatever program is
running, and a blank card is running a different program than a loaded one.

```
blank card   -> boot ROM answers  -> 3B 94 11 00 42 4F 4F 54   "BOOT"
loaded card  -> OS answers        -> 3B 94 11 00 53 43 4F 53   "SCOS"
```

The interface bytes (`3B 94 11 00`) are identical in both, and that is correct:
convention, Fi/Di and programming voltage are properties of the *chip*, not of
the software. Only the historical bytes differ, which is exactly what
historical bytes are for.

On real silicon the ATR is usually clocked out by the interface block from a
configuration register before any application code runs, so "which program is
answering" is decided even earlier. The observable result is the same.

## What the loader does not do

**There is no authentication.** Any reader that can reach a blank SCV1 can load
any image and activate it. The CRC-16 in the slot header detects accidental
corruption; it stops nothing deliberate, because anyone who can drive the
loader can compute a matching CRC.

A production part needs two things this does not have:

1. a signature over the image, checked before ACTIVATE;
2. a one-way fuse blown at issuance that disables the loader permanently.

The first waits on the crypto abstraction (M5). The second needs real silicon.
Both are tracked in [threat-model.md](threat-model.md). Do not read this loader
as a security boundary — it is a programming interface.

## Why not the native simulator

`./build/smartcard-sim` has the OS **compiled into it**:

```
$ nm build/smartcard-sim | grep ' T scos_card_loop'
0000000000019662 T scos_card_loop
```

There is nothing to load, and no honest way to add one. Loading an OS means
writing machine code into flash and jumping to it; the native build's "flash"
is a `uint8_t` array in a Linux process, and x86 code cannot be executed out of
it without a dynamic loader — which the OS is forbidden from depending on
(`docs/architecture.md`, the HAL rule).

Faking it with `dlopen` was considered and rejected. A shared object is not
machine code in flash: it gets relocated, it can call libc, and it would teach
the wrong model of what loading is. The native simulator stays what it is good
at — a fast, sanitizer-instrumented functional target — and the chip-
programming story belongs to SCV1, where the flash, the addresses and the jump
are all real.
