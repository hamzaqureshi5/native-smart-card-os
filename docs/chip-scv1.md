# SCV1 — the virtual chip

> **SCV1 is a chip we invented.** "Smart Card Virtual, revision 1". Its memory
> map, its region sizes and its loader protocol are ours, defined here. It is
> **not** a Samsung part, not any other vendor's part, and no register value or
> address in it was taken from any vendor's documentation. When real hardware
> documentation arrives, `src/hal/s3m228a/` gets written against it and SCV1
> stays as the reference target.


## Two different "ROM" numbers, and they are easy to conflate

| | value | what it is |
|---|---|---|
| `SCV1_OSFLASH_SIZE` | **55 KB** | the actual region the OS links into. A hard limit: exceed it and the linker fails. |
| `SCOS_SIM_ROM_KB` | 32 KB | a **policy budget**, checked by the `os_fits_in_rom` test against `libscos_core.a`. Nothing in the linker enforces it. |

They measure different things -- the second does not even include the HAL,
the crypto backend or the vendored library -- so a percentage of one is not a
percentage of the other. Quoting the linked image's size against the 32 KB
budget produced a "we are nearly out of ROM" conclusion that was wrong by
roughly a factor of two, which is why this table exists.

Current, at the time of writing:

```
libscos_core.a    19,339 B of 32 KB policy budget   59%
smartcard-os.elf  26,268 B of 55 KB OSFLASH         48%
scv1-boot.elf      7,700 B of  8 KB BOOTROM         94%   <- the tight one
```

The boot ROM is the number to watch. It is mask ROM, it cannot be patched
after manufacture, and it contains no crypto.

## What is real, and what is ours

Being honest about this line matters more than the design itself.

| Real, public, and cited | Invented by us |
|---|---|
| **ARM Cortex-M3 (ARMv7-M)** — ARMv7-M Architecture Reference Manual. Secure MCUs in SIM/eSE roles commonly use ARM SecurCore SC000/SC300, which implement ARMv6-M/ARMv7-M, so the core is a realistic choice rather than a guess. | the memory map |
| **SysTick** and **SCB->VTOR** at their architecturally fixed addresses (`0xE000E010`, `0xE000ED08`) | region sizes and page sizes |
| **ARM CMSDK APB UART** — ARM's CMSDK technical reference manual; it is what the MPS2 platform, and therefore QEMU, provides | the loader command set |
| **ISO/IEC 7816-3 / -4** for the ATR and APDU layers | the OS slot header format |
| **ARM semihosting** | the BOOTSEL strap |

Things SCV1 does **not** model, because modelling them would mean inventing
datasheet facts: flash program/erase timing, endurance limits, program-suspend,
clock/voltage tamper detectors, and any crypto peripheral.

## Memory map

```
0x00000000  ┌────────────────────────┐
            │ BOOTROM       8 KB     │  mask ROM. Boot loader. Reset vector.
0x00002000  ├────────────────────────┤
            │ OSFLASH      55 KB     │  the OS image. Vector table at base.
0x0000FC00  ├────────────────────────┤
            │ OSHDR         1 KB     │  OS slot header (16 bytes used)
0x00010000  ├────────────────────────┤
            │ EEPROM       16 KB     │  page 4 B. Filesystem metadata.
0x00014000  ├────────────────────────┤
            │ DFLASH      256 KB     │  page 256 B. File data.
0x00054000  └────────────────────────┘

0x20000000  ┌────────────────────────┐
            │ SRAM         16 KB     │  volatile. Stack grows down from top.
0x20004000  └────────────────────────┘

0x40004000    UART0                     CMSDK APB UART
0xE000E010    SysTick                   ARMv7-M core peripheral
0xE000ED08    SCB->VTOR                 ARMv7-M core peripheral
```

Code flash (BOOTROM/OSFLASH/OSHDR) has a 1 KB page. EEPROM and DFLASH keep the
same geometry as the native simulator so one filesystem image is valid on both
targets — proven by writing on x86 and reading on ARM.

### Why the boot ROM is separate, and unwritable

A chip that can be shipped blank and programmed later must contain something
that is *already there* to do the programming. On SCV1 that is BOOTROM: fixed
at manufacture, not erasable, not reprogrammable.

That is a security property, not a convenience. Whoever controls the loader
controls what the card runs, so the loader must not be replaceable. It is also
why the boot ROM links `libscos_boot` and **never** `libscos_core` — a boot
loader that depended on the OS could not load an OS onto a blank part. The link
enforces it: `tests/unit/test_boot_loader.c` builds against `scos_boot` alone,
so the dependency cannot appear without breaking the build.

The 8 KB is policed by `scv1_boot.ld`, which fails the link if the loader
outgrows it. At the time of writing a `-O0` debug build uses about 7.7 KB, so
it is tight — deliberately. If the loader needs more room than that, the right
response is to ask what it is doing that a loader should not.

## Boot flow

```
reset
  │
  ├─ core reads SP from 0x00000000, PC from 0x00000004   (BOOTROM's vectors)
  │
  ├─ scv1_reset_handler: copy .data, zero .bss, call main()
  │
  ├─ boot_main: UART up, semihosting probe, load or erase the OS slot
  │
  ├─ read OSHDR ─── magic? version? header CRC?  ──── no ──┐
  │                        │ yes                            │
  │                   state == ACTIVE?           ──── no ──┤
  │                        │ yes                            │
  │                   image CRC matches?         ──── no ──┤
  │                        │ yes                            │
  │                   vector table plausible?    ──── no ──┤
  │                        │ yes                            │
  │                   BOOTSEL held?              ──── yes ─┤
  │                        │ no                             │
  │                        ▼                                ▼
  │              ┌──────────────────┐           ┌────────────────────┐
  │              │ VTOR = 0x2000    │           │  LOADER MODE       │
  │              │ MSP = image[0]   │           │  ATR: ...42 4F 4F 54│
  │              │ BX  image[1]     │           │  serves CLA 80     │
  │              └────────┬─────────┘           └────────────────────┘
  │                       ▼
  └──────────────►  the OS runs. ATR: ...53 43 4F 53
```

The handover is three instructions and all three matter:

* **VTOR** must move first, or the next exception — including a fault — vectors
  into the boot ROM's handlers, which by then describe the wrong program.
* **MSP** is written from a register, because the moment it moves every local
  in the calling function is gone.
* **BX**, not a call. There is no return.

`dsb`/`isb` sit between the VTOR write and the jump so the write is visible and
the pipeline holds nothing fetched under the old mapping.

## The OS slot header

16 bytes at `0x0000FC00`, big-endian, written by hand — never as a C struct.
Full layout and reasoning in [`include/boot/boot_hdr.h`](../include/boot/boot_hdr.h).

The one design point worth repeating here: the **state word is excluded from
the header CRC**, because code flash cannot rewrite a byte without erasing the
page, and the state has to change after the header is written. So the two
states are reachable by clearing bits only, which flash always permits:

```
0xFFFF  LOADED   image present and CRC-verified, will NOT be booted
0x0000  ACTIVE   the boot loader will boot it
```

Excluding it is safe in the direction that matters. Corrupting `0xFFFF` into
anything but `0x0000` leaves the card in the loader — the fail-safe outcome.
Reaching ACTIVE by accident needs all sixteen bits to drop, and even then the
image CRC is still checked before the jump.

## Flash physics are modelled

On the emulator the OS slot is ordinary writable memory, so a naive loader
would appear to work while doing something no real chip can do.
[`include/boot/cflash.h`](../include/boot/cflash.h) imposes the two rules
embedded flash actually lives by:

1. erase works on whole pages and sets them to `0xFF`;
2. programming can only **clear** bits — writing `0x0F` over `0xF0` does not
   give you `0x0F`, it gives you `0x00`.

So `cf_program()` checks every byte before storing any of them and returns
`CF_ERR_NOT_ERASED` rather than silently producing the AND of two blocks. A
loader bug that "works" in QEMU and then bricks a real part at the factory is
exactly the class of bug this project exists to catch early.

One consequence is visible in the tests: sending the **same** block twice
succeeds, because at cell level it re-clears bits that are already clear and
real flash permits that. Sending a **different** block over the same offset
fails. Modelling the first as an error would be inventing hardware behaviour.

## BOOTSEL

A strap pin sampled at reset. Held, the boot ROM stays in the loader no matter
what is in flash. SCV1 has no GPIO modelled, so it is a host file
(`card_bootsel.bin`) checked once at power-on; `tools/run-scv1.sh --bootsel`
creates it before QEMU starts and removes it afterwards, which is what "held
during reset" looks like from the firmware's side.

Without something like it the part is a one-way door: once a slot goes ACTIVE
the boot ROM jumps past the loader forever, `recycle.ldr` reaches the OS
instead, and the OS answers `6E00` because `CLA 80` is not its.

**A production part would not ship this.** A card an attacker can put back into
an unauthenticated loader is a card whose OS an attacker can replace. Real
parts authenticate loader entry and blow a one-way fuse at issuance that
disables loading permanently. Tracked in [threat-model.md](threat-model.md).

## Persistence on the emulator

QEMU's memory vanishes when it exits, so both the boot ROM and the NVM HAL
mirror their regions to host files via semihosting:

| File | Region | Owner |
|---|---|---|
| `card_osflash.bin` | OSFLASH, 56320 B | boot ROM |
| `card_oshdr.bin` | OSHDR, 1024 B | boot ROM |
| `card_eeprom.bin` | EEPROM, 16384 B | NVM HAL |
| `card_flash.bin` | DFLASH, 262144 B | NVM HAL |
| `card_bootsel.bin` | — | the runner script |

**Semihosting is not part of the card.** A real SCV1 would program its own
flash through a flash controller and no semihosting call would exist. Card I/O
deliberately does *not* use it — that goes through the UART, because a UART is
a real peripheral and the abstraction we want to exercise.

The boot ROM refreshes its mirror at the points that change whether the card is
bootable, not after every block. A power cut mid-load therefore loses the
partial image here, whereas real flash would keep it. That difference is not
observable: without a VERIFY there is no header, so a partial image is
unbootable either way and the card comes up in the loader regardless.

At power-on the boot ROM has three cases, in this order:

1. mirror files load successfully → a previously programmed card, leave it;
2. otherwise → erase both regions to `0xFF`.

Case 2 matters because QEMU hands out **zeroed** RAM, and `0x00` is not what
blank flash looks like. A slot full of zeros would parse as a header with a bad
CRC rather than as a blank card.

## Running it

See [loading-the-os.md](loading-the-os.md) for the full walkthrough. In short:

```sh
cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
cmake --build build-arm -j

./tools/mkldr.py os build-arm/smartcard-os.bin -o os.ldr
cat os.ldr | ./tools/run-scv1.sh --state-dir mycard --boot
```

## Known gaps

* The C unit tests do not run on-target. They could, under QEMU with a `printf`
  shim; what does run against the firmware is the 62-test Python suite over the
  UART, which makes it a conformance suite for the port rather than something
  rewritten for it.
* No MPU configuration. ARMv7-M has one and a card OS should use it to keep
  applets out of the kernel's RAM; that is applet-isolation work (M6), not
  chip work.
* No interrupt use anywhere. A card is powered by the reader and exists to
  answer; polling costs nothing and removes a concurrency class entirely.
* Timing, endurance and tamper detection are not modelled at all.
