# Porting to real hardware

## Current status

`src/hal/samsung/` is a **placeholder containing no chip-specific code.**

No Samsung datasheet, reference manual, SDK or errata has been consulted. There
are no register addresses, no memory map, no boot sequence, no crypto peripheral
interface and no debug interface in this repository, because inventing them
would be worse than useless -- it would produce code that looks like a port and
is fiction.

Every function in the stub returns `HAL_ERR_UNSUPPORTED`, and the file
**refuses to compile** without `-DSCOS_ACK_SAMSUNG_STUB=ON`. A HAL that quietly
returns plausible values is far more dangerous than one that will not build: it
would let the OS appear to work while writing nothing to real NVM.

Its purpose is to prove the seam is real. It is a second, independent
implementation of `include/hal/hal.h`, and the OS links against it cleanly --
which is how we know the core has not grown a hidden simulator dependency.

## What is needed to start a real port

Documentation, before any code:

1. Datasheet and reference manual for the specific part.
2. SDK / BSP, and the toolchain it expects.
3. Programming guide for NVM (flash and EEPROM).
4. Crypto peripheral documentation.
5. TRNG documentation, including its health-test / failure reporting.
6. The ISO 7816-3 / 14443 interface block documentation.
7. Boot ROM behaviour and the secure-boot chain.
8. Errata.

Provide these and the port becomes ordinary engineering. Without them it is
guesswork with a security product at the end of it.

## Facts to establish from that documentation

Nothing below can be guessed. Each one changes the OS design if it comes out
differently than assumed.

### CPU and toolchain
* architecture, word size, endianness
* the cross-compiler, and whether a freestanding libc is available
* alignment requirements and whether unaligned access faults
* stack size, and whether stack overflow is detected

### Memory map
* base address and size of every region: ROM, flash, EEPROM, RAM
* which regions are executable, and how execution rights are configured
* memory protection: is there an MPU? how many regions? what granularity?
  **This determines whether applet isolation can be enforced by hardware or
  only by software convention** -- the single most consequential item on this
  list.

### NVM programming -- decides the transaction design
* page size and erase granularity for each region
* write and erase timing, and how completion is detected
* endurance and any wear-levelling requirement
* **what a power loss part way through a program leaves behind.** The three
  possibilities require different journal designs:
  - the page is fully written or fully unchanged (rare, easiest)
  - the page contains a mixture of old and new bytes
  - the page contains *indeterminate* bits that may read differently each time
* whether the device offers hardware-assisted atomic write or an EEPROM
  emulation layer with its own guarantees

### TRNG
* start-up and read sequence
* the health tests, and how failure is signalled -- `hal_random_bytes()` must
  return `HAL_ERR_IO` when they fail, and never substitute weaker entropy
* throughput, and whether conditioning is required

### Crypto accelerator
* algorithms, modes and key sizes in hardware
* the register or DMA interface
* **whether keys can live in hardware key slots** rather than in RAM. If so,
  `KeyObject` should reference a slot rather than hold material, which changes
  the crypto abstraction (M5) substantially.
* side-channel countermeasures the hardware provides, and what remains software's
  responsibility

### Communication
* contact (7816-3) and/or contactless (14443) support
* how the ATR/ATS is configured, and by whom -- boot ROM or OS
* protocol support (T=0, T=1) and whether the block layer is in hardware
* buffer sizes and any DMA constraints

### Security peripherals
* sensors: voltage, clock, temperature, light, glitch
* how a tamper event is delivered, and what the OS must do about it
* active shield, memory encryption, bus scrambling
* the unique device identifier and how to read it

### Boot and provisioning
* boot ROM behaviour and the secure-boot chain
* how the OS image is signed, verified and programmed
* how debug is disabled for production, and whether that is irreversible
* the lifecycle-state mechanism the chip enforces in hardware

## A real reference point: Samsung S3M228A

Samsung publishes a product page for the **S3M228A**, a SIM part in mass
production. What it states:

| | S3M228A |
|---|---|
| Core | **ARM SecurCore SC000**, 14 MHz |
| Architecture | ARMv6-M (Cortex-M0 class) |
| Flash | 228 KB |
| RAM | **5 KB** |
| Interface | ISO 7816 |

Source: <https://semiconductor.samsung.com/security-solution/ese-esim-sim/part-number/s3m228a/>

### What this confirms

The choice of an ARM core for SCV1 was a documented assumption -- `scv1.h` says
SIM and eSE parts "commonly use ARM SecurCore SC000/SC300". A shipping Samsung
SIM part bears that out. The core family was the right guess.

### What it warns about

**1. SC000 is ARMv6-M, and SCV1 is ARMv7-M.** That is not a detail. Our boot
ROM hands the core to the OS by writing `SCB->VTOR` to relocate the vector
table, and **Cortex-M0-class cores have no VTOR** -- the table is fixed at
address 0. If SC000 follows Cortex-M0 here, `boot_jump()` in
`src/hal/arm-scv1/boot_main.c` cannot work on such a part, and the handover
needs a different design: a fixed trampoline in mask ROM that forwards each
exception to a table the OS registers, or a RAM-based table if the part
supports remapping.

NOT VERIFIED. Cortex-M0 has no VTOR; whether SecurCore SC000 adds one is a
question for the ARM SecurCore SC000 Technical Reference Manual, and SecurCore
variants do differ from their Cortex-M base. Treat this as a risk to check
before relying on it either way.

The OS core itself is fine: all 17 core and boot translation units compile
clean for `-mcpu=cortex-m0`, at about 13% more code than for Cortex-M3
(19,734 vs 17,408 bytes of text). The CI has an `armv6m` job so this cannot
silently regress.

**2. 5 KB of RAM is less than our OS budget.** `SCOS_OS_RAM_BUDGET_BYTES` is
8 KB -- larger than that entire part's RAM, which is also shared with the
stack. Actual use is only 796 bytes (`sizeof(scos_kernel)`), so the OS would
fit; the *budget* is the fiction.

The geometry has deliberately NOT been changed to match. Reasons, recorded so
the decision is not relitigated blindly:

* Samsung publishes one storage figure, "Flash 228 KB". Our model has separate
  CODE, EEPROM and DFLASH regions with different page sizes and endurance.
  Splitting 228 KB across them would be our invention wearing a vendor's
  number -- on a flash-only part, EEPROM is emulated in flash and the
  code/data partition is an OS-vendor decision, not silicon.
* `SCOS_SIM_ROM_KB` would lose its meaning entirely: the real part has no
  separate ROM.
* Adopting the sizes while keeping a Cortex-M3 core and a VTOR-based boot
  loader would make SCV1 *look* validated against a real part while remaining
  incompatible with it. A chimera is worse than an honest invention.

It builds and passes if you want the pressure -- 16 of 17 tests, the one
failure being a test that hardcodes the flash size:

```sh
cmake -S . -B build-tight -DSCOS_SIM_RAM_KB=5 -DSCOS_SIM_FLASH_KB=148
```

**3. Chaining, not buffering, for extended APDUs.** With 5 KB of RAM shared
with the stack, a 65535-byte command data field is not a tight fit -- it is
impossible, and raising the simulated RAM would not change that. Whatever
extended-length support lands must chain. This is now grounded in a shipping
part rather than in an argument.

### What it does NOT unlock

A product page is not a datasheet. It gives the core family, clock, memory
sizes and interface. It gives no memory map, no register addresses, no
flash-programming sequence, no boot procedure and no crypto peripheral detail.
So `src/hal/samsung/` stays stubbed. Everything in "Facts to establish from
that documentation" above is still unestablished.

## Porting procedure

1. **Implement `hal.h` and nothing else.** If a HAL function cannot be
   implemented cleanly, that is a signal the *abstraction* is wrong and should
   be fixed in `hal.h` -- for both platforms -- rather than worked around.

2. **Run `tests/unit/test_hal_sim.c` against the real HAL.** It is written as a
   *contract* test: every assertion is a statement about `hal.h`, not about the
   simulator. Rename it and run it on hardware. It is the beginning of the
   conformance suite.

3. **Run the core unit tests.** `test_apdu_parse`, `test_select` and
   `test_os_mem` need no HAL at all, so they cross-compile and run on-target
   unchanged. If they pass on hardware, the OS logic is intact.

4. **Repoint the Python suite.** Replace the subprocess transport in
   `tests/python/scos/card.py` with `pyscard` against a PC/SC reader. Every test
   above it keeps working. This is the payoff for having kept the transport in
   one file.

5. **Re-derive the ATR.** From the real clock, guard times and supported
   protocols. The simulator ATR is not transferable.

6. **Redo the NVM-dependent designs** in light of the real tear behaviour. The
   transaction manager is written against `hal_nvm_sync()` for exactly this
   reason, but the journal layout may still need to change.

7. **Re-run the threat model.** Many rows in `docs/threat-model.md` have
   "Hardware dependency: yes" and residual risks that only silicon can close.
   Those become testable -- and some become *newly relevant*, because a real
   chip has attack surface a simulator does not: JTAG, side channels, fault
   injection.

## Reserved HAL names

Deliberately **not** declared yet, to avoid creating API surface with no
implementation behind it. When cryptography arrives (M5) these are the intended
names:

    hal_crypto_aes_encrypt / _decrypt
    hal_crypto_sha256
    hal_crypto_hmac
    hal_crypto_ec_keygen / _ecdsa_sign / _ecdsa_verify
    hal_crypto_key_slot_load / _slot_use     (only if hardware key slots exist)

On the simulator these will be backed by an established software library; on
hardware, by the accelerator. The OS will see only the abstraction.

## What stays useful after the port

The simulator does not become obsolete. It remains:

* the fast development loop -- a full build and test cycle in under a second
* the only place power-failure and corruption paths can be tested exhaustively
  and reproducibly, because a seeded PRNG and a scriptable fault-injection hook
  are things real hardware does not offer
* the reference implementation to diff against when hardware misbehaves
* CI, which cannot depend on a chip being plugged in
