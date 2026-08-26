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
