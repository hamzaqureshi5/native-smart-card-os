# Architecture

## The one rule

The OS core depends on `include/hal/hal.h` and on nothing else.

This is not an aspiration. It is checked by the `core_no_host_deps` test, which
runs `nm` over `libscos_core.a` and fails the build if the core references any
symbol that is not a HAL function, one of its own, or a compiler-emitted memory
intrinsic. As of Milestone 1 the core's complete external dependency list is:

    hal_card_receive
    hal_card_send

That is the whole surface. It is why porting to real silicon is a bounded job.

## Layers

    +-----------------------------------------------------+
    |  Test client (Python / cardctl)                     |   off-card
    +-----------------------------------------------------+
                          | APDUs over a transport
    +-----------------------------------------------------+
    |  Transport (T=0/T=1 on silicon, hex pipe here)      |
    +=====================================================+
    |  CARD OS -- portable, freestanding, no libc         |
    |                                                     |
    |   kernel      scos_process(): pure (state, cmd)     |
    |   apdu        parse / validate / dispatch / respond |
    |   filesystem  MF/DF/EF                  (M2)        |
    |   security    PIN, access conditions    (M3)        |
    |   transactions commit / rollback        (M4)        |
    |   crypto      abstraction over a library (M5)       |
    |   applets     native applet interface   (M6)        |
    |   card mgr    registry, lifecycle       (M7)        |
    +=====================================================+
    |  HAL -- include/hal/hal.h : THE CONTRACT            |
    +-----------------------------------------------------+
              |                             |
    +-------------------+         +-------------------+
    | Simulator HAL     |         | Samsung HAL       |
    | src/hal/simulator |         | src/hal/samsung   |
    | + simulator/      |         | (stub, no code)   |
    +-------------------+         +-------------------+
              |                             |
             PC                       real secure MCU

`hal.h` is a third party to the OS and the simulator both. Neither includes the
other's headers. Selection is at link time via `-DSCOS_HAL=simulator|samsung`,
not through function pointers -- a writable vtable in RAM is both overhead and
an attack surface on a chip where a single write primitive should not become
control-flow hijacking.

## Why this is not a Linux-style kernel

A smart card has one thread of control, and it does not own it: the reader does.
The card is powered by the reader, so it cannot run when nobody is asking it a
question, and power can vanish between any two instructions. There is no heap,
no MMU in the general-purpose sense, no filesystem beneath the OS, and no
trusted clock.

Under those constraints, the usual kernel machinery is not merely unnecessary,
it is harmful. A scheduler adds interleaving that creates security-relevant
race conditions where none needed to exist. A heap introduces fragmentation and
a failure mode -- allocation failure -- at unpredictable points in a command
that must be atomic. Preemption makes it impossible to reason about what state
a torn write left behind.

So the design goes the other way:

* **One command at a time, run to completion.** No concurrency, therefore no
  concurrency bugs.
* **All state static.** `scos_kernel` is the card's entire RAM, allocated once
  by the platform. `sizeof()` is an honest footprint measure, held to the
  configured budget by a `_Static_assert`.
* **Durability is explicit.** Nothing is persistent until `hal_nvm_sync()`
  returns. The OS is written against a device that buffers writes, because every
  real one does.
* **Power loss is a normal input, not an exception.** Handled by the transaction
  system (M4), not by hoping.

## Key design decisions

### `scos_process()` performs no I/O

    scos_status scos_process(k, cmd, cmd_len, rsp, rsp_cap, rsp_len);

A pure function of state and command bytes. Every command the card implements
can therefore be tested with no reader, no simulator, no sockets and no files
-- see `tests/unit/test_select.c`, which links `libscos_core.a` alone.

The I/O pump (`scos_card_loop()`) lives in a *separate translation unit*,
`src/kernel/card_loop.c`. That is deliberate and was in fact forced by the
linker: while the pump shared a file with `scos_process()`, static-library
granularity dragged `hal_card_*` into every unit test. Separate object file,
separate dependency.

### Handlers return a status word; they never write one

    typedef uint16_t (*scos_cmd_handler)(k, cmd, rsp);

The dispatcher appends SW1 SW2. A handler cannot forget to, so "the card always
answers" is structural rather than a convention every new handler must respect.

### Validation order is fixed

    structure -> class -> instruction -> parameters -> security -> execute

Not arbitrary. A card that checks security before structure can be probed with
malformed APDUs. A card that answers "INS not supported" before validating CLA
leaks which instructions exist in classes it does not serve --
`cla_checked_before_ins` in `test_select.c` pins that down.

### Status words are diagnostic, and never invented

Every SW in `include/apdu/sw.h` is defined by ISO/IEC 7816-4, used for its
standard meaning. Where we reject something, we say why: an unsupported logical
channel is 6881, secure messaging is 6882, chaining is 6884 -- not a blanket
6E00. An unimplemented-but-legal selection method is 6A86 ("incorrect
parameters"), *not* 6A82 ("file not found"), because we never looked for the
file and claiming otherwise would mislead anyone mapping the card.

## Measured budgets

Both are enforced by tests, not comments:

| Budget | Limit | Used (M1) | Enforced by |
|---|---|---|---|
| ROM (text+rodata) | 32 KB | 3,936 B (12%) | `os_fits_in_rom` (non-sanitized builds) |
| OS RAM working set | 8 KB | 536 B (7%) | `_Static_assert` in `os/kernel.h` |

The ROM test is registered only when sanitizers are off: an instrumented
binary's size measures the sanitizer, not the OS. This is a deliberate
restriction to a representative build, not a skipped failure.

## Directory layout

| Path | Contents | Portable? |
|---|---|---|
| `include/hal/hal.h` | the contract | yes -- the definition of portable |
| `include/hal/sim/` | virtual-chip internals | simulator only |
| `src/kernel/` `src/apdu/` | the OS | yes, freestanding |
| `src/hal/simulator/` | HAL over the virtual chip | host |
| `src/hal/samsung/` | placeholder, no chip code | future |
| `simulator/` | virtual chip, transport, `main()` | host |
| `tests/unit/` | core tests (no HAL) + HAL contract tests | mostly |
| `tests/integration/` | layering and budget guards | build-time |
| `tests/python/` | reader-side integration tests | host |

### Deviations from the originally proposed tree

* Added `docs/roadmap.md` -- milestone tracking needed somewhere durable.
* Added `include/hal/sim/` -- `vcard.h` and `transport.h` are shared by
  `src/hal/simulator/` and `simulator/`. Putting them in a neutral include
  directory means neither reaches into the other's private headers.
* `simulator/transport.c` implements the `hal_card_*` group rather than
  `src/hal/simulator/` doing it, matching the proposed tree. The split is by
  *what is being modelled* -- link versus chip -- not by directory convenience.
