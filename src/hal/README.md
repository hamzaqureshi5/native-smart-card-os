# `src/hal/` -- one contract, three implementations

`include/hal/hal.h` is the **only** interface the OS core is allowed to use.
Everything in this directory implements that same header. Exactly one is
compiled into any given binary, chosen at configure time:

```
cmake -S . -B build      -DSCOS_HAL=simulator   # default
cmake -S . -B build-arm  -DSCOS_HAL=arm-scv1 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
cmake -S . -B build-chip -DSCOS_HAL=s3m228a  -DSCOS_ACK_S3M228A_STUB=ON
```

These are **not** competing products, and only one of them is a chip target.

| Directory | What it is | Runs? |
|---|---|---|
| `s3m228a/` | **The hardware target.** Samsung S3M228A. Unimplemented. | No -- every function returns `HAL_ERR_UNSUPPORTED` |
| `arm-scv1/` | Bare-metal ARM test bench on an invented chip ("SCV1"), run under QEMU | Yes |
| `simulator/` | Host test bench -- the OS as a Linux process | Yes |

## Why the S3M228A HAL is empty

Because no datasheet or reference manual for the part is available here.
Samsung publishes a marketing page (SecurCore SC000, 14 MHz, 228 KB flash,
5 KB RAM) and nothing more. That is enough to pick a toolchain and a RAM
budget; it is not enough to write a memory map, an NVM programming sequence,
a TRNG driver, or a boot handover.

Writing plausible-looking register code would be worse than writing none: the
OS would appear to work while writing nothing to real NVM. So the file refuses
to compile without `-DSCOS_ACK_S3M228A_STUB=ON`, and every function fails
loudly at run time. See [../../docs/hardware-port.md](../../docs/hardware-port.md)
for the itemised list of what the documentation must supply.

## Why the other two are not "extra"

**`simulator/` is the test bench, not a rival target.** With no silicon in
hand it is the only way to execute the OS at all. Its 17 unit-test binaries
and 81 Python tests are what make the S3M228A port checkable when it becomes
writable -- the suite written against the simulator is a conformance suite for
the port.

**`arm-scv1/` is where the OS is proven to work as bare-metal ARM code** --
real vector table, real `.data`/`.bss` init, a flash model with page-erase
semantics, and the boot ROM that loads an OS onto a blank part. Nearly all of
that plumbing is reusable for the S3M228A. The chip is invented *on purpose*:
inventing "SCV1" is honest, whereas inventing S3M228A register addresses would
be a lie about hardware nobody here has seen. When the documentation arrives,
this directory is the template and `s3m228a/` is the destination.

**`s3m228a/` also earns its place today.** Being a second, independent
implementation of `hal.h`, linking the core against it is what would expose an
accidental dependency on the simulator -- a `FILE *`, a `getenv`, a Linux type
leaking upward. CI builds that configuration on every push for exactly this
reason (`s3m228a-stub` job), alongside a machine check that
`libscos_core.a`'s entire external dependency list is `hal_*`.

## Note on where the simulator's card I/O lives

`simulator/` holds only NVM and platform. The simulator's `hal_card_send` /
`hal_card_receive` / `hal_card_atr` are in `../../simulator/transport.c`,
next to the T=0 framing and the CLI, because in that build the transport *is*
the card reader. On `arm-scv1` the equivalent code is in `hal_arm_io.c`, where
the UART genuinely is a peripheral.
