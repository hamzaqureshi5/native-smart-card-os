/* SPDX-License-Identifier: MIT
 *
 * scv1_boot.ld -- the SCV1 boot ROM.
 *
 * The boot loader is linked SEPARATELY from the OS and lives at address 0, so
 * it is what the core executes on reset. On a real part this region is mask
 * ROM: fixed at manufacture, not erasable, not reprogrammable. That is not a
 * limitation, it is the whole point -- something has to survive a blank or
 * bricked OS slot, and it must not be something an attacker can replace.
 *
 * The addresses here MUST match the SCV1_* constants in scv1.h. They are
 * repeated rather than shared because the linker cannot read a C header; the
 * boot loader checks a few of them at run time and halts on a mismatch.
 */

MEMORY
{
  BOOTROM (rx)  : ORIGIN = 0x00000000, LENGTH = 8K
  SRAM    (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

ENTRY(scv1_reset_handler)

SECTIONS
{
  .vectors : ALIGN(4)
  {
    KEEP(*(.vectors))
  } > BOOTROM

  .text : ALIGN(4)
  {
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.glue_7 .glue_7t)
    . = ALIGN(4);
    _etext = .;
  } > BOOTROM

  .data : ALIGN(4)
  {
    _sdata = .;
    *(.data .data.*)
    . = ALIGN(4);
    _edata = .;
  } > SRAM AT> BOOTROM
  _sidata = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    _sbss = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > SRAM

  _estack = ORIGIN(SRAM) + LENGTH(SRAM);

  _stack_reserve = 2K;
  ASSERT(_ebss + _stack_reserve <= _estack,
         "SCV1 boot: static data plus reserved stack exceeds 16 KB SRAM")

  /* If the loader outgrows the mask ROM the link fails here rather than
   * quietly overlapping the OS slot. 8 KB is generous for what this does; if
   * it ever gets tight, that is a signal the loader is doing too much. */
  ASSERT(_etext <= ORIGIN(BOOTROM) + LENGTH(BOOTROM),
         "SCV1 boot: boot loader does not fit in 8 KB BOOTROM")

  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
