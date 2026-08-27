/* SPDX-License-Identifier: MIT
 *
 * scv1.ld -- SCV1 memory map, as seen by the linker.
 *
 * This file is where the chip stops being a comment and starts being enforced.
 * If the OS outgrows CODE, or its static data outgrows SRAM, the LINK FAILS --
 * which is exactly the feedback a card OS needs, and exactly what a native
 * build cannot give you.
 *
 * EEPROM and DFLASH are declared but NOTHING is placed in them: they hold
 * filesystem data at run time, not linker output. That keeps the flash image
 * the size of the code rather than the size of the chip.
 *
 * NOTE THE ORIGIN. The OS does NOT live at address 0 -- the boot ROM does.
 * The OS is linked to run from OSFLASH at 0x00002000, which is where the boot
 * loader programs it and where it points VTOR before jumping. Linking it at 0
 * would produce an image whose absolute addresses were all 0x2000 too low; it
 * would load, pass its CRC, and then fault on the first function call.
 */

MEMORY
{
  /* OSFLASH -- see scv1.h. 0x00000000..0x00001FFF is BOOTROM and
   * 0x0000FC00..0x0000FFFF is the OS slot header; neither belongs to us. */
  CODE   (rx)  : ORIGIN = 0x00002000, LENGTH = 55K
  EEPROM (rw)  : ORIGIN = 0x00010000, LENGTH = 16K
  DFLASH (rw)  : ORIGIN = 0x00014000, LENGTH = 256K
  SRAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

ENTRY(scv1_reset_handler)

SECTIONS
{
  /* The vector table must be first: on reset the core reads the initial stack
   * pointer from address 0 and the reset vector from address 4. */
  .vectors : ALIGN(4)
  {
    KEEP(*(.vectors))
  } > CODE

  .text : ALIGN(4)
  {
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.glue_7 .glue_7t)
    . = ALIGN(4);
    _etext = .;
  } > CODE

  /* Initialised data lives in CODE and is copied to SRAM by the startup code.
   * AT> makes the load address differ from the run address, which is what
   * makes that copy possible. */
  .data : ALIGN(4)
  {
    _sdata = .;
    *(.data .data.*)
    . = ALIGN(4);
    _edata = .;
  } > SRAM AT> CODE
  _sidata = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    _sbss = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > SRAM

  /* Stack grows down from the top of SRAM. */
  _estack = ORIGIN(SRAM) + LENGTH(SRAM);

  /* Reserve room so a deep call chain cannot silently collide with .bss.
   * 2 KB is a guess that the link will police: exceed it and this errors. */
  _stack_reserve = 2K;
  ASSERT(_ebss + _stack_reserve <= _estack,
         "SCV1: static data plus reserved stack exceeds 16 KB SRAM")

  /* Region symbols, so the HAL never hardcodes an address that could drift
   * out of step with this file. */
  _eeprom_base = ORIGIN(EEPROM);
  _eeprom_size = LENGTH(EEPROM);
  _dflash_base = ORIGIN(DFLASH);
  _dflash_size = LENGTH(DFLASH);

  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.attributes) *(.comment) }
}
