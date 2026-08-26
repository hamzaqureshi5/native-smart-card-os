# SPDX-License-Identifier: MIT
#
# check_rom_budget.cmake -- Hold the OS's code size to the virtual chip's ROM.
#
# Run as: cmake -DLIB=<lib> -DSIZE=<size tool> -DBUDGET=<bytes> -P ...
#
# A card OS that does not fit in ROM is not a card OS. Measuring from the first
# milestone means the number is a tracked quantity rather than a surprise
# discovered when the flash image is built. Only text + rodata count: .data and
# .bss live in RAM and are governed by the _Static_assert in os/kernel.h.
#
# Registered only for non-sanitized builds. ASan/UBSan instrumentation inflates
# code size several-fold, so measuring an instrumented build would report a
# number that describes the sanitizer rather than the OS.

if(NOT DEFINED LIB OR NOT EXISTS "${LIB}")
  message(FATAL_ERROR "check_rom_budget: LIB not found: '${LIB}'")
endif()
if(NOT DEFINED SIZE)
  set(SIZE "size")
endif()

execute_process(
  COMMAND "${SIZE}" --format=berkeley "${LIB}"
  OUTPUT_VARIABLE size_out
  ERROR_VARIABLE  size_err
  RESULT_VARIABLE size_rc)

if(NOT size_rc EQUAL 0)
  message(FATAL_ERROR "check_rom_budget: size failed (${size_rc}): ${size_err}")
endif()

# Berkeley format, one row per object plus a total row:
#    text    data     bss     dec     hex filename
string(REPLACE "\n" ";" lines "${size_out}")
set(total_text 0)
set(total_data 0)
foreach(line IN LISTS lines)
  string(STRIP "${line}" line)
  if(line MATCHES "^([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+")
    math(EXPR total_text "${total_text} + ${CMAKE_MATCH_1}")
    math(EXPR total_data "${total_data} + ${CMAKE_MATCH_2}")
  endif()
endforeach()

math(EXPR rom_used "${total_text} + ${total_data}")
math(EXPR pct "(${rom_used} * 100) / ${BUDGET}")

message(STATUS "OS code size: ${rom_used} bytes of ${BUDGET} ROM budget (${pct}%)")

if(rom_used GREATER BUDGET)
  message(FATAL_ERROR
    "ROM budget exceeded: ${rom_used} > ${BUDGET} bytes.\n"
    "Either shrink the OS or raise -DSCOS_SIM_ROM_KB deliberately, with a "
    "note in docs/architecture.md about what real part justifies the change.")
endif()
