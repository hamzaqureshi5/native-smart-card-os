# SPDX-License-Identifier: MIT
#
# check_core_deps.cmake -- Enforce the layering rule from README section
# "CRITICAL ARCHITECTURAL RULE": the OS core may depend on the HAL and on
# nothing else.
#
# Run as: cmake -DLIB=<path to libscos_core.a> -DNM=<nm> -P check_core_deps.cmake
#
# WHY THIS IS A TEST AND NOT A CODE-REVIEW ITEM
# Architectural rules that are not machine-checked erode. A single #include
# <stdlib.h> plus a malloc() would compile and pass every functional test on a
# PC, and then fail to link -- or worse, link against a stub heap -- on the
# real chip. This test is the tripwire, and it fails the build the moment the
# core reaches outside its layer.

if(NOT DEFINED LIB OR NOT EXISTS "${LIB}")
  message(FATAL_ERROR "check_core_deps: LIB not found: '${LIB}'")
endif()
if(NOT DEFINED NM)
  set(NM "nm")
endif()

execute_process(
  COMMAND "${NM}" --undefined-only --format=posix "${LIB}"
  OUTPUT_VARIABLE nm_out
  ERROR_VARIABLE  nm_err
  RESULT_VARIABLE nm_rc)

if(NOT nm_rc EQUAL 0)
  message(FATAL_ERROR "check_core_deps: nm failed (${nm_rc}): ${nm_err}")
endif()

# Permitted undefined symbols in the OS core:
#
#   hal_*        the entire point: the HAL is the core's only dependency
#   crypto_*     the SECOND seam, added in M3, and allowed for exactly the same
#                reason as hal_*: it is a platform service the core states a
#                need for and cannot see the implementation of. On this build
#                it is mbedTLS compiled from third_party/; on a real part it
#                should be the chip's crypto accelerator, and on a part with
#                hardware key slots the key material would never enter RAM.
#                Nothing above include/crypto/crypto.h can tell which.
#
#                Note what this does NOT permit. The core may call the seam; it
#                may not reach the library behind it. src/crypto/ is the only
#                place mbedtls headers are visible, and the dependency is
#                PRIVATE in CMake, so an mbedtls_* symbol appearing here would
#                still be a violation.
#   scos_* os_* apdu_* fs_* pin_* crc16
#                cross-translation-unit references inside the core itself
#   memcpy/memset/memmove/memcmp
#                GCC and Clang emit calls to these from ordinary struct
#                assignment and loop idioms even under -ffreestanding, with no
#                source-level call present. Every real bare-metal target
#                provides them (libgcc, compiler-rt, or a few lines of asm), so
#                allowing them is honest rather than a loophole. Note that
#                os_mem.c still provides its OWN primitives for anything
#                security-relevant, because memcmp is not constant time.
#   __asan_* __ubsan_* __sanitizer_* __stack_chk_*
#                instrumentation, present only in the sanitized test build.
#   _GLOBAL_OFFSET_TABLE_
#                not a dependency at all: it is the relocation anchor that
#                position-independent codegen emits. A cross-build for a card
#                MCU produces no GOT, so this entry simply will not appear
#                there.
set(allowed_regex
    "^hal_"
    "^crypto_"  # the M3 seam; see the note above -- mbedtls_* is still barred
    "^scos_"
    "^os_"
    "^pin_"     # src/security/pin.c, core's own
    "^apdu_"
    "^fs_"
    "^tlv_"     # added when CREATE FILE became the first core caller of the
                # BER-TLV reader. tlv.c has been in libscos_core since M2b, but
                # nothing referenced it, so the check never saw the symbol --
                # a reminder that this test measures what is USED, not what is
                # compiled.
    "^crc16$"
    "^mem(cpy|set|move|cmp)$"
    "^__asan"
    "^__ubsan"
    "^__sanitizer"
    "^__stack_chk"
    "^_GLOBAL_OFFSET_TABLE_$"
    "^_GLOBAL__sub"
)

string(REPLACE "\n" ";" nm_lines "${nm_out}")
set(violations "")

foreach(line IN LISTS nm_lines)
  string(STRIP "${line}" line)
  if(line STREQUAL "")
    continue()
  endif()
  # POSIX format: "name U" or "name U 0 0"; object headers end with ':'
  if(line MATCHES "^([^ ]+):$")
    continue()
  endif()
  if(NOT line MATCHES "^([^ ]+)[ \t]+[Uw]")
    continue()
  endif()
  set(sym "${CMAKE_MATCH_1}")

  set(ok FALSE)
  foreach(pat IN LISTS allowed_regex)
    if(sym MATCHES "${pat}")
      set(ok TRUE)
      break()
    endif()
  endforeach()

  if(NOT ok)
    list(APPEND violations "${sym}")
  endif()
endforeach()

if(violations)
  list(REMOVE_DUPLICATES violations)
  message("")
  message("LAYERING VIOLATION in the OS core (${LIB}).")
  message("The core references symbols that are neither HAL nor its own:")
  foreach(v IN LISTS violations)
    message("    ${v}")
  endforeach()
  message("")
  message("The core must not depend on libc, the host OS, a heap, or files.")
  message("Move the dependency behind include/hal/hal.h, or implement it in")
  message("src/kernel/os_mem.c. See docs/architecture.md.")
  message(FATAL_ERROR "core layering check failed")
endif()

message(STATUS "core layering check: OK -- no host dependencies")
