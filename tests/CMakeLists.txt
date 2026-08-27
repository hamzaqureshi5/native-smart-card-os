# SPDX-License-Identifier: MIT

# A cross build produces firmware, not host executables. The C tests could run
# on-target under QEMU with a printf shim -- noted as a next step in
# docs/chip-scv1.md rather than half-done here. What DOES run against the
# firmware is the Python integration suite, driven over QEMU's UART.
if(CMAKE_CROSSCOMPILING)
  find_program(SCOS_QEMU qemu-system-arm)
  if(SCOS_QEMU AND SCOS_HAL STREQUAL "arm-scv1")
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_FOUND)
      add_test(NAME python_integration_arm
        COMMAND ${Python3_EXECUTABLE} -m unittest discover
                -s "${CMAKE_CURRENT_SOURCE_DIR}/python" -p "test_*.py")
      set_tests_properties(python_integration_arm PROPERTIES
        ENVIRONMENT
          "SCOS_TARGET=qemu;SCOS_QEMU=${SCOS_QEMU};SCOS_FIRMWARE=${CMAKE_BINARY_DIR}/scv1-boot.elf;SCOS_OS_IMAGE=${CMAKE_BINARY_DIR}/smartcard-os.bin;SCOS_MKLDR=${CMAKE_CURRENT_SOURCE_DIR}/../tools/mkldr.py;PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/python"
        TIMEOUT 600)
    endif()
  endif()
  return()
endif()

# --- C unit tests -----------------------------------------------------------

# Genuinely HAL-free: pure computation over buffers, links libscos_core alone.
foreach(t test_apdu_parse test_os_mem test_tlv)
  add_executable(${t} unit/${t}.c)
  target_link_libraries(${t} PRIVATE scos_core scos_warnings)
  target_include_directories(${t} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unit")
  add_test(NAME ${t} COMMAND ${t})
endforeach()

# The boot loader is equally HAL-free but belongs to libscos_boot, NOT the OS.
# Linking it without scos_core is the point: the loader has to work on a chip
# whose OS slot is empty, so if it ever grows a dependency on the OS this test
# stops linking.
add_executable(test_boot_loader unit/test_boot_loader.c)
target_link_libraries(test_boot_loader PRIVATE scos_boot scos_warnings)
target_include_directories(test_boot_loader PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unit")
add_test(NAME test_boot_loader COMMAND test_boot_loader)

# These need NVM, so a HAL is linked in. The simulator HAL with state_dir=NULL
# is an in-RAM hermetic store -- a test double that is also the real code path.
if(SCOS_HAL STREQUAL "simulator")
  foreach(t test_hal_sim test_select test_fs test_create test_get_response test_lifecycle)
    add_executable(${t} unit/${t}.c)
    target_link_libraries(${t} PRIVATE scos_core scos_hal scos_warnings)
    target_include_directories(${t} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unit")
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
endif()

# Sanitizer settings shared by every test. halt_on_error means a finding fails
# the test rather than being buried in the log.
set(SCOS_SAN_OPTS
    "ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:halt_on_error=1:strict_string_checks=1:detect_stack_use_after_return=1"
    "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

foreach(t test_apdu_parse test_os_mem test_tlv test_boot_loader)
  set_tests_properties(${t} PROPERTIES ENVIRONMENT "${SCOS_SAN_OPTS}")
endforeach()
if(SCOS_HAL STREQUAL "simulator")
  foreach(t test_hal_sim test_select test_fs test_create test_get_response)
    set_tests_properties(${t} PROPERTIES ENVIRONMENT "${SCOS_SAN_OPTS}")
  endforeach()
endif()

# --- fuzz targets -----------------------------------------------------------
#
# Randomised stress testing, not coverage-guided fuzzing -- the driver has no
# feedback loop. Labelled honestly in tests/fuzz/fuzz_targets.h. Run under
# ASan+UBSan, so a memory error becomes a non-zero exit and a failed test.

if(SCOS_HAL STREQUAL "simulator")
  add_executable(fuzz_driver
    fuzz/fuzz_driver.c
    fuzz/fuzz_apdu.c
    fuzz/fuzz_tlv.c
    fuzz/fuzz_command.c
    fuzz/fuzz_fs_image.c
    fuzz/fuzz_boot.c
    fuzz/fuzz_fcp.c)
  target_link_libraries(fuzz_driver PRIVATE scos_core scos_hal scos_boot scos_warnings)
  target_include_directories(fuzz_driver PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/fuzz")
  set_target_properties(fuzz_driver PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

  # Short runs in CI; the seed is fixed so a failure is reproducible.
  # For a longer hunt: ./fuzz_driver apdu 5000000 <seed>
  foreach(tgt apdu tlv command fs_image boot)
    add_test(NAME fuzz_${tgt} COMMAND fuzz_driver ${tgt} 20000 1)
    set_tests_properties(fuzz_${tgt} PROPERTIES
      ENVIRONMENT "${SCOS_SAN_OPTS}" TIMEOUT 300)
  endforeach()

  # fcp gets fewer iterations because it is an order of magnitude slower than
  # the others: it re-personalises a card per input and re-walks all 32
  # descriptors after EVERY command, which is O(n^2) and is the whole point.
  # For a real hunt: ./fuzz_driver fcp 200000 <seed>
  add_test(NAME fuzz_fcp COMMAND fuzz_driver fcp 3000 1)
  set_tests_properties(fuzz_fcp PROPERTIES
    ENVIRONMENT "${SCOS_SAN_OPTS}" TIMEOUT 300)
endif()

# --- architectural guard tests ---------------------------------------------
#
# These check the layering rules rather than behaviour. They are cheap and they
# are the reason the eventual hardware port stays feasible.

find_program(SCOS_NM nm)
if(SCOS_NM)
  add_test(NAME core_no_host_deps
    COMMAND ${CMAKE_COMMAND}
            -DLIB=$<TARGET_FILE:scos_core>
            -DNM=${SCOS_NM}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/integration/check_core_deps.cmake")
else()
  message(WARNING "nm not found: the core layering test will not run")
endif()

find_program(SCOS_SIZE NAMES ${SCOS_CROSS_PREFIX}size size)
if(SCOS_SIZE AND NOT SCOS_SANITIZE)
  math(EXPR SCOS_ROM_BYTES "${SCOS_SIM_ROM_KB} * 1024")
  add_test(NAME os_fits_in_rom
    COMMAND ${CMAKE_COMMAND}
            -DLIB=$<TARGET_FILE:scos_core>
            -DSIZE=${SCOS_SIZE}
            -DBUDGET=${SCOS_ROM_BYTES}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/integration/check_rom_budget.cmake")
elseif(SCOS_SIZE AND SCOS_SANITIZE)
  # Not skipping a failure: an instrumented binary's size measures the
  # sanitizer, not the OS. Configure with -DSCOS_SANITIZE=OFF to get the number.
  message(STATUS "ROM budget test disabled (sanitizers inflate code size)")
endif()

# --- Python integration tests ----------------------------------------------

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND AND SCOS_HAL STREQUAL "simulator")
  add_test(NAME python_integration
    COMMAND ${Python3_EXECUTABLE} -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/python" -p "test_*.py" -v)
  # The client finds the binary through SMARTCARD_SIM; PYTHONPATH makes the
  # scos package importable without installing it.
  set(SCOS_PY_ENV
      "SMARTCARD_SIM=$<TARGET_FILE:smartcard-sim>"
      "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/python"
      ${SCOS_SAN_OPTS})
  set_tests_properties(python_integration PROPERTIES
    ENVIRONMENT "${SCOS_PY_ENV}")
else()
  message(STATUS "Python3 not found: integration tests will not run")
endif()
