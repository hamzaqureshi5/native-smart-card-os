# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.20)

project(smartcard-os
        VERSION 0.1.0
        DESCRIPTION "Smart-card operating system with a virtual-hardware simulator"
        LANGUAGES C)

# Strict ISO C11. C11 for _Static_assert; extensions OFF so that a compiler
# extension cannot sneak into the OS core and break the eventual cross-build.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------- options ----

set(SCOS_HAL "simulator" CACHE STRING "HAL implementation: simulator | arm-scv1 | s3m228a")
set_property(CACHE SCOS_HAL PROPERTY STRINGS simulator arm-scv1 s3m228a)

# Cross builds default to the SCV1 chip target: a native "simulator" HAL cannot
# be built for a bare-metal ARM target, so pick the sensible default rather than
# failing confusingly.
if(CMAKE_CROSSCOMPILING AND SCOS_HAL STREQUAL "simulator")
  set(SCOS_HAL "arm-scv1" CACHE STRING "" FORCE)
endif()

option(SCOS_SANITIZE       "Build with AddressSanitizer + UndefinedBehaviorSanitizer" ON)
option(SCOS_WERROR         "Treat warnings as errors" ON)
option(SCOS_STATIC_ANALYSIS "Enable the GCC static analyzer (-fanalyzer)" OFF)
option(SCOS_ACK_S3M228A_STUB "Build the unimplemented S3M228A HAL anyway" OFF)

# Virtual chip geometry. Simulator defaults only; not any real part.
set(SCOS_SIM_RAM_KB    16  CACHE STRING "Virtual RAM (KB)")
set(SCOS_SIM_ROM_KB    32  CACHE STRING "Virtual ROM (KB)")
set(SCOS_SIM_EEPROM_KB 16  CACHE STRING "Virtual EEPROM (KB)")
set(SCOS_SIM_FLASH_KB  256 CACHE STRING "Virtual FLASH (KB)")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/os/scos_config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/os/scos_config.h"
  @ONLY)

# --------------------------------------------------------------- warnings ----

add_library(scos_warnings INTERFACE)
target_compile_options(scos_warnings INTERFACE
  -Wall -Wextra -Wpedantic
  -Wshadow                # a shadowed length variable is a classic overflow
  -Wconversion            # implicit narrowing is how length bugs are born
  -Wsign-conversion
  -Wstrict-prototypes
  -Wmissing-prototypes    # every non-static function must be declared publicly
  -Wcast-qual             # casting away const on key material must be visible
  -Wpointer-arith
  -Wwrite-strings
  -Wvla                   # no variable-length arrays: unbounded stack growth
  -Wundef
  -Wdouble-promotion
  -Wformat=2
  -Wswitch-enum           # a new enum value must be handled everywhere
)
if(SCOS_WERROR)
  target_compile_options(scos_warnings INTERFACE -Werror)
endif()
if(SCOS_STATIC_ANALYSIS)
  target_compile_options(scos_warnings INTERFACE -fanalyzer)
endif()

# ------------------------------------------------------------- sanitizers ----

add_library(scos_sanitizers INTERFACE)
if(CMAKE_CROSSCOMPILING AND SCOS_SANITIZE)
  # No sanitizer runtime exists for a bare-metal target: ASan needs a heap and
  # a way to report, and the chip has neither. The native build is where
  # sanitizers earn their keep; the cross build is where the linker enforces
  # the memory map.
  message(STATUS "Sanitizers disabled: not available for a bare-metal target")
  set(SCOS_SANITIZE OFF CACHE BOOL "" FORCE)
endif()
if(SCOS_SANITIZE)
  # ASan catches the buffer overruns a hostile APDU is trying to cause.
  # UBSan catches the signed overflow and misaligned access that a card OS
  # doing byte arithmetic can produce. Both are on for the whole test suite;
  # a fuzz finding is worthless if the build cannot detect the corruption.
  target_compile_options(scos_sanitizers INTERFACE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -fno-sanitize-recover=all)   # abort on first finding; never keep going
  target_link_options(scos_sanitizers INTERFACE
    -fsanitize=address,undefined)
endif()

# ---------------------------------------------------------- shared leaf ------
#
# Code used by BOTH the OS and the boot loader. Kept in its own library so that
# the boot loader does not have to link the OS to get a CRC routine -- the boot
# loader must be able to run on a chip whose OS slot is empty, so it cannot
# depend on the OS in any direction.

add_library(scos_util STATIC
  src/kernel/crc16.c
)
target_include_directories(scos_util PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(scos_util PRIVATE scos_warnings)
target_link_libraries(scos_util PUBLIC scos_sanitizers)
target_compile_options(scos_util PRIVATE -ffreestanding)

# ------------------------------------------------------------- OS core -------
#
# libscos_core is THE portable OS. It links against no HAL implementation and
# no libc. Its only undefined symbols must be hal_* (plus compiler-generated
# memory intrinsics) -- which the "core_no_host_deps" test enforces.

add_library(scos_core STATIC
  src/kernel/kernel.c
  src/kernel/card_loop.c
  src/kernel/os_mem.c
  src/apdu/apdu_parse.c
  src/apdu/apdu_resp.c
  src/apdu/apdu_dispatch.c
  src/apdu/cmd_get_response.c
  src/apdu/tlv.c
  src/filesystem/fs_store.c
  src/filesystem/fs.c
  src/filesystem/cmd_select.c
  src/filesystem/cmd_binary.c
  src/filesystem/cmd_create.c
  src/filesystem/cmd_lifecycle.c
)
target_include_directories(scos_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(scos_core PRIVATE scos_warnings)
target_link_libraries(scos_core PUBLIC scos_sanitizers scos_util)

# Freestanding discipline, enforced by the compiler rather than by review:
# no builtin libc calls beyond the memory intrinsics the codegen may emit.
target_compile_options(scos_core PRIVATE -ffreestanding)

# --------------------------------------------------------- boot loader -------
#
# libscos_boot is the loader logic, and like the OS core it is pure: it takes
# pointers to two byte regions and knows nothing about peripherals, files, or
# real addresses. That is what lets the host build unit-test and fuzz the code
# that will eventually sit in unpatchable mask ROM.

add_library(scos_boot STATIC
  src/boot/boot_hdr.c
  src/boot/cflash.c
  src/boot/boot_loader.c
)
target_include_directories(scos_boot PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(scos_boot PRIVATE scos_warnings)
target_link_libraries(scos_boot PUBLIC scos_sanitizers scos_util)
target_compile_options(scos_boot PRIVATE -ffreestanding)

# --------------------------------------------------------- HAL selection -----

if(SCOS_HAL STREQUAL "simulator")
  add_library(scos_hal STATIC
    src/hal/simulator/hal_sim_nvm.c
    src/hal/simulator/hal_sim_platform.c
    simulator/virtual_card.c
    simulator/transport.c
  )
elseif(SCOS_HAL STREQUAL "arm-scv1")
  if(NOT CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR
      "SCOS_HAL=arm-scv1 needs the cross toolchain. Configure with:\n"
      "  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake")
  endif()
  add_library(scos_hal STATIC
    src/hal/arm-scv1/startup.c
    src/hal/arm-scv1/semihost.c
    src/hal/arm-scv1/hal_arm_nvm.c
    src/hal/arm-scv1/hal_arm_io.c
    src/hal/arm-scv1/hal_arm_platform.c
  )
  target_include_directories(scos_hal PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src/hal/arm-scv1")
elseif(SCOS_HAL STREQUAL "s3m228a")
  add_library(scos_hal STATIC src/hal/s3m228a/hal_s3m228a.c)
  if(SCOS_ACK_S3M228A_STUB)
    target_compile_definitions(scos_hal PRIVATE SCOS_S3M228A_STUB_ACKNOWLEDGED=1)
  endif()
  message(WARNING
    "SCOS_HAL=s3m228a selects an UNIMPLEMENTED placeholder. It contains no "
    "part-specific code and every function fails at run time. It exists to "
    "prove the HAL seam holds and to be the place the real port lands.")
else()
  message(FATAL_ERROR
    "SCOS_HAL must be 'simulator', 'arm-scv1' or 's3m228a' (got '${SCOS_HAL}')")
endif()

# NOTE: scos_hal deliberately does NOT link scos_core. The HAL sits BELOW the
# OS and must not depend on it -- that is the whole architectural rule. Targets
# that need both list them in dependency order: scos_core then scos_hal, so the
# linker resolves the core's hal_* references from the library that follows it.
target_link_libraries(scos_hal PRIVATE scos_warnings)
target_include_directories(scos_hal PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(scos_hal PUBLIC scos_sanitizers)

# ------------------------------------------------------------- simulator -----

if(SCOS_HAL STREQUAL "simulator")
  add_executable(smartcard-sim simulator/main.c)
  target_link_libraries(smartcard-sim PRIVATE scos_core scos_hal scos_warnings)
  set_target_properties(smartcard-sim PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()

# ------------------------------------------------------- SCV1 firmware -------

if(SCOS_HAL STREQUAL "arm-scv1")
  set(SCV1_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/src/hal/arm-scv1/scv1.ld")

  add_executable(smartcard-os.elf src/hal/arm-scv1/card_main.c)
  target_link_libraries(smartcard-os.elf PRIVATE scos_core scos_hal scos_warnings)
  target_link_options(smartcard-os.elf PRIVATE
    -T "${SCV1_LINKER_SCRIPT}"
    -Wl,-Map=${CMAKE_BINARY_DIR}/smartcard-os.map
    -Wl,--cref
    -lgcc)
  set_target_properties(smartcard-os.elf PROPERTIES
    LINK_DEPENDS "${SCV1_LINKER_SCRIPT}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

  # ---------------------------------------------------------- boot ROM -----
  #
  # A SEPARATE program, linked at address 0. It shares the startup code, the
  # semihosting shim and the UART transport with the OS -- those are properties
  # of the chip, not of either program -- but links libscos_boot instead of
  # libscos_core, so it cannot accidentally acquire a dependency on the OS it
  # is supposed to be able to load.

  set(SCV1_BOOT_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/src/hal/arm-scv1/scv1_boot.ld")

  add_executable(scv1-boot.elf
    src/hal/arm-scv1/boot_main.c
    src/hal/arm-scv1/startup.c
    src/hal/arm-scv1/semihost.c
    src/hal/arm-scv1/hal_arm_io.c)
  target_include_directories(scv1-boot.elf PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hal/arm-scv1")
  target_link_libraries(scv1-boot.elf PRIVATE scos_boot scos_warnings)
  target_link_options(scv1-boot.elf PRIVATE
    -T "${SCV1_BOOT_LINKER_SCRIPT}"
    -Wl,-Map=${CMAKE_BINARY_DIR}/scv1-boot.map
    -Wl,--cref
    -lgcc)
  set_target_properties(scv1-boot.elf PROPERTIES
    LINK_DEPENDS "${SCV1_BOOT_LINKER_SCRIPT}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

  add_custom_command(TARGET scv1-boot.elf POST_BUILD
    COMMAND "${CMAKE_OBJCOPY}" -O binary
            "$<TARGET_FILE:scv1-boot.elf>" "${CMAKE_BINARY_DIR}/scv1-boot.bin"
    COMMAND "${CMAKE_SIZE_UTIL}" "$<TARGET_FILE:scv1-boot.elf>"
    COMMENT "Building SCV1 boot ROM (scv1-boot.bin)")

  # The flash image. This is the artefact you would program into a chip.
  add_custom_command(TARGET smartcard-os.elf POST_BUILD
    COMMAND "${CMAKE_OBJCOPY}" -O binary
            "$<TARGET_FILE:smartcard-os.elf>" "${CMAKE_BINARY_DIR}/smartcard-os.bin"
    COMMAND "${CMAKE_OBJCOPY}" -O ihex
            "$<TARGET_FILE:smartcard-os.elf>" "${CMAKE_BINARY_DIR}/smartcard-os.hex"
    COMMAND "${CMAKE_SIZE_UTIL}" "$<TARGET_FILE:smartcard-os.elf>"
    COMMENT "Building SCV1 flash image (smartcard-os.bin / .hex)")
endif()

# ----------------------------------------------------------------- tests -----

include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

# --------------------------------------------------------------- summary -----

message(STATUS "")
message(STATUS "smartcard-os ${PROJECT_VERSION}")
message(STATUS "  build type   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  HAL          : ${SCOS_HAL}")
message(STATUS "  sanitizers   : ${SCOS_SANITIZE}")
message(STATUS "  -Werror      : ${SCOS_WERROR}")
message(STATUS "  static anal. : ${SCOS_STATIC_ANALYSIS}")
message(STATUS "  virtual chip : RAM ${SCOS_SIM_RAM_KB}K  ROM ${SCOS_SIM_ROM_KB}K  "
               "EEPROM ${SCOS_SIM_EEPROM_KB}K  FLASH ${SCOS_SIM_FLASH_KB}K")
if(CMAKE_CROSSCOMPILING)
  message(STATUS "  cross target : ${CMAKE_SYSTEM_PROCESSOR} via ${CMAKE_C_COMPILER}")
endif()
message(STATUS "")
