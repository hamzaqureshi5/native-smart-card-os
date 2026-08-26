# SPDX-License-Identifier: MIT
#
# CMake toolchain for the SCV1 target (ARM Cortex-M3, bare metal).
#
# Use:
#   cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake
#
# There is no operating system on the target, so CMAKE_SYSTEM_NAME is Generic.
# That is what stops CMake looking for host libraries and pkg-config.

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(SCOS_CROSS_PREFIX "arm-none-eabi-" CACHE STRING "Cross-toolchain prefix")

set(CMAKE_C_COMPILER   "${SCOS_CROSS_PREFIX}gcc")
set(CMAKE_ASM_COMPILER "${SCOS_CROSS_PREFIX}gcc")
set(CMAKE_AR           "${SCOS_CROSS_PREFIX}ar")
set(CMAKE_OBJCOPY      "${SCOS_CROSS_PREFIX}objcopy" CACHE FILEPATH "")
set(CMAKE_OBJDUMP      "${SCOS_CROSS_PREFIX}objdump" CACHE FILEPATH "")
set(CMAKE_SIZE_UTIL    "${SCOS_CROSS_PREFIX}size"    CACHE FILEPATH "")

# The toolchain cannot link a hosted test executable (no libc, no startup), so
# probe it by building a static library instead.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(SCV1_ARCH_FLAGS "-mcpu=cortex-m3 -mthumb -mfloat-abi=soft")

# -ffreestanding: no hosted-environment assumptions.
# -fno-common: two definitions of the same global become a link error rather
#   than being silently merged -- worth having in code that must be auditable.
# -fno-builtin-*: keep the compiler from turning our own primitives into calls
#   back into themselves.
set(CMAKE_C_FLAGS_INIT
    "${SCV1_ARCH_FLAGS} -ffreestanding -fno-common -fdata-sections -ffunction-sections")

# --gc-sections: drop unreferenced code, which matters when ROM is 64 KB.
# -nostdlib with -lgcc: no libc, but keep the compiler's own helper routines
#   (64-bit shifts, division) which the codegen may emit without a source call.
set(CMAKE_EXE_LINKER_FLAGS_INIT
    "${SCV1_ARCH_FLAGS} -nostdlib -Wl,--gc-sections -Wl,--no-warn-rwx-segments")

# Search the target sysroot for libraries, the host for programs.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM BEFORE)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
