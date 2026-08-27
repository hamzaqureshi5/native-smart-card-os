#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build.sh -- build and test the two configurations a developer uses.
#
#   host   native x86, simulator HAL, ASan + UBSan   -- where bugs are FOUND
#   arm    cross ARMv7-M Cortex-M3, arm-scv1 HAL     -- where the truth IS
#
# Develop in host. Believe arm. A green host with a red arm means working code
# that does not fit on a chip.
#
# The two need separate build trees because CMAKE_TOOLCHAIN_FILE is fixed at
# first configure: one cache cannot hold two compilers.
#
# usage:
#   tools/build.sh              both, build + test
#   tools/build.sh host         one only
#   tools/build.sh --release    host at -O2, sanitizers off (see below)
#   tools/build.sh --clean      wipe the tree first
#   tools/build.sh --no-test    build only
#
# CI runs a wider matrix (Release, ARMv6-M portability, the s3m228a HAL stub,
# clang-format). This script is deliberately not that.

set -u -o pipefail
cd "$(dirname "$0")/.."

BUILD_TYPE=Debug
SANITIZE=ON
TEST=1
CLEAN=0
WANT="host arm"
JOBS=$( (nproc 2>/dev/null || echo 4) )

for a in "$@"; do
    case "$a" in
    host|arm) WANT="$a" ;;
    --release)
        # Not the same check as Debug: -O2 enables warnings -O0 cannot produce
        # (-Wmaybe-uninitialized, -Wstringop-overflow) and NDEBUG removes every
        # assert(). Sanitizers go off because they change what the optimiser
        # sees. Neither build substitutes for the other.
        #
        # It also runs one test Debug cannot: os_fits_in_rom. Measuring the ROM
        # footprint under ASan is meaningless -- the instrumentation dwarfs the
        # code -- so the budget check is Release-only, and skipping Release
        # means skipping it.
        BUILD_TYPE=Release; SANITIZE=OFF ;;
    --no-test) TEST=0 ;;
    --clean)   CLEAN=1 ;;
    -j*)       JOBS=${a#-j} ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's|^# \{0,1\}||'; exit 0 ;;
    *) echo "build.sh: unknown argument '$a' (try --help)" >&2; exit 2 ;;
    esac
done

fail=0

build_one()
{
    local name=$1 dir flags
    if [ "$name" = host ]; then
        # Debug and Release get separate trees. Sharing one would mean every
        # --release run reconfigures the Debug tree and the next plain run
        # reconfigures it back, so the two full rebuilds would make the fast
        # dev loop the slowest thing in the project.
        dir=$( [ "$BUILD_TYPE" = Release ] && echo build-rel || echo build )
        flags="-DSCOS_HAL=simulator -DSCOS_SANITIZE=$SANITIZE"
    else
        dir=build-arm
        # Sanitizers are impossible on bare metal -- ASan needs a heap and
        # somewhere to report, and the chip has neither.
        flags="-DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-arm-scv1.cmake"
        flags="$flags -DSCOS_HAL=arm-scv1 -DSCOS_SANITIZE=OFF"
        if ! command -v arm-none-eabi-gcc >/dev/null; then
            echo ">>> arm: SKIPPED, no arm-none-eabi-gcc"
            echo "    a skip is not a pass -- install gcc-arm-none-eabi"
            return 0
        fi
    fi

    echo ""
    echo ">>> $name  ($BUILD_TYPE, sanitizers $( [ "$name" = arm ] && echo OFF || echo "$SANITIZE" ))"

    # A stale CMakeCache keeps the OLD value of any flag not passed again,
    # which is how a build silently stops checking what you think it checks.
    [ "$CLEAN" = 1 ] && rm -rf "$dir"

    # Every flag stated explicitly, including ones at their default: relying on
    # a default means a change to CMakeLists.txt silently changes this check.
    if ! cmake -S . -B "$dir" \
            -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
            -DSCOS_WERROR=ON \
            $flags > "$dir.log" 2>&1; then
        echo "configure FAILED -- $dir.log"; tail -15 "$dir.log"; fail=1; return
    fi

    if ! cmake --build "$dir" -j"$JOBS" >> "$dir.log" 2>&1; then
        echo "build FAILED -- $dir.log"
        grep -E "error:" "$dir.log" | head -15; fail=1; return
    fi
    grep "warning:" "$dir.log" | head -10

    if [ "$TEST" = 1 ]; then
        if ! ctest --test-dir "$dir" --output-on-failure >> "$dir.log" 2>&1; then
            echo "tests FAILED -- $dir.log"
            sed -n '/The following tests FAILED/,$p' "$dir.log"; fail=1; return
        fi
        grep -E "tests passed" "$dir.log" | tail -1 | sed 's/^/    /'
    fi

    # The boot ROM has a hard 8 KB ceiling and the OS a 32 KB one. A build that
    # succeeds while nearly full is worth seeing before it stops succeeding.
    if [ "$name" = arm ] && command -v arm-none-eabi-size >/dev/null; then
        arm-none-eabi-size "$dir"/*.elf 2>/dev/null | sed 's/^/    /'
    fi
}

for w in $WANT; do build_one "$w"; done

echo ""
if [ "$fail" -ne 0 ]; then echo "FAILED"; exit 1; fi
echo "OK"
