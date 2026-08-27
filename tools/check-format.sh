#!/bin/sh
# SPDX-License-Identifier: MIT
#
# check-format.sh -- verify (or apply) the project's clang-format style.
#
#   tools/check-format.sh          check, and print a diff for anything wrong
#   tools/check-format.sh --fix    reformat in place
#
# CI runs the check form. Run the --fix form before committing and the check
# can never fail on you.
#
# THE VERSION IS PINNED, and that is not fussiness: clang-format's output
# changes between releases, so an unpinned check fails whenever the CI runner's
# distro moves on, for reasons that have nothing to do with the code. The pin
# below must match .github/workflows/ci.yml.
#
#   pip install clang-format==23.1.0
#
# A different version will probably work, and will probably also produce a
# handful of spurious diffs. If yours disagrees, that is the reason.

set -eu

WANT_VERSION=23.1.0
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CF=${CLANG_FORMAT:-clang-format}
FIX=0

[ "${1:-}" = "--fix" ] && FIX=1

if ! command -v "$CF" >/dev/null 2>&1; then
    cat >&2 <<MSG
check-format.sh: $CF not found.

Install the pinned version:
  pip install --user clang-format==$WANT_VERSION

Or point at one you have:
  CLANG_FORMAT=clang-format-19 tools/check-format.sh
MSG
    exit 1
fi

HAVE=$("$CF" --version | sed 's/.*version \([0-9.]*\).*/\1/')
if [ "$HAVE" != "$WANT_VERSION" ]; then
    echo "check-format.sh: note -- using clang-format $HAVE, project pins $WANT_VERSION" >&2
fi

# Only our own sources. Nothing generated, nothing vendored.
#
# Note what is NOT listed: third_party/. Reformatting a vendored submodule
# would turn it into a fork whose next update is a merge conflict on every
# line, and third-party code is compiled as its authors intended (see the
# -w in CMakeLists.txt for the same reason). The -prune below makes that a
# stated exclusion rather than an accident of this list.
#
FILES=$(cd "$ROOT" && find src include simulator tests \
        -path './third_party' -prune -o \
        -name '*.c' -o -name '*.h' | sort)

BAD=""
for f in $FILES; do
    if [ "$FIX" -eq 1 ]; then
        "$CF" -i "$ROOT/$f"
    elif ! "$CF" "$ROOT/$f" | diff -q "$ROOT/$f" - >/dev/null 2>&1; then
        BAD="$BAD $f"
    fi
done

if [ "$FIX" -eq 1 ]; then
    echo "check-format.sh: reformatted $(echo "$FILES" | wc -w) files"
    exit 0
fi

if [ -n "$BAD" ]; then
    echo "check-format.sh: these files are not formatted:" >&2
    for f in $BAD; do
        echo "  $f" >&2
    done
    echo >&2
    for f in $BAD; do
        "$CF" "$ROOT/$f" | diff -u "$ROOT/$f" - | head -40
    done
    echo >&2
    echo "Fix with: tools/check-format.sh --fix" >&2
    exit 1
fi

echo "check-format.sh: $(echo "$FILES" | wc -w) files, all formatted"
