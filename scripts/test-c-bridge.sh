#!/usr/bin/env bash
#
# Builds and runs the C bridge suite.
#
# P11.1.07: "Add a C test suite compiled in CI that exercises every exported
# symbol and verifies the memory contract for crack_get_result."
#
# This is that. It compiles tests/c/test_bridge.c with the system C compiler and
# links it against the static library, then runs it. The Rust suite at
# tests/ffi_roundtrip.rs covers the same ground, but it links the rlib and
# resolves symbol names at compile time, so it cannot demonstrate that the
# symbols are reachable through a C ABI. This can.
#
# The static library is built with unwind rather than abort, because the suite
# links against it directly and an aborting build would make any panic fatal to
# the test process instead of an error code. See docs/PHASE11_STATUS.md.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/engines/engine-bridge"
WORK="${TMPDIR:-/tmp}/pwdcrack-c-bridge-$$"

CC="${CC:-cc}"
command -v "$CC" >/dev/null 2>&1 || {
    echo "no C compiler: set CC, or install one" >&2
    exit 2
}

mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# Which profile to build the static library with. The test binary has to link
# the archive from the same profile that produced it, so this decides both.
#
# Debug by default: this checks linkage, symbol visibility and behaviour, none of
# which a release profile changes, and a release build of this workspace needs a
# writable target/release. Override with PROFILE=release when that is writable.
PROFILE="${PROFILE:-debug}"

CARGO_ARGS=()
[ "$PROFILE" = "release" ] && CARGO_ARGS+=(--release)

echo "building libengine_bridge.a ($PROFILE)"
cargo build -p engine-bridge "${CARGO_ARGS[@]}" 2>&1 | tail -1

# The package is named engine-bridge, so cargo names the archive
# libengine_bridge.a. The libcrack-core name the header comment refers to is the
# product name, not the artefact name; there is no libcrack_bridge.a and looking
# for one is how this file spent a while finding nothing.
STATIC="$ROOT/target/$PROFILE/libengine_bridge.a"
[ -f "$STATIC" ] || {
    echo "static library not found at $STATIC" >&2
    exit 2
}

echo "compiling tests/c/test_bridge.c"
# -Wall -Wextra so a mismatched declaration against the real ABI is a warning
# here rather than undefined behaviour at run time.
"$CC" -std=c11 -Wall -Wextra -O1 \
    "$SRC/tests/c/test_bridge.c" \
    "$STATIC" \
    -lpthread -ldl -lm \
    -o "$WORK/test_bridge"

echo "running"
"$WORK/test_bridge"