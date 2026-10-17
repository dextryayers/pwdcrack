#!/usr/bin/env bash
#
# Builds and runs the Perl bridge suite.
#
# P11.1.03: "Write pwdcrack.xs for Perl, or remove the Perl bridge."
#
# The XS file existed but declared an ABI that does not exist in
# engines/engine-bridge/src/c_api.rs: six wrong function names, a wrong arity,
# a wrong return type, and one function that was never written. It had never
# been compiled. This script compiles it and runs the tests, which is the only
# way that stays true.
#
# Static link against the Rust archive, so there is no LD_LIBRARY_PATH to get
# wrong at run time.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/engines/engine-bridge/perl"
PROFILE="${PROFILE:-debug}"

command -v perl >/dev/null 2>&1 || { echo "no perl on PATH" >&2; exit 2; }
command -v xsubpp >/dev/null 2>&1 || { echo "no xsubpp; install the perl development headers" >&2; exit 2; }

CARGO_ARGS=()
[ "$PROFILE" = "release" ] && CARGO_ARGS+=(--release)

echo "building the Rust archive ($PROFILE)"
cargo build -p engine-bridge "${CARGO_ARGS[@]}" 2>&1 | tail -1

ARCHIVE_DIR="$ROOT/target/$PROFILE"
[ -f "$ARCHIVE_DIR/libengine_bridge.a" ] || {
    echo "archive not found: $ARCHIVE_DIR/libengine_bridge.a" >&2
    exit 2
}

# The build happens in a copy, because XS generates pwdcrack.c, Makefile and
# blib in the source directory and those should not be left behind.
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/pwdcrack-perl-XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT
cp -r "$SRC/." "$BUILD/"

cd "$BUILD"
echo "generating and compiling the XS glue"
# Absolute, because Makefile.PL is run from the scratch directory.
PWDCRACK_LIB_DIR="$ARCHIVE_DIR" PROFILE="$PROFILE" perl Makefile.PL 2>&1 | tail -3
make 2>&1 | tail -15

echo "running t/*.t"
# -Mblib so the tests load the module that was just built rather than any
# installed copy that happens to be on the path.
PERL5LIB="$BUILD/blib/lib:$BUILD/blib/arch" prove -Mblib -v t/ 2>&1 | tail -30