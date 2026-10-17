#!/usr/bin/env bash
#
# Builds the Node addon and runs the JavaScript test suite against it.
#
# P11.1.02: "Complete the Node N-API binding with a promise based asynchronous
# API."
#
# The previous node.rs declared the N-API C functions by hand, read one argument
# into a 256 byte buffer, discarded it, and returned the literal string "ok".
# Nothing verified anything, the returned pointer came from a CString that had
# already been dropped, and a password over 256 bytes was silently truncated.
#
# The tests need a real Node process, because the promise machinery and the
# N-API string handling only exist once Node is loaded. A Rust test cannot check
# either.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$ROOT/engines/engine-bridge"
NODEDIR="$CRATE/node"
WORK="${TMPDIR:-/tmp}/pwdcrack-node-$$"

command -v node >/dev/null 2>&1 || { echo "no node on PATH" >&2; exit 2; }

PROFILE="${PROFILE:-debug}"
CARGO_ARGS=()
[ "$PROFILE" = "release" ] && CARGO_ARGS+=(--release)

echo "building the addon ($PROFILE)"
cargo build -p engine-bridge --features node "${CARGO_ARGS[@]}" 2>&1 | tail -1

# Node loads an addon by its .node suffix. The cdylib cargo produced is a .so,
# so it is copied under the name Node expects rather than symlinked: a symlink
# left behind by an interrupted run is a confusing failure later.
ADDON="$ROOT/target/$PROFILE/libengine_bridge.so"
[ -f "$ADDON" ] || { echo "addon not built: $ADDON" >&2; exit 2; }
# grep -q exits the moment it matches, which closes the pipe; nm then dies of
# SIGPIPE and, under `set -o pipefail`, the whole pipeline reports failure. So
# the symbol table is captured first and searched afterwards.
if ! nm -D "$ADDON" 2>/dev/null | grep napi_register_module_v1 > /dev/null; then
    echo "$ADDON has no napi_register_module_v1, so Node cannot load it" >&2
    exit 1
fi

# Both the addon and the test go into the scratch directory, and the test runs
# from there. The test does `require('./pwdcrack.node')`, which Node resolves
# relative to the test file, so the two have to be side by side. Building in the
# source tree instead would leave a `pwdcrack.node` behind that nothing tracks.
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT
cp "$ADDON" "$WORK/pwdcrack.node"
cp "$NODEDIR/test_bridge.js" "$WORK/test_bridge.js"
if [ -f "$NODEDIR/pwdcrack.d.ts" ]; then
    cp "$NODEDIR/pwdcrack.d.ts" "$WORK/pwdcrack.d.ts"
fi

echo "running node --test"
cd "$WORK"
node --test test_bridge.js 2>&1 | tail -30