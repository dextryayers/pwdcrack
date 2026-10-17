#!/usr/bin/env bash
# Unpack a private Icarus Verilog, without root, so scripts/simulate.sh can run.
#
# # Why this exists
#
# `sudo apt-get install iverilog` needs a password on most machines, and a build
# gate that needs a password is a gate nobody runs. The Debian package unpacks
# into any directory the user can write to, and the unpacked tree is self
# contained: it needs IVL_ROOT pointing at it and nothing else.
#
# The one non obvious step is the symlink. The Debian build resolves its own root
# relative to `usr/x86_64-linux-gnu`, which does not exist inside the package
# because on a real system it is a symlink into `usr/lib`. Without it, iverilog
# reports a missing IVL_ROOT and every compile fails with no useful message.
#
# A system iverilog is always preferred. This is the fallback for machines where
# there is not one.
#
# # Usage
#
#   scripts/setup-iverilog.sh              unpack into /tmp/pwdcrack-iverilog
#   IVL_PREFIX=/somewhere scripts/setup-iverilog.sh
#   scripts/setup-iverilog.sh --path       print the PATH line and exit

set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="${IVL_PREFIX:-/tmp/pwdcrack-iverilog}"

if [ "${1:-}" = "--path" ]; then
    echo "export IVL_ROOT=$PREFIX/usr/lib/x86_64-linux-gnu/ivl"
    echo "export PATH=$PREFIX/usr/lib/x86_64-linux-gnu/ivl:$PREFIX/usr/bin:\$PATH"
    exit 0
fi

if [ -x "$PREFIX/usr/bin/iverilog" ]; then
    echo "already unpacked at $PREFIX"
    scripts/setup-iverilog.sh --path
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "fetching the iverilog package"
( cd "$WORK" && apt-get download iverilog )

DEB="$(find "$WORK" -name 'iverilog_*.deb' | head -1)"
if [ -z "$DEB" ]; then
    echo "could not download iverilog" >&2
    echo "install it with sudo, or set IVL_PREFIX to an existing tree" >&2
    exit 1
fi

echo "unpacking into $PREFIX"
mkdir -p "$PREFIX"
dpkg-deb -x "$DEB" "$PREFIX"

# The symlink the package expects but does not ship.
if [ ! -e "$PREFIX/usr/x86_64-linux-gnu" ]; then
    ln -s lib/x86_64-linux-gnu "$PREFIX/usr/x86_64-linux-gnu"
fi

chmod +x "$PREFIX"/usr/bin/* 2>/dev/null || true

if ! "$PREFIX/usr/bin/iverilog" -V >/dev/null 2>&1; then
    echo "iverilog unpacked but will not run. Check IVL_ROOT:" >&2
    "$PREFIX/usr/bin/iverilog" -V 2>&1 | head -3 >&2
    exit 1
fi

echo "iverilog $("$PREFIX/usr/bin/iverilog" -V 2>&1 | head -1 | sed 's/.*version //')"
echo
scripts/setup-iverilog.sh --path
echo
echo "add those two lines to your shell, or run scripts/simulate.sh which"
echo "finds this tree on its own."