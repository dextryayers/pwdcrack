#!/usr/bin/env bash
#
# Builds the Python wheel, installs it into a throwaway prefix, and runs the
# Python test suite against the installed package.
#
# P11.1.01 asks for "a py.typed marker and a maturin build". A maturin build that
# is never imported proves nothing, so this installs what it built and imports
# that, rather than importing from a cargo target directory.
#
# The install prefix is temporary and the tests are run with it first on
# PYTHONPATH, so an already installed pwdcrack cannot satisfy the import and hide
# a broken wheel.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$ROOT/engines/engine-bridge"
WORK="${TMPDIR:-/tmp}/pwdcrack-python-$$"
PREFIX="$WORK/prefix"
WHEELS="$WORK/wheels"

command -v python3 >/dev/null 2>&1 || { echo "no python3 on PATH" >&2; exit 2; }

MATURIN="${MATURIN:-}"
if [ -z "$MATURIN" ]; then
    if command -v maturin >/dev/null 2>&1; then
        MATURIN="maturin"
    elif [ -x "$HOME/.local/bin/maturin" ]; then
        MATURIN="$HOME/.local/bin/maturin"
    else
        echo "maturin not found. Install it with: pip install maturin" >&2
        exit 2
    fi
fi

mkdir -p "$WHEELS"
trap 'rm -rf "$WORK"' EXIT

echo "building the wheel with maturin"
# --manifest-path must be the Cargo.toml: maturin requires pyproject.toml to sit
# beside it, which is why the Python sources live under python/ rather than next
# to the manifest.
"$MATURIN" build --manifest-path "$CRATE/Cargo.toml" --out "$WHEELS" 2>&1 | tail -3

WHEEL="$(find "$WHEELS" -name '*.whl' -print -quit)"
[ -n "$WHEEL" ] || { echo "no wheel was produced" >&2; exit 2; }
echo "built $(basename "$WHEEL")"

echo "installing into a throwaway prefix"
python3 -m pip install --quiet --no-deps --target "$PREFIX" "$WHEEL"

echo "checking the wheel ships py.typed"
if [ ! -f "$PREFIX/pwdcrack/py.typed" ]; then
    echo "py.typed is not in the wheel, so type checkers would treat pwdcrack as untyped" >&2
    exit 1
fi
echo "  present"

echo "running the Python test suite against the installed wheel"
# PYTHONPATH first so the throwaway prefix wins over anything already installed.
PYTHONPATH="$PREFIX" PYTHONNOUSERSITE=1 \
    python3 "$CRATE/python/tests/test_bridge.py" 2>&1 | tail -25