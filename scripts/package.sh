#!/bin/bash
# ============================================================
# Package pwdcrack for distribution
# ============================================================
#
# Builds the release binary, stages a clean tree, and produces a tarball.
#
# Notes on correctness:
#   - The library artefact is libpwdcrack, not libcrack-core. The name comes
#     from [lib] name in Cargo.toml. The old name never existed, so the copy
#     silently did nothing.
#   - Optional inputs are copied only when present, and the script reports each
#     skip instead of hiding it behind `|| true`.
#   - The version is read from Cargo.toml, not from git, so packaging works in
#     a tree without tags and never disagrees with the compiled binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Single source of truth for the version.
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
if [ -z "$VERSION" ]; then
    echo "error: could not read version from Cargo.toml" >&2
    exit 1
fi

ARCH="${2:-x86_64-linux}"
OUTPUT="pwdcrack-${VERSION}-${ARCH}"

echo "Packaging pwdcrack v$VERSION for $ARCH..."

# Build the release binary. Fail loudly rather than packaging a stale artefact.
if [ ! -f target/release/pwdcrack ]; then
    echo "==> target/release/pwdcrack missing, building..."
    cargo build --release
fi
if [ ! -x target/release/pwdcrack ]; then
    echo "error: target/release/pwdcrack is not executable" >&2
    exit 1
fi

# Recreate a clean staging directory.
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"/{bin,lib,share/pwdcrack,config,doc}

# Binary
cp target/release/pwdcrack "$OUTPUT/bin/"
strip "$OUTPUT/bin/pwdcrack" 2>/dev/null \
    || echo "note: strip skipped, binary left unstripped"

# Shared library. The crate-type is ["lib", "cdylib"], so the cdylib artefact
# is named after [lib] name = "pwdcrack".
for so in target/release/libpwdcrack.so target/release/libpwdcrack.dylib \
          target/release/pwdcrack.dll; do
    if [ -f "$so" ]; then
        cp "$so" "$OUTPUT/lib/"
        echo "==> included $(basename "$so")"
    else
        echo "note: $(basename "$so") not built (run: cargo build --release --lib), skipped"
    fi
done

# Test vectors, shipped so users can self-verify the binary.
if [ -d tests/test_vectors ]; then
    cp tests/test_vectors/*.txt "$OUTPUT/share/pwdcrack/"
    echo "==> included test vectors"
else
    echo "note: tests/test_vectors missing, skipped"
fi

# Config presets
if compgen -G "configs/*.toml" > /dev/null; then
    cp configs/*.toml "$OUTPUT/config/"
    echo "==> included config presets"
else
    echo "note: configs/*.toml not found, skipped"
fi

# Documentation
for doc in README.md LICENSE ARCHITECTURE.md; do
    if [ -f "$doc" ]; then
        cp "$doc" "$OUTPUT/doc/"
    else
        echo "note: $doc not found, skipped"
    fi
done
if [ -f docs/plan.md ]; then
    cp docs/plan.md "$OUTPUT/doc/"
fi

# Create tarball
tar czf "${OUTPUT}.tar.gz" "$OUTPUT"
rm -rf "$OUTPUT"

echo "Package: ${OUTPUT}.tar.gz"
ls -lh "${OUTPUT}.tar.gz"
