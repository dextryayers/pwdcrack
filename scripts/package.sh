#!/bin/bash
# ============================================================
# Package pwdcrack for distribution
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VERSION="${1:-$(git describe --tags 2>/dev/null || echo "0.1.0")}"
OUTPUT="pwdcrack-${VERSION}-x86_64-linux"

echo "Packaging pwdcrack v$VERSION..."

# Ensure release build exists
cargo build --release --features tier-high 2>/dev/null

# Create package directory
mkdir -p "$OUTPUT"/{bin,lib,share/pwdcrack,config}

# Binary
cp target/release/pwdcrack "$OUTPUT/bin/"
strip "$OUTPUT/bin/pwdcrack"

# Shared library (if exists)
[ -f target/release/libcrack-core.so ] && \
    cp target/release/libcrack-core.so "$OUTPUT/lib/"

# Configs
cp configs/*.toml "$OUTPUT/config/" 2>/dev/null || true

# Rules
cp -r rules "$OUTPUT/share/pwdcrack/" 2>/dev/null || true

# Documentation
cp README.md LICENSE "$OUTPUT/" 2>/dev/null || true
cp ARCHITECTURE.md "$OUTPUT/share/pwdcrack/"

# Create tarball
tar czf "${OUTPUT}.tar.gz" "$OUTPUT"
rm -rf "$OUTPUT"

echo "Package: ${OUTPUT}.tar.gz"
ls -lh "${OUTPUT}.tar.gz"
