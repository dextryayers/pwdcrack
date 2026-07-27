#!/bin/bash
# ============================================================
# Build pwdcrack for ALL platforms
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== pwdcrack Multi-Platform Build ==="
echo "Date: $(date)"
echo "Rust: $(rustc --version)"
echo ""

BUILDS=(
    # Format: "target|features|description"
    "x86_64-unknown-linux-gnu|tier-high|x86_64 Linux (High-End)"
    "x86_64-unknown-linux-gnu|tier-mid|x86_64 Linux (Mid-Range)"
    "i686-unknown-linux-gnu|tier-low|i686 Linux (32-bit Low-End)"
    "aarch64-unknown-linux-gnu|tier-mid|AArch64 Linux (ARM64 Mid)"
    "armv7-unknown-linux-gnueabihf|tier-low|ARMv7 Linux (32-bit Low)"
)

for build in "${BUILDS[@]}"; do
    IFS='|' read -r target features desc <<< "$build"
    echo "--- $desc ($target) ---"
    rustup target add "$target" 2>/dev/null || true
    cargo build --release --target "$target" --features "$features" 2>&1 | tail -3
    echo ""
done

echo "=== Build Complete ==="
echo "Binaries:"
find target -name "pwdcrack" -type f -executable 2>/dev/null | while read f; do
    file "$f" | head -1
    ls -lh "$f" | awk '{print "  Size:", $5}'
done
