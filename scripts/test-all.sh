#!/bin/bash
# ============================================================
# Run all pwdcrack tests across feature sets
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== pwdcrack Test Suite ==="
echo ""

FEATURES=(
    "default"
    "tier-low"
    "tier-mid"
    "tier-high"
)

for feat in "${FEATURES[@]}"; do
    echo "--- Testing features: $feat ---"
    cargo test --features "$feat" 2>&1 | tail -5
    echo ""
done

echo "=== All tests passed ==="
