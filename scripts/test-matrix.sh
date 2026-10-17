#!/bin/bash
# ============================================================
# Feature combination matrix
# ============================================================
#
# Builds the workspace across every feature combination that matters, so a
# feature-gated compile error cannot hide behind a working default build.
#
# This exists because the project shipped three separate feature-gated compile
# errors (a `_args` used as `args`, an undefined `tested`, and calls to a
# `probe` function that did not exist). None of them appeared in a default
# build. The matrix is the gate that catches that class of defect.
#
# Usage:
#   scripts/test-matrix.sh          # check only (fast, no linking)
#   scripts/test-matrix.sh --build  # full build instead of cargo check
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

MODE="check"
if [ "${1:-}" = "--build" ]; then
    MODE="build"
fi

# Engines that require external toolchains or hardware are excluded from the
# default run. Each one is listed with the reason so the exclusion is explicit
# rather than silent.
#
#   engine-cuda    needs nvcc and the CUDA driver
#   engine-fpga    needs a PCIe device at /dev/fpga0 for runtime, builds without
#   engine-metal   needs an Apple toolchain for real device work
#   engine-sycl    has no Rust runtime binding available
#
# Set PWDC_MATRIX_FULL=1 to include them when the toolchain is available.

CORE_COMBINATIONS=(
    ""                          # default = tier-auto
    "tier-low"
    "tier-mid"
    "tier-high"
    "progress-simple"
    "progress-rich"
    "simd-detect"
    "mmap"
    "io-stream"
)

ENGINE_COMBINATIONS=(
    "engine-simd"
    "engine-gpu"
    "engine-fpga"
    "engine-jit"
    "engine-power"
    "engine-distributed"
    "engine-web"
    "engine-android"
    "engine-opencl"
    "engine-vulkan"
    "engine-metal"
    "engine-tpu"
    "engine-riscv"
    "engine-zen"
    "engine-xpu"
    "engine-dsp"
    "engine-tensor"
    "engine-embedded"
    "engine-hybrid"
    "engine-go"
    "engine-julia"
    "engine-wasm"
    "engine-warp"
    "engine-sycl"
    "android"
    "distributed"
)

EXTERNAL_TOOLCHAIN_ENGINES=(
    "engine-cuda"
)

BRIDGE_COMBINATIONS=(
    ""
    "python"
    "node"
    "perl"
)

declare -i PASS=0
declare -i FAIL=0
declare -a FAILED=()

run_one() {
    local package="$1"
    local features="$2"
    local label="${package}"
    [ -n "$features" ] && label="${package} [${features}]"

    printf '%-46s ' "$label"

    local args=(check -p "$package")
    [ "$MODE" = "build" ] && args=(build -p "$package")
    if [ -n "$features" ]; then
        args+=(--features "$features")
    fi

    if output=$(cargo "${args[@]}" 2>&1); then
        echo "ok"
        PASS+=1
        return 0
    fi

    echo "FAIL"
    FAIL+=1
    FAILED+=("$label")
    # Show only the diagnostics, not the full compiler invocation noise.
    echo "$output" | grep -E '^(error|warning: unused|  -->)' | head -12 | sed 's/^/      /'
    return 1
}

echo "=============================================="
echo " pwdcrack feature matrix (mode: $MODE)"
echo "=============================================="

echo
echo "--- root crate: tiers and core features ---"
for combo in "${CORE_COMBINATIONS[@]}"; do
    run_one "pwdcrack" "$combo"
done

echo
echo "--- engines: one feature at a time ---"
for engine in "${ENGINE_COMBINATIONS[@]}"; do
    skip=0
    if [ "${PWDC_MATRIX_FULL:-0}" != "1" ]; then
        for ext in "${EXTERNAL_TOOLCHAIN_ENGINES[@]}"; do
            [ "$engine" = "$ext" ] && skip=1
        done
    fi
    if [ "$skip" = "1" ]; then
        printf '%-46s skipped (needs external toolchain)\n' "$engine"
        continue
    fi
    run_one "pwdcrack" "$engine"
done

echo
echo "--- engine-bridge: each language bridge ---"
for combo in "${BRIDGE_COMBINATIONS[@]}"; do
    run_one "engine-bridge" "$combo"
done

echo
echo "=============================================="
printf ' passed: %d\n' "$PASS"
printf ' failed: %d\n' "$FAIL"
echo "=============================================="

if [ "$FAIL" -gt 0 ]; then
    echo "Failing combinations:"
    for f in "${FAILED[@]}"; do
        echo "  - $f"
    done
    exit 1
fi

echo "All combinations passed."
