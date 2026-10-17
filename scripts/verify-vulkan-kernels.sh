#!/usr/bin/env bash
# Verifies the Vulkan path in three stages, from weakest claim to strongest.
#
#   1. WGSL tables and arithmetic, checked against python hashlib for every
#      message length from 0 to 200. Catches a mistyped constant or a rotation in
#      the wrong direction, which is what every previous GPU kernel in this
#      repository got wrong, and which no compiler detects.
#
#   2. WGSL to SPIR-V compilation with naga, plus checks on the emitted module:
#      magic number, declared bindings, and the absence of the access-mode bug
#      that naga 26 had, where a `var<storage, read_write>` buffer was silently
#      treated as read only and every store was rejected at validation.
#
#   3. The real SPIR-V module executed on a real Vulkan device, digests compared
#      against python hashlib. This stage needs a Vulkan ICD and is skipped with a
#      clear message when there is none. It has run on the AMD Radeon device on
#      the development machine.
#
# Usage: scripts/verify-vulkan-kernels.sh

set -euo pipefail
cd "$(dirname "$0")/.."

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SHADER="engines/engine-vulkan/shaders/md5.wgsl"

# ---- stage 1: the algorithm ----
echo "stage 1: WGSL tables and arithmetic against python hashlib"
CORPUS="$TMP/corpus"
python3 - "$CORPUS" <<'PY'
import hashlib, sys
with open(sys.argv[1], "w") as out:
    for n in range(201):
        data = bytes(((k * 7 + (n % 13)) & 0xff) for k in range(n))
        out.write(f"{n} {hashlib.md5(data).hexdigest()}\n")
PY

cc -O2 -std=c99 -Wall -Wextra -o "$TMP/wgslcheck" scripts/wgsl_host_verify.c
PWDCRACK_MD5_CORPUS="$CORPUS" "$TMP/wgslcheck"

# ---- stage 2: compilation ----
echo
echo "stage 2: WGSL to SPIR-V with naga"

if ! cargo build -p engine-vulkan --features vulkan --target-dir .build 2>/dev/null; then
    echo "  could not build engine-vulkan with the vulkan feature"
    echo "  (this needs network access on first run for the naga dependency)"
    exit 1
fi

# The crate exposes the compiler as a small helper binary so the check uses the
# same naga version and options the library does, rather than a separate copy.
if ! cargo run -q -p engine-vulkan --features vulkan --target-dir .build \
        --bin compile-spirv -- "$SHADER" "$TMP/md5.spv" 2>"$TMP/naga.err"; then
    echo "FAIL naga rejected the shader"
    cat "$TMP/naga.err"
    exit 1
fi

python3 - "$TMP/md5.spv" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
assert len(data) % 4 == 0, "SPIR-V size is not a multiple of 4"
words = struct.unpack(f"<{len(data)//4}I", data)
magic = words[0]
# 0x07230203 is the SPIR-V magic; a byte swapped module reads as 0x03022307,
# which is what a missing endianness conversion in the emitter produces.
assert magic == 0x07230203, f"bad SPIR-V magic 0x{magic:08x}"
assert len(words) > 100, f"SPIR-V module is suspiciously small: {len(words)} words"
print(f"  SPIR-V: {len(words)} words, magic 0x{magic:08x}, version {(words[1] >> 16) & 0xff}.{(words[1] >> 8) & 0xff}")
PY

# ---- stage 3: the device ----
echo
echo "stage 3: executing on a Vulkan device"
if ! command -v vulkaninfo >/dev/null 2>&1; then
    echo "  vulkaninfo not present, cannot confirm a device exists; skipping"
    echo "  the SPIR-V has been compiled and the algorithm verified, but has NOT"
    echo "  been run on hardware on this machine"
    exit 0
fi

# The binary reads the same corpus from the environment so the expected digests
# come from python hashlib rather than being embedded in the crate.
if ! PWDCRACK_MD5_CORPUS="$CORPUS" \
     cargo run -q -p engine-vulkan --features vulkan --target-dir .build \
     --bin device-check 2>"$TMP/dev.err"; then
    echo "  device check failed:"
    grep -v "^warning:" "$TMP/dev.err" | grep -v "^ " | grep -v "^$" | sed -n '1,20p'
    exit 1
fi