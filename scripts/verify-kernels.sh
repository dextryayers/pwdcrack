#!/usr/bin/env bash
# Verifies the CUDA kernel hash core on the host.
#
# The compression functions in engines/engine-cuda/src/kernels/hash_core.h are
# plain C with no device specific code, so the system C compiler can build them
# and they can be checked against digests produced by independent
# implementations. That is what this script does.
#
# Why it exists: the previous CUDA kernels contained six separate correctness
# defects, and none of them could be caught without a CUDA device on the build
# machine. This turns the arithmetic into something checkable everywhere, and
# leaves only the genuinely device specific parts unverified.
#
# What it does NOT verify, and this is stated plainly in docs/PHASE6_STATUS.md:
#   - kernel launch, grid and block sizing
#   - thread indexing and bounds checks
#   - shared memory usage
#   - global memory access patterns
#   - any measured throughput
#
# Usage: scripts/verify-kernels.sh

set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="$(mktemp -d)/host_verify"
mkdir -p "$(dirname "$OUT")"

echo "compiler: $($CC --version | head -1)"

# Build the expected-digest corpus with python hashlib. Lengths 0 through 200
# inclusive, because a multi-block digest that is wrong only at a block
# boundary is the classic failure here: 55 bytes fits one block, 56 needs two.
CORPUS=""
if command -v python3 >/dev/null 2>&1; then
    CORPUS="$(mktemp)"
    python3 - "$CORPUS" <<'PY'
import hashlib, sys
out = open(sys.argv[1], "w")
for n in range(201):
    # Same generator the C harness uses, so the two sides agree on the bytes.
    data = bytes(((k * 7 + (n % 13)) & 0xff) for k in range(n))
    out.write(f"{n} {hashlib.md5(data).hexdigest()}\n")
out.close()
PY
    echo "corpus: 201 lengths (0..200) generated with python hashlib"
else
    echo "warning: python3 not found, the length sweep will be skipped" >&2
fi

echo "compiling host harness..."
# The hash core lives in engines/kernel-common and is shared by the CUDA and
# OpenCL engines. Both include paths are needed: the engine directory has the
# forwarding header, the common directory has the real one.
"$CC" -O2 -std=c99 -Wall -Wextra \
    -I engines/engine-cuda/src/kernels -I engines/kernel-common \
    -o "$OUT" scripts/host_verify.c

if [ -n "$CORPUS" ]; then
    PWDCRACK_MD5_CORPUS="$CORPUS" "$OUT"
else
    "$OUT"
fi

# Cross check MD4 against openssl, since python 3.13 no longer ships md4 in
# hashlib and an MD4 bug would silently pass every other check here.
if command -v openssl >/dev/null 2>&1 && openssl dgst -md4 -provider legacy \
        -provider default </dev/null >/dev/null 2>&1; then
    echo
    echo "cross checking MD4 against openssl"
    # The harness already checks MD4 against fixed vectors; this confirms openssl
    # agrees with those same vectors, so the vectors themselves are not the
    # thing that is wrong.
    # '|' as the separator, not a space: the input contains a space and shell
    # word splitting here would hash "message" instead of "message digest".
    while IFS='|' read -r raw_msg expect_hex; do
        # Strip the leading space the heredoc introduces, otherwise the message
        # being hashed is " abc" rather than "abc".
        expect_msg="${raw_msg# }"
        got=$(printf '%s' "$expect_msg" | openssl dgst -md4 -provider legacy \
              -provider default 2>/dev/null | awk '{print $NF}')
        if [ "$got" != "$expect_hex" ]; then
            echo "FAIL openssl MD4 disagreement for '$expect_msg'"
            echo "  openssl $got"
            echo "  vectors $expect_hex"
            exit 1
        fi
    done <<'VECTORS'
 abc|a448017aaf21d8525fc10ae87aa6729d
message digest|d9130a8164549fe818874806e1c7014b
VECTORS
    echo "openssl agrees with the MD4 vectors used above"
else
    echo "note: openssl MD4 unavailable, skipping the openssl cross check"
fi

# Second stage: compile and run the real .cu kernel bodies on the host, through
# the shim in scripts/cuda_host_shim.c. This checks the kernel entry points, the
# thread to candidate mapping, the bounds check and the padding path, not just the
# compression functions.
echo
echo "building the kernel body test (host execution of the .cu sources)"
KERNEL_SHIM_DIR="$(mktemp -d)"
cat > "$KERNEL_SHIM_DIR/main.c" <<'SHIMEOF'
#include "cuda_host_shim.c"
SHIMEOF

if c++ -O2 -I engines/engine-cuda/src/kernels -I engines/kernel-common -I scripts \
      -o "$KERNEL_SHIM_DIR/kernel_test" "$KERNEL_SHIM_DIR/main.c" 2>"$KERNEL_SHIM_DIR/err"; then
    "$KERNEL_SHIM_DIR/kernel_test"
else
    echo "FAIL could not build the kernel body test"
    cat "$KERNEL_SHIM_DIR/err"
    exit 1
fi

echo
echo "hash core and MD5 kernel body verified on the host"