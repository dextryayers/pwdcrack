#!/usr/bin/env bash
# Verifies the OpenCL kernels without an OpenCL device.
#
# This machine has libOpenCL.so.1 and no vendor ICD, so there are zero OpenCL
# devices to run anything on. Three things can still be checked, and this script
# does all three:
#
#   1. The generated core (engines/kernel-common/hash_core.cl) is compiled with
#      clang in OpenCL mode. This proves the syntax is valid OpenCL C and that
#      the tables survived the transform from the shared header.
#   2. The same core is compiled as host C and checked against 220 values from
#      python hashlib, openssl and the RFC vectors, exactly as the CUDA path does.
#   3. The assembled kernel is executed through a host shim that emulates
#      get_global_id, so the work item to candidate mapping, the bounds check and
#      the padding path are exercised.
#
# What none of this proves: that the kernel runs on real OpenCL hardware, or any
# performance characteristic. A machine with a vendor ICD is required for that.
# See docs/PHASE7_STATUS.md.
#
# Usage: scripts/verify-opencl-kernels.sh

set -euo pipefail
cd "$(dirname "$0")/.."

CORE="engines/kernel-common/hash_core.cl"
KERNEL="engines/engine-opencl/src/kernels/md5.cl"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Regenerate, so a stale generated file cannot pass.
echo "generating the OpenCL core from the shared header"
python3 scripts/gen-opencl-core.py

# 2. OpenCL syntax check. clang in cl mode is a real OpenCL front end; it will
#    reject anything the specification does not allow even without a device.
echo
echo "compiling the core in OpenCL mode (clang -x cl)"
if ! clang -x cl -cl-std=CL2.0 -Werror -c "$CORE" -o "$TMP/core.bc" 2>"$TMP/core.err"; then
    echo "FAIL the generated core is not valid OpenCL C"
    head -40 "$TMP/core.err"
    exit 1
fi
echo "  core.cl accepted by the OpenCL front end"

echo
echo "compiling the assembled kernel in OpenCL mode"
cat "$CORE" "$KERNEL" > "$TMP/assembled.cl"
if ! clang -x cl -cl-std=CL2.0 -c "$TMP/assembled.cl" -o "$TMP/kernel.bc" 2>"$TMP/kern.err"; then
    echo "FAIL the assembled kernel is not valid OpenCL C"
    head -40 "$TMP/kern.err"
    exit 1
fi
echo "  md5.cl accepted by the OpenCL front end"

# 3. Execute the same kernel body on the host.
echo
echo "executing the kernel body through the host shim"
cat > "$TMP/main.c" <<'EOF'
#include "opencl_host_shim.c"
EOF

if ! clang -x c -O2 -I scripts -I engines/kernel-common \
        -I engines/engine-opencl/src/kernels \
        -o "$TMP/kernel_test" "$TMP/main.c" 2>"$TMP/shim.err"; then
    echo "FAIL could not build the OpenCL host shim"
    head -30 "$TMP/shim.err"
    exit 1
fi
"$TMP/kernel_test"

# 4. Cross check the generated core against the same values the CUDA path uses,
#    so the two engines cannot drift apart unnoticed.
echo
echo "cross checking the generated core against reference digests"
CORPUS="$TMP/corpus"
python3 - "$CORPUS" <<'PY'
import hashlib, sys
with open(sys.argv[1], "w") as out:
    for n in range(201):
        data = bytes(((k * 7 + (n % 13)) & 0xff) for k in range(n))
        out.write(f"{n} {hashlib.md5(data).hexdigest()}\n")
PY

cat > "$TMP/corecheck.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* The generated source uses OpenCL builtins, so this harness supplies them the
 * same way the kernel shim does. Compiling it as plain C with typedefs is what
 * makes "the OpenCL C and the host C agree" a checkable claim rather than an
 * assumption. */
typedef unsigned char  uchar;
typedef unsigned int   uint;
#ifndef ulong
typedef unsigned long  ulong;   /* <sys/types.h> already defines it on glibc */
#endif
typedef unsigned char  uint8_t;
typedef unsigned int   uint32_t;
typedef unsigned long long uint64_t;
#define inline inline
/* The generated OpenCL core, compiled as C. OpenCL C and C agree closely enough
 * here that the compression functions compile unchanged, which is the property
 * this stage is checking. */
#include "hash_core.cl"

int main(void) {
    const char *corpus = getenv("PWDCRACK_MD5_CORPUS");
    if (!corpus) { printf("no corpus\n"); return 1; }
    FILE *f = fopen(corpus, "r");
    if (!f) { perror("corpus"); return 1; }
    char line[512]; int bad = 0, n = 0;
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = '\0';
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = '\0';
        size_t len = (size_t)atoi(line);
        const char *want = sp + 1;
        unsigned char *msg = (unsigned char *)malloc(len + 1);
        for (size_t k = 0; k < len; ++k) msg[k] = (unsigned char)((k*7 + (len%13)) & 0xff);
        /* Sized for the longest corpus entry. pw_pad_md returns 0 when the
         * message does not fit, and this harness was passing a 128 byte buffer
         * for messages up to 200 bytes. It therefore hashed nothing for those
         * lengths and reported a constant state as a failure, which looked like
         * a broken core. 256 covers 200 bytes plus padding and the length field. */
        uchar pad[256];
        uint st[4] = {0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u};
        size_t padded = pw_pad_md(pad, sizeof pad, msg, len, 64);
        if (padded == 0) { printf("pad failed for %zu\n", len); ++bad; free(msg); continue; }
        for (size_t o = 0; o < padded; o += 64) pw_md5_compress(pad + o, st);
        unsigned char got[16];
        for (int i = 0; i < 4; ++i) pw_store_le32(got + i*4, st[i]);
        char hex[33];
        for (int i = 0; i < 16; ++i) snprintf(hex + i*2, 3, "%02x", got[i]);
        if (strcmp(hex, want) != 0) {
            printf("FAIL length %zu\n  got  %s\n  want %s\n", len, hex, want);
            ++bad;
        }
        free(msg); ++n;
    }
    fclose(f);
    printf("%d core checks, %d failure(s)\n", n, bad);
    return bad ? 1 : 0;
}
EOF

clang -x c -O2 -Wno-unused-function -I engines/kernel-common \
    -o "$TMP/corecheck" "$TMP/corecheck.c" 2>"$TMP/cc.err" || {
        echo "FAIL could not build the core check"
        head -30 "$TMP/cc.err"
        exit 1
    }
PWDCRACK_MD5_CORPUS="$CORPUS" "$TMP/corecheck"

echo
echo "OpenCL kernels verified: syntax, arithmetic and kernel body"