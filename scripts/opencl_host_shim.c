/* Host shim for the OpenCL kernel bodies.
 *
 * Compiled as C, this makes the .cl kernel source runnable without an OpenCL
 * runtime. The substitutions are the ones an OpenCL compiler defines:
 *
 *   __kernel          empty
 *   __global const    const
 *   get_global_id(n)  a per-invocation counter, driven by a launch helper
 *   uint / uchar / ulong / size_t / memcpy
 *
 * Only get_global_id has real behaviour, and it is deliberately faithful rather
 * than convenient: the launch helper calls the kernel once per work item with the
 * counter set to that item's index, which is exactly how a driver maps work items
 * to invocations for a one dimensional dispatch. If the kernel's index arithmetic
 * is wrong, a lane reads the wrong candidate and the mismatch shows up here.
 *
 * What this does not exercise: real parallelism, work group memory, barriers,
 * global memory coalescing, or anything a specific vendor driver does differently.
 * A kernel that passes this can still fail on hardware, and can still be slower
 * than the CPU. See docs/PHASE7_STATUS.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* OpenCL builtins, in their host equivalents. */
typedef uint32_t uint;
typedef uint64_t ulong;
typedef uint8_t uchar;

/* Address space qualifiers have no meaning on the host. */
#define __kernel
#define __global
#define __local
#define __constant

/* Single global work item counter, as if the launch were one dimensional. */
static size_t g_global_id;

static size_t get_global_id(unsigned int dim)
{
    (void)dim;
    return g_global_id;
}

/* Launch helper: run the kernel once per work item. */
#define LAUNCH_KERNEL(kernel, items, ...)                                  \
    do {                                                                    \
        for (size_t _i = 0; _i < (size_t)(items); ++_i) {                   \
            g_global_id = _i;                                               \
            kernel(__VA_ARGS__);                                            \
        }                                                                   \
    } while (0)

#include "hash_core.cl"
#include "md5.cl"

#define MAXC 256u
#define N 128

static int g_failures = 0;
static int g_checks = 0;

static void check(const char *what, const unsigned char *got,
                  const unsigned char *want, unsigned int len)
{
    ++g_checks;
    if (memcmp(got, want, len) != 0) {
        ++g_failures;
        printf("FAIL %s\n     got  ", what);
        for (unsigned int i = 0; i < len; ++i) printf("%02x", got[i]);
        printf("\n     want ");
        for (unsigned int i = 0; i < len; ++i) printf("%02x", want[i]);
        printf("\n");
    }
}

/* MD5 through the kernel's own padding helper, so the padding path under test
 * is the one being checked. */
static void md5_reference(const unsigned char *msg, unsigned int len,
                          unsigned char out[16])
{
    uchar pad[128];
    uint st[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    size_t padded = pw_pad_md(pad, sizeof pad, msg, len, 64);
    for (size_t o = 0; o < padded; o += 64) pw_md5_compress(pad + o, st);
    for (int i = 0; i < 4; ++i) pw_store_le32(out + i * 4, st[i]);
}

int main(void)
{
    static unsigned char cands[N * MAXC];
    uint lengths[N];
    static unsigned char out[N * 16];

    /* Every length from 0 upward, one work item each, in one dispatch. */
    memset(cands, 0, sizeof cands);
    memset(out, 0, sizeof out);
    for (unsigned int i = 0; i < N; ++i) {
        for (unsigned int k = 0; k < i; ++k) {
            cands[i * MAXC + k] = (unsigned char)('a' + (k % 26));
        }
        lengths[i] = i;
    }

    LAUNCH_KERNEL(md5_digest, N, cands, lengths, out, (uint)N, (uint)MAXC);

    for (unsigned int i = 0; i < N; ++i) {
        unsigned char want[16];
        char what[64];
        snprintf(what, sizeof what, "item %u len %u", i, i);
        if (i > 119u) {
            /* Above the kernel's ceiling the digest must stay zero. Hashing a
             * truncated string here would let the kernel produce a digest for a
             * candidate that was never submitted, which can collide with a real
             * target. The reference in this test used to compute a real digest
             * for these lengths, so it was asserting the wrong thing. */
            memset(want, 0, 16);
        } else {
            md5_reference(cands + i * MAXC, i, want);
        }
        check(what, out + i * 16, want, 16);
    }

    /* A candidate containing a zero byte must hash as that byte string. The
     * previous kernel stopped at the first zero, so this is the regression it
     * would fail. */
    {
        memset(cands, 0, sizeof cands);
        memset(out, 0, sizeof out);
        unsigned char embedded_zero[4] = { 'a', 0x00, 'b', 'c' };
        memcpy(cands, embedded_zero, 4);
        lengths[0] = 4;
        for (unsigned int i = 1; i < 4; ++i) lengths[i] = 0;

        LAUNCH_KERNEL(md5_digest, 4, cands, lengths, out, (uint)4, (uint)MAXC);

        unsigned char want[16];
        md5_reference(embedded_zero, 4, want);
        check("candidate containing a zero byte", out, want, 16);
    }

    /* Over-length candidates produce no digest rather than a truncated one. */
    {
        memset(cands, 0, sizeof cands);
        memset(out, 0xAB, sizeof out);
        for (unsigned int k = 0; k < MAXC; ++k) cands[k] = 'x';
        lengths[0] = MAXC;
        for (unsigned int i = 1; i < 4; ++i) lengths[i] = 0;

        LAUNCH_KERNEL(md5_digest, 4, cands, lengths, out, (uint)4, (uint)MAXC);

        unsigned char zero[16] = { 0 };
        check("over-length candidate yields no digest", out, zero, 16);
    }

    /* Known vectors through the kernel entry point. */
    {
        static const struct { const char *s; const char *hex; } V[] = {
            { "abc",   "900150983cd24fb0d6963f7d28e17f72" },
            { "hello", "5d41402abc4b2a76b9719d911017c592" },
            { "",      "d41d8cd98f00b204e9800998ecf8427e" },
        };
        memset(cands, 0, sizeof cands);
        memset(out, 0, sizeof out);
        for (unsigned int i = 0; i < sizeof V / sizeof V[0]; ++i) {
            unsigned int len = (unsigned int)strlen(V[i].s);
            memcpy(cands + i * MAXC, V[i].s, len);
            lengths[i] = len;
        }
        unsigned int n = (unsigned int)(sizeof V / sizeof V[0]);
        LAUNCH_KERNEL(md5_digest, n, cands, lengths, out, (uint)n, (uint)MAXC);
        for (unsigned int i = 0; i < n; ++i) {
            unsigned char want[16];
            for (int k = 0; k < 16; ++k) {
                unsigned int byte;
                sscanf(V[i].hex + k * 2, "%2x", &byte);
                want[k] = (unsigned char)byte;
            }
            char what[64];
            snprintf(what, sizeof what, "vector \"%s\"", V[i].s);
            check(what, out + i * 16, want, 16);
        }
    }

    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}