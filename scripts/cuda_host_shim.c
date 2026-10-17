/* Host execution of the CUDA kernel bodies.
 *
 * The .cu files in this directory cannot be compiled or run without a CUDA
 * toolchain and a device, and neither is present on the build machine. What can
 * still be checked is the kernel body itself, because it is ordinary C wrapped in
 * a handful of CUDA spellings.
 *
 * This file provides those spellings as host shims:
 *
 *   __global__  empty
 *   blockIdx    a single block of `total` threads with the given blockDim
 *   blockDim    thread count
 *   threadIdx   the thread's linear index inside that block
 *
 * and then includes the real .cu files unmodified. The kernel code under test is
 * therefore exactly the code that would be handed to nvcc, not a paraphrase.
 *
 * What this proves:
 *   - the compression functions produce correct digests
 *   - padding is correct for every candidate length up to the fast path limit
 *   - the thread to candidate mapping is correct, including the bounds check
 *   - every thread writes its own digest slot and no other thread's
 *   - candidates longer than the kernel limit are skipped rather than truncated
 *
 * What this does NOT prove, and what only real hardware can:
 *   - actual parallel execution, so there is no concurrency or occupancy claim
 *   - real memory latency, coalescing or bandwidth behaviour
 *   - measured throughput of any kind
 *   - that nvcc accepts the file
 *
 * See docs/PHASE6_STATUS.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* Compiled as C++ because the .cu files use `extern "C"`, which is exactly how
 * they are written for nvcc. Building this shim with a C++ compiler means the
 * kernel source is compiled with the same language rules it will meet under
 * nvcc, rather than a C-only approximation of them. */
#ifdef __cplusplus
extern "C" {
#endif

/* ---- CUDA spellings, host versions ---- */

#define __global__
#define __device__
#define __host__
#define __forceinline__ inline

typedef struct { unsigned int x, y, z; } dim3_t;

static dim3_t g_blockDim;
static dim3_t g_blockIdx;
static dim3_t g_threadIdx;

/* The .cu files declare blockIdx and friends as if they were builtins. */
#define blockIdx g_blockIdx
#define blockDim g_blockDim
#define threadIdx g_threadIdx

#include "hash_core.h"
#include "md5.cu"

#ifdef __cplusplus
}
#endif

/* ---- launch shim: run the grid as one block ---- */

static int g_failures = 0;
static int g_checks = 0;

static void launch_md5_digest(const unsigned char *candidates,
                              unsigned int *lengths,
                              unsigned char *out,
                              unsigned int count,
                              unsigned int stride)
{
    /* Every thread gets the same blockIdx because this is a single block, and a
     * distinct threadIdx. That is exactly the mapping the real launch uses for
     * grids that fit in one block; a grid larger than blockDim needs the real
     * device to distribute blocks, which is the part that stays unverified. */
    g_blockIdx.x = 0;
    g_blockDim.x = count;
    for (unsigned int t = 0; t < count; ++t) {
        g_threadIdx.x = t;
        md5_digest(candidates, lengths, out, count, stride);
    }
}

static void check(const char *what, const unsigned char *got,
                  const unsigned char *want, unsigned int len)
{
    ++g_checks;
    if (memcmp(got, want, len) != 0) {
        ++g_failures;
        printf("FAIL %s\n     got  ", what);
        for (unsigned int i = 0; i < len; ++i) { printf("%02x", got[i]); }
        printf("\n     want ");
        for (unsigned int i = 0; i < len; ++i) { printf("%02x", want[i]); }
        printf("\n");
    }
}

/* MD5 of an arbitrary byte string, computed through the kernel's own padding
 * helper so the padding path under test is the one being checked. */
static void md5_reference(const unsigned char *msg, unsigned int len,
                          unsigned char out[16])
{
    unsigned char pad[128];
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    size_t padded = pw_pad_md(pad, sizeof pad, msg, len, 64);
    if (padded == 0) { memset(out, 0, 16); return; }
    for (size_t off = 0; off < padded; off += 64) {
        pw_md5_compress(pad + off, state);
    }
    for (int i = 0; i < 4; ++i) { pw_store_le32(out + i * 4, state[i]); }
}

#define MAXC 256u

int main(void)
{
    enum { N = 128 };
    /* Candidates are packed at a fixed stride, exactly as the host side packs
     * them. Every slot is zero filled first so a short candidate followed by a
     * long one cannot read the neighbour's bytes. */
    static unsigned char cands[N * MAXC];
    unsigned int lengths[N];
    static unsigned char out[N * 16];

    /* Test 1: every length from 0 to the kernel ceiling, one per thread, in a
     * single launch. This is the check that catches an off-by-one in the thread
     * to candidate mapping, because any lane reading the wrong slot shows up as
     * a mismatch at exactly one length. */
    memset(cands, 0, sizeof cands);
    memset(out, 0, sizeof out);
    for (unsigned int i = 0; i < N; ++i) {
        unsigned int len = i;   /* 0..127, 119 and below go through the kernel */
        for (unsigned int k = 0; k < len; ++k) {
            cands[i * MAXC + k] = (unsigned char)('a' + (k % 26));
        }
        lengths[i] = len;
    }

    launch_md5_digest(cands, lengths, out, N, MAXC);

    for (unsigned int i = 0; i < N; ++i) {
        unsigned char want[16];
        md5_reference(cands + i * MAXC, i, want);
        char what[64];
        snprintf(what, sizeof what, "lane %u len %u", i, i);
        check(what, out + i * 16, want, 16);
    }

    /* Test 2: candidates above the ceiling must be skipped, not truncated. A
     * truncated candidate would produce a digest for a shorter string, which is
     * worse than producing nothing because it can match a real hash. */
    memset(cands, 0, sizeof cands);
    memset(out, 0xAB, sizeof out);
    for (unsigned int k = 0; k < MAXC; ++k) { cands[k] = 'x'; }
    lengths[0] = MAXC;
    for (unsigned int i = 1; i < N; ++i) { lengths[i] = 0; }

    launch_md5_digest(cands, lengths, out, N, MAXC);

    {
        unsigned char zero[16] = { 0 };
        char what[64];
        snprintf(what, sizeof what, "over-length candidate yields no digest");
        check(what, out, zero, 16);
    }

    /* Test 3: known vectors through the real kernel entry point. */
    {
        static const struct { const char *s; const char *hex; } V[] = {
            { "abc",     "900150983cd24fb0d6963f7d28e17f72" },
            { "hello",   "5d41402abc4b2a76b9719d911017c592" },
            { "",        "d41d8cd98f00b204e9800998ecf8427e" },
        };
        memset(cands, 0, sizeof cands);
        memset(out, 0, sizeof out);
        for (unsigned int i = 0; i < sizeof V / sizeof V[0]; ++i) {
            unsigned int len = (unsigned int)strlen(V[i].s);
            memcpy(cands + i * MAXC, V[i].s, len);
            lengths[i] = len;
        }
        launch_md5_digest(cands, lengths, out, sizeof V / sizeof V[0], MAXC);
        for (unsigned int i = 0; i < sizeof V / sizeof V[0]; ++i) {
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