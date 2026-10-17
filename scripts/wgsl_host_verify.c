/* Host verification of the WGSL MD5 kernel.
 *
 * A SPIR-V module being accepted by naga proves the shader is well formed. It
 * says nothing about whether it computes MD5. The previous CUDA and OpenCL
 * kernels in this repository were all well formed and all wrong, each for a
 * different reason: a constant used for all 64 steps, a fixed rotation of 7, a
 * word order derived from a formula that was right once and wrong fifteen times.
 * None of those is a syntax error and none would be caught by a compiler.
 *
 * So this file carries a transliteration of engines/engine-vulkan/shaders/md5.wgsl
 * and checks it against python hashlib. The transliteration is mechanical and
 * mirrors the WGSL statement for statement, including using u32 rather than u8 for
 * byte buffers so that a discrepancy is a transcription slip and not a dialect
 * difference.
 *
 * What this proves about the WGSL: that its tables, its rotations, its word
 * indices and its padding are the correct MD5 ones. It cannot prove that the
 * shader reads the right buffer at the right offset, because that depends on the
 * buffer binding, which depends on the host. scripts/verify-vulkan-kernels.sh
 * runs this first, then runs the real SPIR-V on the real device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* --- transliteration of shaders/md5.wgsl --- */

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static const uint32_t S[64] = {
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

static const uint32_t G[64] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
     5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
     0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9,
};

#define MAX_CANDIDATE 119u
#define DIGEST_BYTES  16u
#define PADDED_CAPACITY 128u

static uint32_t rotl(uint32_t x, uint32_t s) {
    return (x << s) | (x >> (32u - s));
}

static uint32_t load_le32(const uint32_t *pad, uint32_t off) {
    return (pad[off] & 0xffu)
         | ((pad[off + 1u] & 0xffu) << 8u)
         | ((pad[off + 2u] & 0xffu) << 16u)
         | ((pad[off + 3u] & 0xffu) << 24u);
}

static uint32_t padded_len(uint32_t len) {
    if (len + 9u > PADDED_CAPACITY) return 0u;
    uint32_t total = len + 1u;
    while (total % 64u != 56u) total += 1u;
    return total + 4u;
}

static void pad_md(uint32_t *pad, const uint32_t *candidates, uint32_t base, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) pad[i] = candidates[base + i];
    pad[len] = 0x80u;
    uint32_t total = len + 1u;
    while (total % 64u != 56u) { pad[total] = 0u; total += 1u; }
    uint32_t bit_len = len * 8u;
    pad[total] = bit_len & 0xffu;
    pad[total + 1u] = (bit_len >> 8u) & 0xffu;
    pad[total + 2u] = (bit_len >> 16u) & 0xffu;
    pad[total + 3u] = (bit_len >> 24u) & 0xffu;
}

static void compress(const uint32_t *pad, uint32_t *state, uint32_t off) {
    uint32_t w[16];
    for (uint32_t i = 0; i < 16u; ++i) w[i] = load_le32(pad, off + i * 4u);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (uint32_t i = 0; i < 64u; ++i) {
        uint32_t f;
        if (i < 16u)      f = (b & c) | (~b & d);
        else if (i < 32u) f = (d & b) | (~d & c);
        else if (i < 48u) f = b ^ c ^ d;
        else              f = c ^ (b | ~d);
        uint32_t t = f + a + K[i] + w[G[i]];
        a = d; d = c; c = b;
        b = b + rotl(t, S[i]);
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

/* Mirrors fn main in the WGSL, including the zeroing of the output slot and the
 * refusal to hash an over-long candidate. */
static void wgsl_main(const uint32_t *candidates, const uint32_t *lengths,
                     uint32_t *out, uint32_t idx, uint32_t count, uint32_t stride) {
    if (idx >= count) return;
    for (uint32_t i = 0; i < DIGEST_BYTES; ++i) out[idx * DIGEST_BYTES + i] = 0u;

    uint32_t len = lengths[idx];
    if (len > MAX_CANDIDATE) return;

    uint32_t total = padded_len(len);
    if (total == 0u) return;

    uint32_t pad[PADDED_CAPACITY];
    pad_md(pad, candidates, idx * stride, len);

    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    for (uint32_t off = 0; off < total; off += 64u) compress(pad, state, off);

    for (uint32_t w = 0; w < 4u; ++w) {
        uint32_t v = state[w];
        uint32_t b = idx * DIGEST_BYTES + w * 4u;
        out[b] = v & 0xffu;
        out[b + 1u] = (v >> 8u) & 0xffu;
        out[b + 2u] = (v >> 16u) & 0xffu;
        out[b + 3u] = (v >> 24u) & 0xffu;
    }
}

/* --- driver --- */

#define MAXC 256u
#define N 128

static int failures = 0;
static int checks = 0;

int main(void) {
    static uint32_t cands[N * MAXC];
    uint32_t lengths[N];
    static uint32_t out[N * DIGEST_BYTES];

    /* Every length from 0 upward, one invocation each, mirroring a single
     * dispatch with N invocations. */
    memset(cands, 0, sizeof cands);
    memset(out, 0, sizeof out);
    for (uint32_t i = 0; i < N; ++i) {
        for (uint32_t k = 0; k < i; ++k) cands[i * MAXC + k] = 'a' + (k % 26);
        lengths[i] = i;
    }
    for (uint32_t i = 0; i < N; ++i) {
        wgsl_main(cands, lengths, out, i, N, MAXC);
    }

    const char *corpus = getenv("PWDCRACK_MD5_CORPUS");
    if (!corpus) {
        fprintf(stderr, "PWDCRACK_MD5_CORPUS not set\n");
        return 2;
    }
    FILE *f = fopen(corpus, "r");
    if (!f) { perror("corpus"); return 2; }

    char line[512];
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = 0;
        uint32_t len = (uint32_t)atoi(line);
        const char *want = sp + 1;

        /* The kernel buffers one byte per u32, so build the input the same way
         * the host will when it uploads. */
        memset(out, 0, sizeof out);
        memset(lengths, 0, sizeof lengths);
        for (uint32_t k = 0; k < len; ++k) cands[k] = (uint32_t)((k * 7 + (len % 13)) & 0xff);
        lengths[0] = len;
        wgsl_main(cands, lengths, out, 0, 1, MAXC);

        char hex[33];
        for (int k = 0; k < 16; ++k) {
            snprintf(hex + k * 2, 3, "%02x", (unsigned)(out[k] & 0xffu));
        }
        ++checks;
        if (strcmp(hex, want) != 0) {
            ++failures;
            if (failures <= 10) {
                printf("FAIL len %u\n  got  %s\n  want %s\n", len, hex, want);
            }
        }
    }
    fclose(f);

    printf("%d WGSL table checks, %d failure(s)\n", checks, failures);
    return failures ? 1 : 0;
}