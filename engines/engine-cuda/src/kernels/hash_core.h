/* pwdcrack hash core: compression functions shared by the CUDA kernels.
 *
 * Why a header and not code inside each .cu file
 * ----------------------------------------------
 * Everything below is plain C. It contains no CUDA intrinsic, no `__shared__`,
 * no `threadIdx`, and no device-only qualifier. That is deliberate: it lets the
 * same source compile in two places.
 *
 *   - As device code, included from a .cu file compiled by nvcc.
 *   - As host code, compiled by the system C compiler in
 *     `scripts/verify-kernels.sh`, which links it against reference digests.
 *
 * The reason for the second use is that the hash arithmetic in a GPU kernel is
 * exactly where silent wrong answers come from, and the previous version of this
 * engine had six separate defects in a 37 line MD5 kernel: one round constant
 * reused for all 64 steps, one fixed rotation for all 64 steps, a message word
 * order computed from a formula that is wrong from the second step onward, a
 * shared memory array written by every thread, an unaligned cast from
 * `unsigned char*`, and no padding at all. None of those can be caught without
 * running the code.
 *
 * So the code is run, on the host, against digests produced by an independent
 * implementation. What that proves is that the arithmetic and the tables are
 * right. It does not prove anything about memory layout, thread indexing or the
 * launch configuration, which is a separate concern documented in
 * docs/PHASE6_STATUS.md.
 *
 * Every table here is transcribed from the specification and checked by
 * tests/host_verify.c. Where a table could be derived from a formula, the
 * literal table is used anyway: a formula that is subtly wrong produces
 * plausible output for the first step and wrong output afterwards, which is
 * harder to notice than a mistyped constant.
 */

#ifndef PWDCRACK_HASH_CORE_H
#define PWDCRACK_HASH_CORE_H

#include <stdint.h>
#include <string.h>

/* Under nvcc these are available as device primitives. Under a host compiler
 * they resolve to the ordinary C library. */
#if defined(__CUDACC__)
#define PW_HOST_DEVICE __host__ __device__
#define PW_INLINE __device__ __forceinline__
#else
#define PW_HOST_DEVICE
#define PW_INLINE static inline
#endif

/* ===================================================================
 * MD5 (RFC 1321)
 * =================================================================== */

/* Round constants, floor(abs(sin(i + 1)) * 2^32). */
static const uint32_t PW_MD5_K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

/* Per step left rotation, from section 3.4 of RFC 1321. */
static const uint8_t PW_MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/* Message word index per step, transcribed from appendix A.3 of RFC 1321.
 *
 * This is the table that must not be a formula. The sequence for round 2 is
 * 1, 6, 11, 0, ... and while (5i+1) mod 16 does produce exactly that, deriving
 * it in code rather than writing it down is how the previous kernel ended up
 * with a right first word and 15 wrong ones. */
static const uint8_t PW_MD5_G[64] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
     5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
     0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9
};

PW_INLINE uint32_t pw_rotl32(uint32_t v, uint8_t s)
{
    return (uint32_t)((v << s) | (v >> (32 - s)));
}

PW_INLINE uint32_t pw_load_le32(const unsigned char *p)
{
    /* Explicit byte assembly rather than a cast.
     *
     * A `(uint32_t*)(p)` cast requires 4 byte alignment. Candidate buffers on a
     * GPU are packed at arbitrary offsets, so the cast both breaks strict
     * aliasing on the host and can fault or read wrong data on the device. */
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

PW_INLINE void pw_store_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

PW_INLINE uint32_t pw_rotr32(uint32_t v, uint8_t s)
{
    return (uint32_t)((v >> s) | (v << (32 - s)));
}

PW_INLINE void pw_store_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)((v >> 24) & 0xffu);
    p[1] = (unsigned char)((v >> 16) & 0xffu);
    p[2] = (unsigned char)((v >> 8) & 0xffu);
    p[3] = (unsigned char)(v & 0xffu);
}

PW_INLINE uint32_t pw_load_be32(const unsigned char *p)
{
    /* SHA-1 and SHA-256 read the message as a big endian bit stream, so the
     * first word of "abc" is 0x61626380, not the 0x80636261 that MD4 and MD5
     * see. Using the little endian loader here produced a digest that matched
     * nothing while still looking structurally correct. */
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | ((uint32_t)p[3]);
}

/* Compresses one 64 byte block into state a,b,c,d.
 *
 * The four round functions follow RFC 1321 appendix A exactly. The detail that
 * is easy to get wrong: F(X,Y,Z) = XY v not(X) Z, and the complement applies to
 * the first argument, which is b in the FF(a,b,c,d,...) macro, not to the
 * target register a. */
PW_INLINE void pw_md5_compress(const unsigned char *block,
                               uint32_t state[4])
{
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) {
        w[i] = pw_load_le32(block + i * 4);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    for (int i = 0; i < 64; ++i) {
        uint32_t f;
        if (i < 16) {
            f = (b & c) | (~b & d);              /* F */
        } else if (i < 32) {
            f = (d & b) | (~d & c);              /* G */
        } else if (i < 48) {
            f = b ^ c ^ d;                       /* H */
        } else {
            f = c ^ (b | ~d);                    /* I */
        }
        f = f + a + PW_MD5_K[i] + w[PW_MD5_G[i]];
        a = d;
        d = c;
        c = b;
        b = b + pw_rotl32(f, PW_MD5_S[i]);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* ===================================================================
 * MD4 (RFC 1320), which is what an NTLM hash is computed over
 * =================================================================== */

PW_INLINE void pw_md4_compress(const unsigned char *block, uint32_t state[4])
{
    uint32_t w[16];
    for (int i = 0; i < 16; ++i) {
        w[i] = pw_load_le32(block + i * 4);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    /* Message word index per step, transcribed from the MD4Transform listing in
     * RFC 1320 appendix A.3.
     *
     * Round 1 is plain order. Round 2 is 0,4,8,12,1,5,9,13,... and round 3 is
     * 0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15.
     *
     * These are literal tables on purpose. Round 3 in particular does not follow
     * any simple formula: (i mod 4) * 2 + (i / 4) gives the right first four
     * entries and then diverges, which is the same class of mistake this file
     * records for MD5's round 2 word order. */
    static const uint8_t PW_MD4_ORDER[3][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,
           8,  9, 10, 11, 12, 13, 14, 15 },
        {  0,  4,  8, 12,  1,  5,  9, 13,
           2,  6, 10, 14,  3,  7, 11, 15 },
        {  0,  8,  4, 12,  2, 10,  6, 14,
           1,  9,  5, 13,  3, 11,  7, 15 }
    };
    static const uint8_t PW_MD4_SHIFT[3][4] = {
        { 3,  7, 11, 19 },
        { 3,  5,  9, 13 },
        { 3,  9, 11, 15 }
    };
    static const uint32_t PW_MD4_ADD[3] = { 0u, 0x5a827999u, 0x6ed9eba1u };

    /* Round 1: F(x,y,z) = (x AND y) OR (NOT x AND z). */
    for (int i = 0; i < 16; ++i) {
        uint32_t f = (b & c) | (~b & d);
        uint32_t t = a + f + w[PW_MD4_ORDER[0][i]] + PW_MD4_ADD[0];
        a = d; d = c; c = b;
        b = pw_rotl32(t, PW_MD4_SHIFT[0][i & 3]);
    }

    /* Round 2: G(x,y,z) = (x AND y) OR (x AND z) OR (y AND z). */
    for (int i = 0; i < 16; ++i) {
        uint32_t g = (b & c) | (b & d) | (c & d);
        uint32_t t = a + g + w[PW_MD4_ORDER[1][i]] + PW_MD4_ADD[1];
        a = d; d = c; c = b;
        b = pw_rotl32(t, PW_MD4_SHIFT[1][i & 3]);
    }

    /* Round 3: H(x,y,z) = x XOR y XOR z. */
    for (int i = 0; i < 16; ++i) {
        uint32_t h = b ^ c ^ d;
        uint32_t t = a + h + w[PW_MD4_ORDER[2][i]] + PW_MD4_ADD[2];
        a = d; d = c; c = b;
        b = pw_rotl32(t, PW_MD4_SHIFT[2][i & 3]);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* ===================================================================
 * SHA-1 (FIPS 180-4)
 * =================================================================== */

PW_INLINE void pw_sha1_compress(const unsigned char *block, uint32_t state[5])
{
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = pw_load_be32(block + i * 4);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = pw_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2];
    uint32_t d = state[3], e = state[4];

    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        /* T = ROL(a, 5) + f + e + W[t] + K.
         *
         * The rotate applies to `a` alone. Writing this as
         * ROL(a + f + W + K, 5), which is the form MD5 uses, is wrong: rotation
         * is linear over XOR but not over addition modulo 2^32, so the two are
         * not equal. MD5 really does rotate the sum, SHA-1 does not. */
        uint32_t t = pw_rotl32(a, 5) + f + e + w[i] + k;
        e = d; d = c; c = pw_rotl32(b, 30); b = a; a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

/* ===================================================================
 * SHA-256 (FIPS 180-4)
 * =================================================================== */

static const uint32_t PW_SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

PW_INLINE void pw_sha256_compress(const unsigned char *block, uint32_t state[8])
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = pw_load_be32(block + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        /* sigma0 and sigma1 are defined with ROTR, not ROTL. Rotating left
         * instead of right produces a structurally valid looking digest that
         * matches nothing. */
        uint32_t s0 = pw_rotr32(w[i - 15], 7) ^ pw_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = pw_rotr32(w[i - 2], 17) ^ pw_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = pw_rotr32(e, 6) ^ pw_rotr32(e, 11) ^ pw_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + PW_SHA256_K[i] + w[i];
        uint32_t S0 = pw_rotr32(a, 2) ^ pw_rotr32(a, 13) ^ pw_rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ===================================================================
 * SHA-512 (FIPS 180-4)
 * =================================================================== */

PW_INLINE uint64_t pw_rotr64(uint64_t v, unsigned s)
{
    return (uint64_t)((v >> s) | (v << (64 - s)));
}

static const uint64_t PW_SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

PW_INLINE uint64_t pw_load_be64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

PW_INLINE void pw_store_be64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) {
        p[i] = (unsigned char)((v >> (56 - i * 8)) & 0xffu);
    }
}

PW_INLINE void pw_sha512_compress(const unsigned char *block, uint64_t state[8])
{
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = pw_load_be64(block + i * 8);
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = pw_rotr64(w[i - 15], 1) ^ pw_rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = pw_rotr64(w[i - 2], 19) ^ pw_rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = pw_rotr64(e, 14) ^ pw_rotr64(e, 18) ^ pw_rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t t1 = h + S1 + ch + PW_SHA512_K[i] + w[i];
        uint64_t S0 = pw_rotr64(a, 28) ^ pw_rotr64(a, 34) ^ pw_rotr64(a, 39);
        uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + mj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ===================================================================
 * Merkle-Damgard padding shared by every digest above
 * =================================================================== */

/* Writes the 0x80 marker, the zero fill and the length field for one of the
 * Merkle-Damgard constructions. MD4, MD5 and SHA-1 use a 64 bit little endian
 * bit count; SHA-256 uses the same layout; SHA-512 uses a 128 bit big endian
 * count, which is handled separately by pw_pad_sha512.
 *
 * `msg_len` is the message length in bytes, not including padding. Returns the
 * total padded length, which is always a multiple of `block_size`.
 *
 * The caller must ensure `out` has room for the padded length. The maximum
 * message this accepts for a given output buffer of `cap` bytes is
 * cap - 9 for the 64 bit variants and cap - 17 for SHA-512. */
PW_INLINE size_t pw_pad_md(unsigned char *out, size_t cap,
                           const unsigned char *msg, size_t msg_len,
                           size_t block_size)
{
    if (msg_len + 9 > cap) {
        return 0;
    }
    memcpy(out, msg, msg_len);
    out[msg_len] = 0x80;

    size_t total = msg_len + 1;
    /* Pad with zeros until the length field (8 bytes) fits at the end of a
     * block. The `- 8` is the length field itself. */
    while ((total % block_size) != (block_size - 8)) {
        out[total] = 0x00;
        ++total;
    }

    uint64_t bit_len = (uint64_t)msg_len * 8u;
    for (int i = 0; i < 8; ++i) {
        out[total + i] = (unsigned char)((bit_len >> (i * 8)) & 0xffu);
    }
    return total + 8;
}

/* Padding for SHA-1 and SHA-256: identical to the Merkle-Damgard form except
 * that the 64 bit bit count is big endian. SHA-1 and SHA-256 read the message
 * as a big endian bit stream, so the length field follows the same order. MD4
 * and MD5 read little endian and must use pw_pad_md instead. */
PW_INLINE size_t pw_pad_be(unsigned char *out, size_t cap,
                           const unsigned char *msg, size_t msg_len,
                           size_t block_size)
{
    if (msg_len + 9 > cap) {
        return 0;
    }
    memcpy(out, msg, msg_len);
    out[msg_len] = 0x80;

    size_t total = msg_len + 1;
    while ((total % block_size) != (block_size - 8)) {
        out[total] = 0x00;
        ++total;
    }

    uint64_t bit_len = (uint64_t)msg_len * 8u;
    for (int i = 0; i < 8; ++i) {
        out[total + i] = (unsigned char)((bit_len >> (56 - i * 8)) & 0xffu);
    }
    return total + 8;
}

/* SHA-512 padding: 16 byte big endian bit count, 128 byte blocks. */
PW_INLINE size_t pw_pad_sha512(unsigned char *out, size_t cap,
                               const unsigned char *msg, size_t msg_len)
{
    const size_t block_size = 128;
    if (msg_len + 17 > cap) {
        return 0;
    }
    memcpy(out, msg, msg_len);
    out[msg_len] = 0x80;

    size_t total = msg_len + 1;
    while ((total % block_size) != (block_size - 16)) {
        out[total] = 0x00;
        ++total;
    }

    /* The 128 bit high half is always zero for any message that fits in the
     * buffer this function accepts, but it is written explicitly rather than
     * assumed so the code stays correct if the cap ever grows. */
    uint64_t bit_len = (uint64_t)msg_len * 8u;
    for (int i = 0; i < 8; ++i) {
        out[total + i] = 0x00;
        out[total + 8 + i] = (unsigned char)((bit_len >> (56 - i * 8)) & 0xffu);
    }
    return total + 16;
}

#endif /* PWDCRACK_HASH_CORE_H */