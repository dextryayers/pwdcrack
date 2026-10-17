/* Host differential test for the CUDA hash core.
 *
 * Compiles `hash_core.h` as ordinary C and checks every digest against values
 * produced by an independent implementation. This is what makes the kernel
 * arithmetic verifiable on a machine with no CUDA device: the compression
 * functions contain no device specific code, so running them on the host tests
 * the same source the GPU would execute.
 *
 * What this does NOT cover, and cannot: memory layout, thread indexing, block
 * sizing, shared memory use and the launch path. Those are documented as
 * unverified in docs/PHASE6_STATUS.md.
 *
 * Expected vectors are passed in from a file produced by a separate oracle, or
 * the built in table below is used. Run via scripts/verify-kernels.sh, which
 * additionally cross checks a random corpus against python hashlib and
 * `openssl dgst -md4 -provider legacy`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../engines/engine-cuda/src/kernels/hash_core.h"

static int g_failures = 0;
static int g_checks = 0;

static void check(const char *algo, const char *what,
                  const unsigned char *got, size_t got_len,
                  const char *want_hex)
{
    char got_hex[257];
    for (size_t i = 0; i < got_len && i < 256; ++i) {
        snprintf(got_hex + i * 2, 3, "%02x", got[i]);
    }
    got_hex[got_len * 2] = '\0';

    ++g_checks;
    if (strcmp(got_hex, want_hex) != 0) {
        ++g_failures;
        printf("FAIL %-8s %-28s\n     got  %s\n     want %s\n",
               algo, what, got_hex, want_hex);
    }
}

/* ---------------- MD5 ---------------- */

static void md5(const unsigned char *msg, size_t len, unsigned char out[16])
{
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

    /* Cap covers the longest message this harness feeds in. */
    unsigned char *buf = (unsigned char *)malloc(len + 128);
    size_t padded = pw_pad_md(buf, len + 128, msg, len, 64);
    if (padded == 0) {
        fprintf(stderr, "md5: message too long for buffer\n");
        free(buf);
        exit(2);
    }
    for (size_t off = 0; off < padded; off += 64) {
        pw_md5_compress(buf + off, state);
    }
    free(buf);

    for (int i = 0; i < 4; ++i) {
        pw_store_le32(out + i * 4, state[i]);
    }
}

/* ---------------- MD4 ---------------- */

static void md4(const unsigned char *msg, size_t len, unsigned char out[16])
{
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    unsigned char *buf = (unsigned char *)malloc(len + 128);
    size_t padded = pw_pad_md(buf, len + 128, msg, len, 64);
    if (padded == 0) {
        fprintf(stderr, "md4: message too long for buffer\n");
        free(buf);
        exit(2);
    }
    for (size_t off = 0; off < padded; off += 64) {
        pw_md4_compress(buf + off, state);
    }
    free(buf);
    for (int i = 0; i < 4; ++i) {
        pw_store_le32(out + i * 4, state[i]);
    }
}

/* ---------------- SHA-1 ---------------- */

static void sha1(const unsigned char *msg, size_t len, unsigned char out[20])
{
    uint32_t state[5] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                          0xc3d2e1f0u };
    unsigned char *buf = (unsigned char *)malloc(len + 128);
    /* Big endian bit count: SHA-1 reads the message as a big endian stream. */
    size_t padded = pw_pad_be(buf, len + 128, msg, len, 64);
    if (padded == 0) {
        fprintf(stderr, "sha1: message too long for buffer\n");
        free(buf);
        exit(2);
    }
    for (size_t off = 0; off < padded; off += 64) {
        pw_sha1_compress(buf + off, state);
    }
    free(buf);
    /* SHA-1 emits its words big endian. Storing them little endian produced a
     * digest that was the correct value with every 4 byte group reversed. */
    for (int i = 0; i < 5; ++i) {
        pw_store_be32(out + i * 4, state[i]);
    }
}

/* ---------------- SHA-256 ---------------- */

static void sha256(const unsigned char *msg, size_t len, unsigned char out[32])
{
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    unsigned char *buf = (unsigned char *)malloc(len + 128);
    /* Big endian bit count: SHA-256 reads the message as a big endian stream. */
    size_t padded = pw_pad_be(buf, len + 128, msg, len, 64);
    if (padded == 0) {
        fprintf(stderr, "sha256: message too long for buffer\n");
        free(buf);
        exit(2);
    }
    for (size_t off = 0; off < padded; off += 64) {
        pw_sha256_compress(buf + off, state);
    }
    free(buf);
    for (int i = 0; i < 8; ++i) {
        pw_store_be32(out + i * 4, state[i]);
    }
}

/* ---------------- SHA-512 ---------------- */

static void sha512(const unsigned char *msg, size_t len, unsigned char out[64])
{
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    unsigned char *buf = (unsigned char *)malloc(len + 256);
    size_t padded = pw_pad_sha512(buf, len + 256, msg, len);
    if (padded == 0) {
        fprintf(stderr, "sha512: message too long for buffer\n");
        free(buf);
        exit(2);
    }
    for (size_t off = 0; off < padded; off += 128) {
        pw_sha512_compress(buf + off, state);
    }
    free(buf);
    for (int i = 0; i < 8; ++i) {
        pw_store_be64(out + i * 8, state[i]);
    }
}

/* ---------------- vectors ---------------- */

/* RFC 1321 appendix A.5 */
static const struct { const char *in; const char *md5; const char *sha1; } V[] = {
    { "",        "d41d8cd98f00b204e9800998ecf8427e",
                 "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "a",       "0cc175b9c0f1b6a831c399e269772661",
                 "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" },
    { "abc",     "900150983cd24fb0d6963f7d28e17f72",
                 "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "message digest", "f96b697d7cb7938d525a2f31aaf161d0",
                 "c12252ceda8be8994d5fa0290a47231c1d16aae3" },
    { "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b",
                 "32d10c7b8cf96570ca04ce37f2a19d84240d3a89" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "57edf4a22be3c955ac49da2e2107b67a", NULL },
};

/* FIPS 180-4 examples */
static const struct { const char *in; const char *sha256; const char *sha512; } W[] = {
    { "abc",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
      "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
};

int main(void)
{
    unsigned char d[64];

    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); ++i) {
        char what[64];
        snprintf(what, sizeof(what), "\"%.20s\"", V[i].in);
        md5((const unsigned char *)V[i].in, strlen(V[i].in), d);
        check("md5", what, d, 16, V[i].md5);
        if (V[i].sha1) {
            sha1((const unsigned char *)V[i].in, strlen(V[i].in), d);
            check("sha1", what, d, 20, V[i].sha1);
        }
    }

    for (size_t i = 0; i < sizeof(W) / sizeof(W[0]); ++i) {
        char what[64];
        snprintf(what, sizeof(what), "FIPS \"%.*s\"", (int)(i == 0 ? 3 : 56), W[i].in);
        sha256((const unsigned char *)W[i].in, strlen(W[i].in), d);
        check("sha256", what, d, 32, W[i].sha256);
        sha512((const unsigned char *)W[i].in, strlen(W[i].in), d);
        check("sha512", what, d, 64, W[i].sha512);
    }

    /* MD4 vectors, from the RFC 1320 appendix and cross checked with
     * `openssl dgst -md4 -provider legacy`. */
    md4((const unsigned char *)"", 0, d);
    check("md4", "\"\"", d, 16, "31d6cfe0d16ae931b73c59d7e0c089c0");
    md4((const unsigned char *)"a", 1, d);
    check("md4", "\"a\"", d, 16, "bde52cb31de33e46245e05fbdbd6fb24");
    md4((const unsigned char *)"abc", 3, d);
    check("md4", "\"abc\"", d, 16, "a448017aaf21d8525fc10ae87aa6729d");
    md4((const unsigned char *)"message digest", 14, d);
    check("md4", "\"message digest\"", d, 16, "d9130a8164549fe818874806e1c7014b");

    /* Every length from 0 to 200, checked against values the caller supplies
     * through the environment variable PWDCRACK_MD5_CORPUS, which
     * scripts/verify-kernels.sh fills from python hashlib. This is the check
     * that catches padding and block boundary mistakes: a kernel that is right
     * for short messages and wrong at 55, 56 or 64 bytes still passes the
     * vectors above. */
    const char *corpus = getenv("PWDCRACK_MD5_CORPUS");
    if (corpus && *corpus) {
        FILE *f = fopen(corpus, "r");
        if (!f) {
            printf("FAIL could not open corpus file %s\n", corpus);
            ++g_failures;
        } else {
            char line[512];
            int n = 0;
            while (fgets(line, sizeof(line), f)) {
                size_t len = strlen(line);
                while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                    line[--len] = '\0';
                }
                /* Format: <len> <hex expected> */
                char *sp = strchr(line, ' ');
                if (!sp) { continue; }
                *sp = '\0';
                size_t mlen = (size_t)atoi(line);
                const char *want = sp + 1;

                unsigned char *msg = (unsigned char *)malloc(mlen + 1);
                for (size_t k = 0; k < mlen; ++k) {
                    msg[k] = (unsigned char)((k * 7u + (mlen % 13u)) & 0xffu);
                }
                md5(msg, mlen, d);
                char what[64];
                snprintf(what, sizeof(what), "corpus len=%zu", mlen);
                check("md5", what, d, 16, want);
                free(msg);
                ++n;
            }
            fclose(f);
            printf("corpus: %d lengths checked (0..200)\n", n);
        }
    } else {
        printf("note: PWDCRACK_MD5_CORPUS not set, "
               "run scripts/verify-kernels.sh for the length sweep\n");
    }

    printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}