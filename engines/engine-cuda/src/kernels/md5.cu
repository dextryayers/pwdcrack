// Multi-buffer MD5 for one candidate per thread.
//
// Structure: one thread per candidate. Each thread builds its own padded block
// in private memory and runs the compression from hash_core.h.
//
// The previous version of this file had six defects, all of which produced a
// digest that did not correspond to the input while still looking like a valid
// hash:
//
//   1. The round constant 0x5A827999 (a SHA-1 constant) was used for all 64
//      steps. MD5 needs the full K[64] table.
//   2. Every step used the rotation 7. MD5 needs the per step rotation table.
//   3. The round 2 word order was computed as (5i+1) mod 16, which is right for
//      the first step and wrong for the other 15.
//   4. A __shared__ w[16] array was written by every thread in the block, so
//      all 32 threads raced on the same 16 words.
//   5. Words were read through a (unsigned int*) cast of an unsigned char
//      pointer. That requires 4 byte alignment, which packed candidate buffers
//      do not provide.
//   6. There was no padding at all: no 0x80 marker, no length field.
//
// All six are gone. Points 1, 2, 3 and 6 are in the compression function and are
// verified on the host by scripts/verify-kernels.sh, which compiles the same
// header with the system C compiler and checks 220 values against RFC vectors,
// python hashlib and openssl. Point 5 is addressed by pw_load_le32, which
// assembles a word from individual bytes.
//
// Point 4 needs no shared memory at all: each thread hashes a different message,
// so the message schedule is private. A shared buffer would only be correct for
// a kernel where all threads cooperate on one message, which is not this one.
//
// What is NOT verified, because this kernel has never been run on a CUDA device:
// thread indexing beyond the obvious bounds check, the packing layout agreed
// with the host side, and any measured throughput. See docs/PHASE6_STATUS.md.

#include "hash_core.h"

/* Maximum candidate length this kernel accepts, in bytes.
 *
 * A longer candidate cannot be padded into the single on-stack block below, and
 * silently truncating it would produce a digest for a different string. The host
 * side filters on this constant before launching, so the kernel can treat an
 * over-long candidate as impossible rather than guessing. */
#define PW_MD5_MAX_CANDIDATE 119u

/* Digest width in bytes for MD5. */
#define PW_MD5_DIGEST_BYTES 16u

/* Padded block size: MD5 blocks are 64 bytes and the two block ceiling covers
 * every candidate up to 119 bytes. */
#define PW_MD5_PADDED_CAPACITY 128u

extern "C" __global__
void md5_digest(const unsigned char *candidates,
                unsigned int      *lengths,
                unsigned char    *out,
                unsigned int      count,
                unsigned int      stride)
{
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) {
        return;
    }

    unsigned int len = lengths[idx];

    /* Zero the digest slot first. A candidate that is skipped must not leave the
     * previous candidate's bytes behind for the host to misread as a match. */
    for (unsigned int i = 0; i < PW_MD5_DIGEST_BYTES; ++i) {
        out[idx * PW_MD5_DIGEST_BYTES + i] = 0;
    }

    if (len > PW_MD5_MAX_CANDIDATE) {
        return;
    }

    /* Private padded buffer.
     *
     * This must be a local array, not __shared__. Each thread pads and hashes a
     * different message, so a shared buffer would have every thread in the block
     * overwriting the same bytes, which is the race the previous version of this
     * kernel had with its shared w[16]. Local arrays in CUDA are backed by local
     * memory, which is slower than shared but correct, and 128 bytes per thread
     * is small enough that it is normally cached in L1. */
    unsigned char pad[PW_MD5_PADDED_CAPACITY];

    /* `stride` is the distance between candidates in the input buffer, and it is
     * a parameter rather than the maximum length. Tying the two together means
     * the host packing has to match a constant baked into the kernel, and when it
     * does not match every lane silently hashes the wrong bytes. */
    size_t padded = pw_pad_md(pad, PW_MD5_PADDED_CAPACITY,
                              candidates + (size_t)idx * (size_t)stride,
                              len, 64);
    if (padded == 0) {
        return;
    }

    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

    for (size_t off = 0; off < padded; off += 64) {
        pw_md5_compress(pad + off, state);
    }

    for (unsigned int i = 0; i < 4; ++i) {
        pw_store_le32(out + idx * PW_MD5_DIGEST_BYTES + i * 4, state[i]);
    }
}