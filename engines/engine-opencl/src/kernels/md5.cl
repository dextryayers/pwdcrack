/* OpenCL C MD5 kernel.
 *
 * One work item per candidate. The compression comes from hash_core.cl, which
 * scripts/gen-opencl-core.py generates from the shared header, so this file and
 * the CUDA engine run the same verified code.
 *
 * What the previous version of this kernel did wrong, all of it silent:
 *
 *   1. Round constants were four hand-picked values out of the 64 entry table,
 *      applied one per quarter of the rounds, plus 0x5A827999 added to every
 *      step. MD5 needs the full K[64].
 *   2. Rotation 7 for every step, instead of the per step table.
 *   3. Round 2 word order from the formula (5i+1) mod 16, which is right for the
 *      first step and wrong for the other 15.
 *   4. Words read through a (__global const uint*) cast of a uchar pointer, which
 *      needs 4 byte alignment that packed candidate buffers do not provide.
 *   5. No padding at all.
 *   6. Candidates were read until the first zero byte, so any candidate
 *      containing a zero byte, or any shorter than the assumed 64, produced the
 *      digest of a truncated string.
 *   7. w[16] entries were left uninitialised when the candidate was short, so
 *      the result depended on whatever the driver left on the stack.
 *   8. The candidate stride was a literal 68 baked into the source.
 *
 * Device side limits
 * ------------------
 * MAX_CANDIDATE covers a two block digest. A longer candidate is left with a
 * zero digest rather than truncated, because a digest of a truncated string can
 * collide with a real target and report a match that did not happen. The host
 * side filters on the same constant before dispatching.
 *
 * Verified by scripts/verify-opencl-kernels.sh, which compiles this source with
 * clang in OpenCL mode, checks the generated core against 220 reference values,
 * and executes the kernel body through a host shim. It has not been run on an
 * OpenCL device, because this machine has the ICD loader and no vendor ICD, so
 * there are zero OpenCL devices. See docs/PHASE7_STATUS.md.
 */

#define PW_MD5_MAX_CANDIDATE 119u
#define PW_MD5_DIGEST_BYTES 16u
#define PW_MD5_PADDED_CAPACITY 128u

__kernel void md5_digest(
    __global const uchar *candidates,
    __global const uint  *lengths,
    __global uchar       *out,
    uint                  count,
    uint                  stride)
{
    uint idx = get_global_id(0);
    if (idx >= count) {
        return;
    }

    /* Clear the slot first so a skipped candidate cannot leave another
     * candidate's bytes behind for the host to read as a match. */
    for (uint i = 0; i < PW_MD5_DIGEST_BYTES; ++i) {
        out[idx * PW_MD5_DIGEST_BYTES + i] = 0;
    }

    uint len = lengths[idx];
    if (len > PW_MD5_MAX_CANDIDATE) {
        return;
    }

    /* Private, not __local. Each work item pads and hashes a different message,
     * so a local buffer would have the whole work group overwriting one buffer. */
    uchar pad[PW_MD5_PADDED_CAPACITY];

    size_t padded = pw_pad_md(pad, PW_MD5_PADDED_CAPACITY,
                              candidates + (size_t)idx * (size_t)stride,
                              (size_t)len, 64);
    if (padded == 0) {
        return;
    }

    uint state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

    for (size_t off = 0; off < padded; off += 64) {
        pw_md5_compress(pad + off, state);
    }

    for (uint i = 0; i < 4; ++i) {
        pw_store_le32(out + idx * PW_MD5_DIGEST_BYTES + i * 4, state[i]);
    }
}