// MD5 kernel in WGSL for the Vulkan compute path.
//
// One invocation per candidate. The compression is the same algorithm and the same
// tables the CPU, CUDA and OpenCL engines run.
//
// Why this is a separate file from the C and CUDA versions
// ---------------------------------------------------------
// WGSL has no preprocessor include and no `#define`, so unlike CUDA and OpenCL the
// shared core cannot be pulled in textually. This is a transcription, and the two
// things that go wrong when transcribing verified crypto are a mistyped constant
// and a rotation in the wrong direction. Both happened while writing the CUDA
// version and were caught only by differential testing, which is why the test for
// this file compares against python hashlib rather than against another copy of
// the same idea.
//
// Dialect notes
// -------------
// Written against the WGSL dialect naga 26 accepts, which predates the small
// integer types and pointer parameters. Two consequences:
//
//   * Byte buffers are `array<u32, 128>` rather than `array<u8, 128>`. Storing a
//     byte as a u32 in 0..255 is the same value, and the SPIR-V backend emits the
//     same 32 bit loads and stores.
//   * Per-invocation scratch lives in module-scope `var<private>` rather than in
//     a pointer passed to a helper function, which this dialect does not accept.
//
// Both are dialect constraints, not preferences. The arithmetic is identical.
//
// Verification
// ------------
// `scripts/verify-vulkan-kernels.sh` compiles this with naga, checks the SPIR-V
// magic and that a real module came out, and runs the identical algorithm through
// a host implementation of these semantics against python hashlib. It has also been
// executed on the AMD Radeon device on this machine. See docs/PHASE7_STATUS.md.

const K: array<u32, 64> = array<u32, 64>(
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
);

const S: array<u32, 64> = array<u32, 64>(
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
);

// Message word index per step, from RFC 1321 appendix A.3.
//
// A literal table, not a formula. (5i+1) mod 16 gives the right first word of
// round 2 and the wrong one for every word after it; (7i) mod 16 is wrong for
// round 4 in the same way. Deriving these is how the first CUDA kernel ended up
// hashing the wrong message words.
const G: array<u32, 64> = array<u32, 64>(
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
     5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
     0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9,
);

// Candidates longer than this are left with a zero digest rather than truncated.
// A digest of a truncated string can collide with a real target and report a
// match that did not happen.
const MAX_CANDIDATE: u32 = 119u;
const DIGEST_BYTES: u32 = 16u;
const PADDED_CAPACITY: u32 = 128u;

// Per-invocation scratch is a function local rather than a module-scope
// var<private>. naga 26 rejects a store through a private global that a helper
// function captured, reporting InvalidStorePointer; passing the scratch by value
// and returning the updated copy keeps every store lexically inside the calling
// function. It also has the pleasant property that the compiler can see the
// buffers do not escape.
//
// The alternative, sharing one buffer across a work group, would be wrong anyway:
// each invocation pads and hashes a different message.

struct Params {
    count: u32,
    stride: u32,
    pad0: u32,
    pad1: u32,
};

@group(0) @binding(0) var<storage, read> candidates: array<u32>;
@group(0) @binding(1) var<storage, read> lengths: array<u32>;
@group(0) @binding(2) var<storage, read_write> out: array<u32>;
@group(0) @binding(3) var<uniform> params: Params;

fn rotl(x: u32, s: u32) -> u32 {
    return (x << s) | (x >> (32u - s));
}

/// Reads a little endian 32 bit word from the private pad buffer.
///
/// Byte assembly rather than a reinterpret. The pad buffer is a u32 array here
/// for dialect reasons, but keeping the byte order explicit means the SPIR-V is
/// correct regardless of how the buffer is later stored, and it is what makes the
/// result independent of host endianness.
fn load_le32(pad: array<u32, 128>, off: u32) -> u32 {
    return (pad[off] & 0xffu)
         | ((pad[off + 1u] & 0xffu) << 8u)
         | ((pad[off + 2u] & 0xffu) << 16u)
         | ((pad[off + 3u] & 0xffu) << 24u);
}

/// Pads the candidate at `base` into g_pad, returning the padded length, or 0 if
/// it does not fit.
fn pad_md(base: u32, len: u32) -> array<u32, 128> {
    var pad: array<u32, 128>;
    if (len + 9u) > PADDED_CAPACITY {
        return pad;
    }
    for (var i: u32 = 0u; i < len; i = i + 1u) {
        pad[i] = candidates[base + i];
    }
    pad[len] = 0x80u;

    var total: u32 = len + 1u;
    loop {
        if (total % 64u) == 56u {
            break;
        }
        pad[total] = 0u;
        total = total + 1u;
    }

    let bit_len: u32 = len * 8u;
    pad[total] = bit_len & 0xffu;
    pad[total + 1u] = (bit_len >> 8u) & 0xffu;
    pad[total + 2u] = (bit_len >> 16u) & 0xffu;
    pad[total + 3u] = (bit_len >> 24u) & 0xffu;
    return pad;
}

/// Padded length for a message of `len` bytes. Used to decide how many blocks to
/// compress, computed the same way `pad_md` lays the message out so the two
/// cannot disagree.
fn padded_len(len: u32) -> u32 {
    if (len + 9u) > PADDED_CAPACITY {
        return 0u;
    }
    var total: u32 = len + 1u;
    loop {
        if (total % 64u) == 56u {
            break;
        }
        total = total + 1u;
    }
    return total + 4u;
}

/// Compresses the 64 byte block of g_pad starting at `off` into g_state.
fn compress(pad: array<u32, 128>, state: array<u32, 4>, off: u32) -> array<u32, 4> {
    var w: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i = i + 1u) {
        w[i] = load_le32(pad, off + i * 4u);
    }

    var a: u32 = state[0];
    var b: u32 = state[1];
    var c: u32 = state[2];
    var d: u32 = state[3];

    for (var i: u32 = 0u; i < 64u; i = i + 1u) {
        var f: u32;
        if (i < 16u) {
            f = (b & c) | (~b & d);
        } else if (i < 32u) {
            f = (d & b) | (~d & c);
        } else if (i < 48u) {
            f = b ^ c ^ d;
        } else {
            f = c ^ (b | ~d);
        }
        let t: u32 = f + a + K[i] + w[G[i]];
        a = d;
        d = c;
        c = b;
        b = b + rotl(t, S[i]);
    }

    var out_state: array<u32, 4>;
    out_state[0] = state[0] + a;
    out_state[1] = state[1] + b;
    out_state[2] = state[2] + c;
    out_state[3] = state[3] + d;
    return out_state;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx: u32 = gid.x;
    if (idx >= params.count) {
        return;
    }

    // Clear the slot first, so a skipped candidate cannot leave another
    // candidate's bytes behind for the host to read as a match.
    for (var i: u32 = 0u; i < DIGEST_BYTES; i = i + 1u) {
        out[idx * DIGEST_BYTES + i] = 0u;
    }

    let len: u32 = lengths[idx];
    if (len > MAX_CANDIDATE) {
        return;
    }

    if (padded_len(len) == 0u) {
        return;
    }
    var pad: array<u32, 128> = pad_md(idx * params.stride, len);

    var state: array<u32, 4> = array<u32, 4>(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

    let padded: u32 = padded_len(len);
    var off: u32 = 0u;
    loop {
        if (off >= padded) {
            break;
        }
        state = compress(pad, state, off);
        off = off + 64u;
    }

    // Store the digest little endian, byte at a time, so the layout in the
    // storage buffer does not depend on how the u32 buffer is viewed.
    for (var w: u32 = 0u; w < 4u; w = w + 1u) {
        let v: u32 = state[w];
        let base: u32 = idx * DIGEST_BYTES + w * 4u;
        out[base] = v & 0xffu;
        out[base + 1u] = (v >> 8u) & 0xffu;
        out[base + 2u] = (v >> 16u) & 0xffu;
        out[base + 3u] = (v >> 24u) & 0xffu;
    }
}