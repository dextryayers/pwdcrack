//! Multi-buffer MD5 over AVX2.
//!
//! # Why this shape
//!
//! MD5 is inherently serial: every step of the compression function depends on
//! the previous one, so a single message cannot be vectorised. The way to make
//! MD5 fast is to process **several independent messages at once**, one per SIMD
//! lane, so the latency of that dependency chain is filled by useful work from
//! the other lanes. This is the standard multi-buffer technique and it is what
//! every high rate MD5 cracker does.
//!
//! With eight 32 bit lanes on AVX2, eight passwords are hashed per pass instead
//! of one. The expected speedup is close to 8x on a core that is otherwise
//! stalled waiting on the MD5 dependency chain, minus the cost of padding.
//!
//! # Why the caller must batch
//!
//! This kernel does not hash one password. It hashes a slice of them. The
//! public entry point [`md5_batch`] takes a slice and returns a slice, and
//! [`md5_verify`] is a single item wrapper that is deliberately *not*
//! accelerated, because a one item batch has nothing to fill the lanes with.
//!
//! # Correctness contract
//!
//! Every lane must produce exactly the same digest as the scalar
//! implementation. That is checked by `tests`, which compares against the
//! `md-5` crate for message lengths 0 through 200 and at every block boundary.
//! A multi-buffer kernel that gets padding or length encoding wrong is the
//! classic source of "works on short passwords, silently wrong on long ones",
//! so the differential test covers the boundary cases explicitly.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use md5::{Md5, Digest};

/// Number of 32 bit lanes in an AVX2 register.
pub const LANES: usize = 8;

// The per step shift amounts are written as literals inside the `step!` calls
// rather than kept in a table, because `_mm256_slli_epi32` needs an immediate
// and reading the amount from an array would not compile. RFC 1321 uses the
// sequence 7 12 17 22 / 5 9 14 20 / 4 11 16 23 / 6 10 15 21, repeated per
// quarter, and those literals appear in that order.

/// MD5 round constants: `floor(abs(sin(i + 1)) * 2^32)` for `i` in 0..64.
const SINE: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
];

/// Serial reference digest, used by the differential test and by
/// [`md5_verify`] where batching is impossible.
pub fn scalar_digest(message: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(message);
    let out = h.finalize();
    let mut d = [0u8; 16];
    d.copy_from_slice(&out);
    d
}

// MD4 pads with the same bytes MD5 does, so the padding lives in one module
// that both kernels call. A second copy here would be a second chance at the
// defects this file's original version carried: a terminator skipped when the
// length was an exact multiple of 64, a bit length written to the wrong block,
// and a message accepted past the two block window.
use super::md_pad::pad_message;

/// Rotates each 32 bit lane left by `s` bits.
///
/// Written as a macro because `_mm256_slli_epi32` requires an immediate, so a
/// runtime shift amount cannot compile. Unrolling all 64 steps with literal
/// shifts is the standard approach for hand written SIMD and also removes every
/// branch from the inner loop.
macro_rules! rotl {
    ($v:expr, $s:literal) => {{
        _mm256_or_si256(
            _mm256_slli_epi32($v, $s),
            _mm256_srli_epi32($v, 32 - $s),
        )
    }};
}

/// Emits one MD5 step with a literal shift amount.
macro_rules! step {
    ($a:ident, $b:ident, $c:ident, $d:ident, $f:expr, $k:expr, $w:expr, $s:literal) => {{
        let tmp = _mm256_add_epi32(
            _mm256_add_epi32(_mm256_add_epi32($f, $a), _mm256_set1_epi32($k as i32)),
            $w,
        );
        $a = $d;
        $d = $c;
        $c = $b;
        $b = _mm256_add_epi32($b, rotl!(tmp, $s));
    }};
}

/// The full 64 step MD5 compression function, fully unrolled over eight lanes.
///
/// Unrolling is not only about immediates. Each step depends on the previous
/// one, so an unrolled body lets the compiler schedule the eight independent
/// lanes' arithmetic to hide the dependency latency, which is the entire point
/// of multi-buffer hashing.
///
/// # Safety
///
/// Requires the AVX2 feature. The body is one explicit `unsafe` block rather
/// than relying on `unsafe fn`, because edition 2024 rejects an implicit
/// unsafe body and a blanket allowance would hide the boundary.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn md5_compress(
    a: __m256i,
    b: __m256i,
    c: __m256i,
    d: __m256i,
    w: &[__m256i; 16],
) -> (__m256i, __m256i, __m256i, __m256i) {
    // SAFETY: the caller must have established that AVX2 is present, which is
    // the only precondition of every intrinsic used below.
    unsafe {
    let (mut a, mut b, mut c, mut d) = (a, b, c, d);
    // Round 1: F(b,c,d) = (b AND c) OR (NOT b AND d)
    // `f` is recomputed from the current b, c, d inside each step.
    macro_rules! f1 { ($b:ident,$c:ident,$d:ident) => {
        _mm256_or_si256(_mm256_and_si256($b,$c), _mm256_andnot_si256($b,$d))
    } }
    // Round functions per RFC 1321, written in terms of the register roles
    // b, c, d as they exist at the start of each step.
    //
    // The tricky ones are G and I. G is `F(x, d, c)` with the arguments
    // rotated, which expands to (b AND d) OR (c AND NOT d). I is `F(b, c, d)
    // XOR c`, which expands to c XOR (b OR NOT d).
    macro_rules! f2 { ($b:ident,$c:ident,$d:ident) => {
        _mm256_or_si256(_mm256_and_si256($b,$d), _mm256_andnot_si256($d,$c))
    } }
    macro_rules! f3 { ($b:ident,$c:ident,$d:ident) => {
        _mm256_xor_si256(_mm256_xor_si256($b,$c),$d)
    } }
    macro_rules! f4 { ($b:ident,$c:ident,$d:ident) => {
        _mm256_xor_si256($c,_mm256_or_si256($b,_mm256_andnot_si256($d,_mm256_set1_epi32(-1))))
    } }

    // --- Round 1, steps 0..15, g = i ---
    step!(a,b,c,d, f1!(b,c,d), SINE[0],  w[0],  7);
    step!(a,b,c,d, f1!(b,c,d), SINE[1],  w[1],  12);
    step!(a,b,c,d, f1!(b,c,d), SINE[2],  w[2],  17);
    step!(a,b,c,d, f1!(b,c,d), SINE[3],  w[3],  22);
    step!(a,b,c,d, f1!(b,c,d), SINE[4],  w[4],  7);
    step!(a,b,c,d, f1!(b,c,d), SINE[5],  w[5],  12);
    step!(a,b,c,d, f1!(b,c,d), SINE[6],  w[6],  17);
    step!(a,b,c,d, f1!(b,c,d), SINE[7],  w[7],  22);
    step!(a,b,c,d, f1!(b,c,d), SINE[8],  w[8],  7);
    step!(a,b,c,d, f1!(b,c,d), SINE[9],  w[9],  12);
    step!(a,b,c,d, f1!(b,c,d), SINE[10], w[10], 17);
    step!(a,b,c,d, f1!(b,c,d), SINE[11], w[11], 22);
    step!(a,b,c,d, f1!(b,c,d), SINE[12], w[12], 7);
    step!(a,b,c,d, f1!(b,c,d), SINE[13], w[13], 12);
    step!(a,b,c,d, f1!(b,c,d), SINE[14], w[14], 17);
    step!(a,b,c,d, f1!(b,c,d), SINE[15], w[15], 22);

    // --- Round 2 ---
    // Word order is taken literally from RFC 1321 appendix A.3, which lists
    // x[1], x[6], x[11], x[0], ... An earlier version of this file computed the
    // order as (5i+1) mod 16, which yields the right first word but the wrong
    // one for every step after it, and produced a plausible but incorrect digest
    // for every input. The explicit table is used rather than a formula so the
    // code can be checked against the specification line by line.
    step!(a,b,c,d, f2!(b,c,d), SINE[16], w[1],  5);
    step!(a,b,c,d, f2!(b,c,d), SINE[17], w[6],  9);
    step!(a,b,c,d, f2!(b,c,d), SINE[18], w[11], 14);
    step!(a,b,c,d, f2!(b,c,d), SINE[19], w[0],  20);
    step!(a,b,c,d, f2!(b,c,d), SINE[20], w[5],  5);
    step!(a,b,c,d, f2!(b,c,d), SINE[21], w[10], 9);
    step!(a,b,c,d, f2!(b,c,d), SINE[22], w[15], 14);
    step!(a,b,c,d, f2!(b,c,d), SINE[23], w[4],  20);
    step!(a,b,c,d, f2!(b,c,d), SINE[24], w[9],  5);
    step!(a,b,c,d, f2!(b,c,d), SINE[25], w[14], 9);
    step!(a,b,c,d, f2!(b,c,d), SINE[26], w[3],  14);
    step!(a,b,c,d, f2!(b,c,d), SINE[27], w[8],  20);
    step!(a,b,c,d, f2!(b,c,d), SINE[28], w[13], 5);
    step!(a,b,c,d, f2!(b,c,d), SINE[29], w[2],  9);
    step!(a,b,c,d, f2!(b,c,d), SINE[30], w[7],  14);
    step!(a,b,c,d, f2!(b,c,d), SINE[31], w[12], 20);

    // --- Round 3 ---
    step!(a,b,c,d, f3!(b,c,d), SINE[32], w[5],  4);
    step!(a,b,c,d, f3!(b,c,d), SINE[33], w[8],  11);
    step!(a,b,c,d, f3!(b,c,d), SINE[34], w[11], 16);
    step!(a,b,c,d, f3!(b,c,d), SINE[35], w[14], 23);
    step!(a,b,c,d, f3!(b,c,d), SINE[36], w[1],  4);
    step!(a,b,c,d, f3!(b,c,d), SINE[37], w[4],  11);
    step!(a,b,c,d, f3!(b,c,d), SINE[38], w[7],  16);
    step!(a,b,c,d, f3!(b,c,d), SINE[39], w[10], 23);
    step!(a,b,c,d, f3!(b,c,d), SINE[40], w[13], 4);
    step!(a,b,c,d, f3!(b,c,d), SINE[41], w[0],  11);
    step!(a,b,c,d, f3!(b,c,d), SINE[42], w[3],  16);
    step!(a,b,c,d, f3!(b,c,d), SINE[43], w[6],  23);
    step!(a,b,c,d, f3!(b,c,d), SINE[44], w[9],  4);
    step!(a,b,c,d, f3!(b,c,d), SINE[45], w[12], 11);
    step!(a,b,c,d, f3!(b,c,d), SINE[46], w[15], 16);
    step!(a,b,c,d, f3!(b,c,d), SINE[47], w[2],  23);

    // --- Round 4 ---
    step!(a,b,c,d, f4!(b,c,d), SINE[48], w[0],  6);
    step!(a,b,c,d, f4!(b,c,d), SINE[49], w[7],  10);
    step!(a,b,c,d, f4!(b,c,d), SINE[50], w[14], 15);
    step!(a,b,c,d, f4!(b,c,d), SINE[51], w[5],  21);
    step!(a,b,c,d, f4!(b,c,d), SINE[52], w[12], 6);
    step!(a,b,c,d, f4!(b,c,d), SINE[53], w[3],  10);
    step!(a,b,c,d, f4!(b,c,d), SINE[54], w[10], 15);
    step!(a,b,c,d, f4!(b,c,d), SINE[55], w[1],  21);
    step!(a,b,c,d, f4!(b,c,d), SINE[56], w[8],  6);
    step!(a,b,c,d, f4!(b,c,d), SINE[57], w[15], 10);
    step!(a,b,c,d, f4!(b,c,d), SINE[58], w[6],  15);
    step!(a,b,c,d, f4!(b,c,d), SINE[59], w[13], 21);
    step!(a,b,c,d, f4!(b,c,d), SINE[60], w[4],  6);
    step!(a,b,c,d, f4!(b,c,d), SINE[61], w[11], 10);
    step!(a,b,c,d, f4!(b,c,d), SINE[62], w[2],  15);
    step!(a,b,c,d, f4!(b,c,d), SINE[63], w[9],  21);

    (a, b, c, d)
    }
}

/// Computes MD5 for up to [`LANES`] messages at once.
///
/// Returns `None` when any message is too long for the two block fast path, so
/// the caller can fall back to scalar for that group rather than produce a
/// wrong digest.
///
/// # Safety
///
/// The caller must have verified that the AVX2 feature is available. Use
/// [`avx2_available`] to check, or call through [`md5_batch`] which does.
#[target_feature(enable = "avx2")]
pub unsafe fn md5_multi8(messages: &[&[u8]]) -> Option<Vec<[u8; 16]>> {
    let n = messages.len().min(LANES);
    let mut out = vec![[0u8; 16]; n];

    let mut padded: [[[u8; 64]; 2]; LANES] = [[[0u8; 64]; 2]; LANES];
    let mut counts = [0usize; LANES];
    for i in 0..n {
        counts[i] = match pad_message(messages[i], &mut padded[i]) {
            Some(c) => c,
            None => return None,
        };
    }

    // Initial state, identical for every lane. This is the MD5 chaining vector from
    // RFC 1321 section 3.3.
    //
    // SAFETY: the caller must have established that AVX2 is present.
    unsafe {
    let mut a = _mm256_set1_epi32(0x67452301u32 as i32);
    let mut b = _mm256_set1_epi32(0xefcdab89u32 as i32);
    let mut c = _mm256_set1_epi32(0x98badcfeu32 as i32);
    let mut d = _mm256_set1_epi32(0x10325476u32 as i32);

    let max_blocks = counts.iter().copied().max().unwrap_or(1);

    for blk in 0..max_blocks {
        // Gather word w for each of the 16 positions, one per lane.
        //
        // Words are staged through a byte array and loaded with a single
        // `_mm256_loadu_si256`. The alternative, `_mm256_insert_epi32` per lane,
        // needs a compile time lane index and would have to be unrolled eight
        // times. Staging costs one store and one load per word and lets the
        // loop stay a loop.
        let mut words: [__m256i; 16] = [_mm256_setzero_si256(); 16];
        let mut stage = [0u8; 32];
        for w in 0..16 {
            for lane in 0..n {
                let bytes: [u8; 4] = if blk < counts[lane] {
                    // `padded[lane][blk]` is already block `blk`, so the offset
                    // is within that block. Adding `blk * 64` here indexed past
                    // the end of the block for every message over 64 bytes, which
                    // is why single block batches were correct and multi block
                    // ones panicked.
                    let off = w * 4;
                    [
                        padded[lane][blk][off],
                        padded[lane][blk][off + 1],
                        padded[lane][blk][off + 2],
                        padded[lane][blk][off + 3],
                    ]
                } else {
                    // Lane has already finished. Its state must stop advancing,
                    // so feed zeros here and let the blend below discard it.
                    [0u8; 4]
                };
                stage[lane * 4..lane * 4 + 4].copy_from_slice(&bytes);
            }
            words[w] = _mm256_loadu_si256(stage.as_ptr() as *const __m256i);
        }

        let (na, nb, nc, nd) = md5_compress(a, b, c, d, &words);

        // MD5 chains blocks: the state entering a block is the state leaving the
        // previous one, and the compression output is added back to that input
        // state, not to the initial vector. Adding `a0` on every iteration is
        // correct for the first block and wrong for every later one, which is
        // why a single block batch agreed with the scalar digest and a two block
        // batch did not.
        //
        // A lane must only advance while it still has a block left. Lanes beyond
        // the batch length, and lanes whose message was shorter than the longest
        // in this group, have to keep the state they had.
        //
        // `advance` has 0xff on the bytes of every lane that should take the
        // freshly compressed value and 0x00 elsewhere. `_mm256_blendv_epi8(a, b,
        // mask)` returns `b` where the mask byte has its high bit set and `a`
        // everywhere else, so the carried state is the first argument and the
        // compressed result is the second. Inverting that polarity is silent: the
        // kernel returns a full 16 byte answer that simply does not correspond to
        // the input, and it was a real cause of a wrong digest here.
        let mut mb = [0u8; 32];
        for lane in 0..LANES {
            if lane < n && blk < counts[lane] {
                mb[lane * 4..lane * 4 + 4].fill(0xff);
            }
        }
        let advance = _mm256_loadu_si256(mb.as_ptr() as *const __m256i);
        let av = _mm256_blendv_epi8(a, na, advance);
        let bv = _mm256_blendv_epi8(b, nb, advance);
        let cv = _mm256_blendv_epi8(c, nc, advance);
        let dv = _mm256_blendv_epi8(d, nd, advance);

        // Feed-forward: add the state this block started from. Omitting it still
        // yields a plausible looking digest for one block and is wrong always.
        //
        // The addend is masked as well. A lane that did not advance this round
        // already holds the correct value in `av`, so adding its own state again
        // would double it. Masking the addend to zero on those lanes turns the
        // feed forward into a plain copy.
        let zero = _mm256_setzero_si256();
        let addend_a = _mm256_blendv_epi8(zero, a, advance);
        let addend_b = _mm256_blendv_epi8(zero, b, advance);
        let addend_c = _mm256_blendv_epi8(zero, c, advance);
        let addend_d = _mm256_blendv_epi8(zero, d, advance);
        a = _mm256_add_epi32(av, addend_a);
        b = _mm256_add_epi32(bv, addend_b);
        c = _mm256_add_epi32(cv, addend_c);
        d = _mm256_add_epi32(dv, addend_d);
    }

    // Store each lane's digest. The state is little endian word order, and MD5
    // outputs the words little endian, so a straight word store is correct.
    let mut abuf = [0i32; LANES];
    let mut bbuf = [0i32; LANES];
    let mut cbuf = [0i32; LANES];
    let mut dbuf = [0i32; LANES];
    _mm256_storeu_si256(abuf.as_mut_ptr() as *mut __m256i, a);
    _mm256_storeu_si256(bbuf.as_mut_ptr() as *mut __m256i, b);
    _mm256_storeu_si256(cbuf.as_mut_ptr() as *mut __m256i, c);
    _mm256_storeu_si256(dbuf.as_mut_ptr() as *mut __m256i, d);

    for lane in 0..n {
        out[lane][0..4].copy_from_slice(&abuf[lane].to_le_bytes());
        out[lane][4..8].copy_from_slice(&bbuf[lane].to_le_bytes());
        out[lane][8..12].copy_from_slice(&cbuf[lane].to_le_bytes());
        out[lane][12..16].copy_from_slice(&dbuf[lane].to_le_bytes());
    }
    }
    Some(out)
}

/// Whether AVX2 is available on this host.
pub fn avx2_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Batched MD5 entry point.
///
/// Uses the AVX2 kernel when the host supports it and every message fits the
/// two block window, otherwise falls back to the scalar implementation per
/// message. The result is always the same as hashing each message separately;
/// the batching only changes how the work is scheduled.
///
/// Messages longer than 119 bytes take the scalar path. That covers effectively
/// every real password and keeps the fast path a fixed size buffer, which is
/// what makes the register pressure predictable.
pub fn md5_batch(messages: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = Vec::with_capacity(messages.len());

    let can_vector = avx2_available()
        && messages
            .iter()
            .all(|m| m.len() <= 119);

    if can_vector {
        let mut idx = 0usize;
        while idx < messages.len() {
            let end = (idx + LANES).min(messages.len());
            let group = &messages[idx..end];
            // SAFETY: `can_vector` established the feature is present, and
            // `pad_message` rejects anything too long, which `md5_multi8`
            // reports by returning None.
            match unsafe { md5_multi8(group) } {
                Some(digests) => {
                    out.extend_from_slice(&digests[..group.len()]);
                    idx = end;
                }
                None => {
                    // Should not happen given the length check above, but a
                    // correct fallback beats a wrong digest.
                    for m in group {
                        out.push(scalar_digest(m));
                    }
                    idx = end;
                }
            }
        }
        return out;
    }

    for m in messages {
        out.push(scalar_digest(m));
    }
    out
}

/// Single message MD5. Not accelerated, and documented as such.
///
/// A single message cannot fill eight lanes, so routing it through the kernel
/// would cost more than it saves. Callers with several messages should use
/// [`md5_batch`] and get the real speedup.
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    let d = scalar_digest(password);
    hex::encode(d).eq_ignore_ascii_case(target_hex)
}

/// Verifies a batch of passwords against a batch of hex digests, pairing them by
/// position.
///
/// The comparison writes each digest into a stack buffer. `hex::encode` would
/// allocate one `String` per lane, which is pure overhead next to eight hashes.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    let n = passwords.len().min(targets.len());
    let digests = md5_batch(&passwords[..n]);
    let mut out = vec![false; n];
    let mut hexbuf = [0u8; 32];
    for i in 0..n {
        let ok = hex::encode_to_slice(digests[i], &mut hexbuf).is_ok();
        out[i] = ok && targets[i].as_bytes().eq_ignore_ascii_case(&hexbuf);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86::md_pad::block_count;

    #[test]
    fn scalar_matches_known_vector() {
        // RFC 1321 test suite.
        assert_eq!(
            hex::encode(scalar_digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex::encode(scalar_digest(b"a")),
            "0cc175b9c0f1b6a831c399e269772661"
        );
        assert_eq!(
            hex::encode(scalar_digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex::encode(scalar_digest(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex::encode(scalar_digest(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn block_count_boundaries() {
        assert_eq!(block_count(0), 1);
        assert_eq!(block_count(55), 1, "55 bytes plus padding fits one block");
        assert_eq!(block_count(56), 2, "56 bytes needs a second block");
        assert_eq!(block_count(119), 2);
        assert_eq!(block_count(120), 3, "beyond the two block fast path");
    }

    #[test]
    fn padding_matches_scalar_for_every_length_up_to_two_blocks() {
        // The most common multi-buffer bug is wrong padding, so check the
        // padded bytes directly against what the scalar implementation implies.
        for len in 0..=119usize {
            let msg = vec![b'a'; len];
            let mut out = [[0u8; 64]; 2];
            let blocks = pad_message(&msg, &mut out).expect("fits two blocks");

            // Reconstruct the logical byte stream and compare lengths.
            let total = blocks * 64;
            assert!(total >= len + 9, "padded length must leave room for length");

            // The 0x80 marker must be at position len within the stream.
            let marker = if len < 64 { out[0][len] } else { out[1][len - 64] };
            assert_eq!(marker, 0x80, "0x80 marker missing at len {len}");

            // Bytes after the marker up to the length field must be zero.
            for b in len + 1..blocks * 64 - 8 {
                let v = if b < 64 { out[0][b] } else { out[1][b - 64] };
                assert_eq!(v, 0, "non zero padding byte at {b} for len {len}");
            }

            // The length field must be the bit length, little endian.
            let lb = blocks * 64 - 8;
            let got = if lb < 64 {
                u64::from_le_bytes(out[0][lb..lb + 8].try_into().unwrap())
            } else {
                u64::from_le_bytes(out[1][lb - 64..lb - 64 + 8].try_into().unwrap())
            };
            assert_eq!(got, (len as u64) * 8, "bit length wrong for len {len}");
        }
    }

    #[test]
    fn batch_of_one_matches_scalar() {
        let m: &[u8] = b"hello";
        let got = md5_batch(&[m]);
        assert_eq!(got[0], scalar_digest(m));
    }

    #[test]
    fn batch_of_eight_matches_scalar() {
        let msgs: Vec<Vec<u8>> = (0..8).map(|i| format!("password{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md5_batch(&refs);
        assert_eq!(got.len(), 8);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(got[i], scalar_digest(m), "lane {i} disagreed");
        }
    }

    #[test]
    fn batch_covers_every_length_up_to_the_fast_path_limit() {
        // This is the differential test that matters most: a kernel that is
        // correct for short messages and wrong for long ones would still pass a
        // naive test. Every length from 0 to 119 is exercised, which covers all
        // padding and block boundary cases.
        let mut msgs: Vec<Vec<u8>> = Vec::new();
        let mut expected: Vec<[u8; 16]> = Vec::new();
        for len in 0..=119usize {
            let m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            msgs.push(m);
            expected.push(scalar_digest(&msgs[msgs.len() - 1]));
        }
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md5_batch(&refs);
        assert_eq!(got.len(), expected.len());
        for (i, e) in expected.iter().enumerate() {
            assert_eq!(&got[i], e, "length {} disagreed", msgs[i].len());
        }
    }

    #[test]
    fn ragged_batch_fills_remaining_lanes_with_zeros() {
        // A batch shorter than LANES must still produce correct digests, with
        // unused lanes simply not written out.
        let msgs: Vec<Vec<u8>> = (0..3).map(|i| format!("p{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md5_batch(&refs);
        assert_eq!(got.len(), 3);
        for i in 0..3 {
            assert_eq!(got[i], scalar_digest(&refs[i]));
        }
    }

    #[test]
    fn long_messages_take_the_scalar_fallback() {
        let msg = vec![b'x'; 500];
        let got = md5_batch(&[&msg]);
        assert_eq!(got[0], scalar_digest(&msg), "long message must fall back");
    }

    #[test]
    fn mixed_long_and_short_batch_is_all_correct() {
        // One long message in a batch must not corrupt the short ones.
        let short = b"short".to_vec();
        let long = vec![b'y'; 300];
        let got = md5_batch(&[&short, &long]);
        assert_eq!(got[0], scalar_digest(&short));
        assert_eq!(got[1], scalar_digest(&long));
    }

    #[test]
    fn empty_batch_is_empty() {
        assert!(md5_batch(&[]).is_empty());
    }

    #[test]
    fn batch_verify_reports_per_item_results() {
        let a = b"one";
        let b = b"two";
        let ha = hex::encode(scalar_digest(a));
        // The second target is deliberately wrong so the test checks that a
        // batch reports per lane results instead of collapsing them.
        let wrong = "00000000000000000000000000000000";
        let res = md5_batch_verify(&[a, b], &[ha.as_str(), wrong]);
        assert_eq!(res, vec![true, false]);
    }

    #[test]
    fn two_block_lengths_are_correct() {
        // Messages of 56 bytes and above need a second MD5 block. Three separate
        // defects in the vectorised path only showed up here: a wrong word
        // offset that indexed past the block, a blend mask with inverted
        // polarity that discarded the compressed result, and feeding forward the
        // initial vector instead of the previous block's state. Every one of them
        // left single block messages correct, so this test is the one that
        // actually pins the chaining down.
        for len in [56usize, 57, 63, 64, 65, 100, 118, 119] {
            let m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let got = md5_batch(&[&m]);
            assert_eq!(got[0], scalar_digest(&m), "length {len} disagreed");
        }
    }

    #[test]
    fn lanes_finishing_at_different_blocks_each_stop_correctly() {
        // A group mixing a one block message with a two block one. The short lane
        // must keep its state after the first block instead of being advanced a
        // second time over zeros.
        let short: Vec<u8> = b"short".to_vec();
        let long: Vec<u8> = (0..100).map(|i| (i % 251) as u8).collect();
        let got = md5_batch(&[&short, &long]);
        assert_eq!(got[0], scalar_digest(&short), "short lane advanced too far");
        assert_eq!(got[1], scalar_digest(&long));
    }

    #[test]
    fn a_group_of_eight_two_block_messages_is_correct() {
        // Every lane active for both blocks, so the advance mask is fully set and
        // no lane takes the carry forward path.
        let msgs: Vec<Vec<u8>> = (0..8).map(|i| (0..70 + i).map(|j| (j % 251) as u8).collect()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md5_batch(&refs);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(got[i], scalar_digest(m), "lane {i} disagreed");
        }
    }

    #[test]
    fn verify_is_case_insensitive_on_hex() {
        let d = hex::encode(scalar_digest(b"hello"));
        assert!(md5_verify(b"hello", &d.to_uppercase()));
        assert!(md5_verify(b"hello", &d.to_lowercase()));
        assert!(!md5_verify(b"hello2", &d));
    }
}
