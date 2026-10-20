//! Multi-buffer MD4 over AVX2. This is also the NTLM kernel.
//!
//! # Why MD4 is the best case for multi-buffer
//!
//! MD4 is three rounds of sixteen steps, forty eight in total against MD5's
//! sixty four, and its round functions are cheap: one `AND`/`OR`/`ANDNOT`
//! select, one three way majority, one three way XOR. Every step still depends
//! on the step before it, so a single message cannot be vectorised, but eight
//! independent messages fill eight AVX2 lanes and the latency of that dependency
//! chain is paid once for eight candidates. Fewer and cheaper steps per message
//! means a larger fraction of each issue slot is useful work, which is why the
//! plan calls MD4 the largest win of the Phase 4 kernels.
//!
//! # NTLM is this kernel
//!
//! NTLMv1 hashes the password encoded as UTF-16LE with plain MD4, so NTLM needs
//! no second compression function: [`ntlm_batch_verify`] re-encodes each
//! candidate and calls the same kernel. UTF-16LE doubles the byte length, so a
//! candidate of 60 bytes or more falls outside the two block fast path and is
//! hashed scalar, which is documented rather than silently approximated.
//!
//! # Correctness contract
//!
//! Every lane must produce exactly the digest the scalar implementation
//! produces. The differential test compares against the `md4` crate for every
//! message length from 0 through 200, which covers both the one block and two
//! block padding cases and every block boundary in between, and the RFC 1320
//! Appendix A.5 suite is asserted separately so the kernel is held against a
//! published vector as well as against another implementation.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use md4::{Md4, Digest};

use super::avx2_md5::avx2_available;
use super::md_pad::pad_message;

/// Whether the AVX2 kernels can run on this host.
///
/// Re-exported from [`super::avx2_md5`], which owns the check, so callers that
/// only care about MD4 or NTLM do not have to reach into the MD5 module.
pub use super::avx2_md5::avx2_available as kernel_available;

/// Number of 32 bit lanes in an AVX2 register.
pub const LANES: usize = 8;

/// Round 2 additive constant: `floor(2^30 * sqrt(2))`.
const K2: u32 = 0x5A827999;
/// Round 3 additive constant: `floor(2^30 * sqrt(3))`.
const K3: u32 = 0x6ED9EBA1;

/// Serial reference digest, used by the differential test and by
/// [`md4_verify`] where batching is impossible.
pub fn scalar_digest(message: &[u8]) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(message);
    let out = h.finalize();
    let mut d = [0u8; 16];
    d.copy_from_slice(&out);
    d
}

/// Rotates each 32 bit lane left by `s` bits.
///
/// A macro because `_mm256_slli_epi32` needs an immediate operand, so the shift
/// amount has to be a literal at every call site.
macro_rules! rotl {
    ($v:expr, $s:literal) => {{
        _mm256_or_si256(
            _mm256_slli_epi32($v, $s),
            _mm256_srli_epi32($v, 32 - $s),
        )
    }};
}

/// Emits one MD4 step.
///
/// Unlike MD5, whose step macro rotates the roles of the four registers, MD4's
/// pseudocode keeps the registers in place and cycles the arguments: step `i`
/// writes to `a, d, c, b, a, d, c, b ...` in turn. This macro writes to the
/// register named by the caller and the F argument order is spelled out at each
/// call site, so every one of the forty eight lines below can be read against
/// RFC 1320 section 3.4 line by line.
macro_rules! step {
    ($dst:ident, $f:expr, $k:expr, $w:expr, $s:literal) => {{
        let t = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32($dst, $f),
                _mm256_set1_epi32($k as i32),
            ),
            $w,
        );
        $dst = rotl!(t, $s);
    }};
}

/// The full 48 step MD4 compression function over eight lanes.
///
/// # Safety
///
/// Requires the AVX2 feature. The body is one explicit `unsafe` block rather
/// than an implicit unsafe body, which edition 2024 rejects.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn md4_compress(
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

        // Round functions from RFC 1320 section 3.4. The macros take the three
        // registers in the order the step uses them, which rotates as the
        // register roles cycle: a step writing `a` applies F(b,c,d), a step
        // writing `d` applies F(a,b,c), and so on.
        macro_rules! f1 { ($x:ident,$y:ident,$z:ident) => {
            _mm256_or_si256(_mm256_and_si256($x,$y), _mm256_andnot_si256($x,$z))
        } }
        macro_rules! f2 { ($x:ident,$y:ident,$z:ident) => {
            _mm256_or_si256(
                _mm256_and_si256($x,$y),
                _mm256_or_si256(_mm256_and_si256($x,$z), _mm256_and_si256($y,$z)),
            )
        } }
        macro_rules! f3 { ($x:ident,$y:ident,$z:ident) => {
            _mm256_xor_si256(_mm256_xor_si256($x,$y),$z)
        } }

        // --- Round 1: F, K = 0, words in order, shifts 3 7 11 19 ---
        step!(a, f1!(b,c,d), 0u32, w[0],  3);
        step!(d, f1!(a,b,c), 0u32, w[1],  7);
        step!(c, f1!(d,a,b), 0u32, w[2],  11);
        step!(b, f1!(c,d,a), 0u32, w[3],  19);
        step!(a, f1!(b,c,d), 0u32, w[4],  3);
        step!(d, f1!(a,b,c), 0u32, w[5],  7);
        step!(c, f1!(d,a,b), 0u32, w[6],  11);
        step!(b, f1!(c,d,a), 0u32, w[7],  19);
        step!(a, f1!(b,c,d), 0u32, w[8],  3);
        step!(d, f1!(a,b,c), 0u32, w[9],  7);
        step!(c, f1!(d,a,b), 0u32, w[10], 11);
        step!(b, f1!(c,d,a), 0u32, w[11], 19);
        step!(a, f1!(b,c,d), 0u32, w[12], 3);
        step!(d, f1!(a,b,c), 0u32, w[13], 7);
        step!(c, f1!(d,a,b), 0u32, w[14], 11);
        step!(b, f1!(c,d,a), 0u32, w[15], 19);

        // --- Round 2: G, K = 0x5A827999, shifts 3 5 9 13 ---
        // The four groups read word columns 0, 1, 2, 3 with a stride of four.
        step!(a, f2!(b,c,d), K2, w[0],  3);
        step!(d, f2!(a,b,c), K2, w[4],  5);
        step!(c, f2!(d,a,b), K2, w[8],  9);
        step!(b, f2!(c,d,a), K2, w[12], 13);
        step!(a, f2!(b,c,d), K2, w[1],  3);
        step!(d, f2!(a,b,c), K2, w[5],  5);
        step!(c, f2!(d,a,b), K2, w[9],  9);
        step!(b, f2!(c,d,a), K2, w[13], 13);
        step!(a, f2!(b,c,d), K2, w[2],  3);
        step!(d, f2!(a,b,c), K2, w[6],  5);
        step!(c, f2!(d,a,b), K2, w[10], 9);
        step!(b, f2!(c,d,a), K2, w[14], 13);
        step!(a, f2!(b,c,d), K2, w[3],  3);
        step!(d, f2!(a,b,c), K2, w[7],  5);
        step!(c, f2!(d,a,b), K2, w[11], 9);
        step!(b, f2!(c,d,a), K2, w[15], 13);

        // --- Round 3: H, K = 0x6ED9EBA1, shifts 3 9 11 15 ---
        // Word groups are 0 8 4 12, then 2 10 6 14, then 1 9 5 13, then
        // 3 11 7 15. The middle two offsets are swapped relative to round 2
        // because the pseudocode reads X[0], X[8], X[4], X[12].
        step!(a, f3!(b,c,d), K3, w[0],  3);
        step!(d, f3!(a,b,c), K3, w[8],  9);
        step!(c, f3!(d,a,b), K3, w[4],  11);
        step!(b, f3!(c,d,a), K3, w[12], 15);
        step!(a, f3!(b,c,d), K3, w[2],  3);
        step!(d, f3!(a,b,c), K3, w[10], 9);
        step!(c, f3!(d,a,b), K3, w[6],  11);
        step!(b, f3!(c,d,a), K3, w[14], 15);
        step!(a, f3!(b,c,d), K3, w[1],  3);
        step!(d, f3!(a,b,c), K3, w[9],  9);
        step!(c, f3!(d,a,b), K3, w[5],  11);
        step!(b, f3!(c,d,a), K3, w[13], 15);
        step!(a, f3!(b,c,d), K3, w[3],  3);
        step!(d, f3!(a,b,c), K3, w[11], 9);
        step!(c, f3!(d,a,b), K3, w[7],  11);
        step!(b, f3!(c,d,a), K3, w[15], 15);

        (a, b, c, d)
    }
}

/// Computes MD4 for up to [`LANES`] messages at once.
///
/// Returns `None` when any message is too long for the two block fast path, so
/// the caller can fall back to scalar for that group rather than produce a
/// digest that is wrong only for the long messages.
///
/// # Safety
///
/// The caller must have verified that AVX2 is available. Use [`avx2_available`]
/// to check, or call through [`md4_batch`], which does.
#[target_feature(enable = "avx2")]
pub unsafe fn md4_multi8(messages: &[&[u8]]) -> Option<Vec<[u8; 16]>> {
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

    // SAFETY: the caller must have established that AVX2 is present. The
    // chaining values are the MD4 initial vector from RFC 1320 section 3.3,
    // which is the same four words MD5 uses.
    unsafe {
        let mut a = _mm256_set1_epi32(0x67452301u32 as i32);
        let mut b = _mm256_set1_epi32(0xefcdab89u32 as i32);
        let mut c = _mm256_set1_epi32(0x98badcfeu32 as i32);
        let mut d = _mm256_set1_epi32(0x10325476u32 as i32);

        let max_blocks = counts.iter().copied().max().unwrap_or(1);

        for blk in 0..max_blocks {
            // Stage one 32 bit word per lane through a byte array, then load it
            // with a single unaligned load. Eight `_mm256_insert_epi32` calls
            // would need compile time lane indices and so eight unrolled
            // statements per word position.
            let mut words: [__m256i; 16] = [_mm256_setzero_si256(); 16];
            let mut stage = [0u8; 32];
            for (wi, word) in words.iter_mut().enumerate() {
                for lane in 0..n {
                    let bytes: [u8; 4] = if blk < counts[lane] {
                        let off = wi * 4;
                        let block = &padded[lane][blk];
                        [block[off], block[off + 1], block[off + 2], block[off + 3]]
                    } else {
                        // This lane finished at an earlier block. Feed zeros and
                        // discard the result with the blend mask below, so the
                        // lane's state does not advance over padding it already
                        // consumed.
                        [0u8; 4]
                    };
                    stage[lane * 4..lane * 4 + 4].copy_from_slice(&bytes);
                }
                *word = _mm256_loadu_si256(stage.as_ptr() as *const __m256i);
            }

            let (na, nb, nc, nd) = md4_compress(a, b, c, d, &words);

            // A lane advances only while it still has a block left. `advance`
            // has 0xff across the bytes of every lane that should take the
            // freshly compressed value. `_mm256_blendv_epi8(x, y, mask)` returns
            // the second argument where the mask byte's high bit is set, so the
            // carried state is the first argument.
            let mut mb = [0u8; 32];
            for lane in 0..LANES {
                if lane < n && blk < counts[lane] {
                    mb[lane * 4..lane * 4 + 4].fill(0xff);
                }
            }
            let advance = _mm256_loadu_si256(mb.as_ptr() as *const __m256i);
            let zero = _mm256_setzero_si256();

            // MD4, like MD5, adds the state the block started from back into the
            // compressed state. The addend is masked to zero on lanes that did
            // not advance, which turns their feed forward into a plain copy
            // instead of adding a value to itself.
            a = _mm256_add_epi32(
                _mm256_blendv_epi8(a, na, advance),
                _mm256_blendv_epi8(zero, a, advance),
            );
            b = _mm256_add_epi32(
                _mm256_blendv_epi8(b, nb, advance),
                _mm256_blendv_epi8(zero, b, advance),
            );
            c = _mm256_add_epi32(
                _mm256_blendv_epi8(c, nc, advance),
                _mm256_blendv_epi8(zero, c, advance),
            );
            d = _mm256_add_epi32(
                _mm256_blendv_epi8(d, nd, advance),
                _mm256_blendv_epi8(zero, d, advance),
            );
        }

        // MD4 outputs the four state words little endian, so a straight word
        // store is the wire format.
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

/// Batched MD4, which is the entry point that reaches the vector path.
///
/// Messages longer than 119 bytes take the scalar path, which for NTLM means
/// candidate passwords of 60 bytes or more.
pub fn md4_batch(messages: &[&[u8]]) -> Vec<[u8; 16]> {
    let mut out = Vec::with_capacity(messages.len());

    let can_vector = avx2_available() && messages.iter().all(|m| m.len() <= 119);

    if can_vector {
        let mut idx = 0usize;
        while idx < messages.len() {
            let end = (idx + LANES).min(messages.len());
            let group = &messages[idx..end];
            // SAFETY: `can_vector` established that AVX2 is present and that
            // every message fits the two block window, which is the only way
            // `md4_multi8` returns `None`.
            match unsafe { md4_multi8(group) } {
                Some(digests) => out.extend_from_slice(&digests[..group.len()]),
                None => {
                    for m in group {
                        out.push(scalar_digest(m));
                    }
                }
            }
            idx = end;
        }
        return out;
    }

    for m in messages {
        out.push(scalar_digest(m));
    }
    out
}

/// Single message MD4, deliberately not accelerated.
///
/// One message cannot fill eight lanes, so the kernel would do the same work
/// with seven wasted lanes and extra gather traffic. Callers with several
/// messages should use [`md4_batch`].
pub fn md4_verify(password: &[u8], target_hex: &str) -> bool {
    hex::encode(scalar_digest(password)).eq_ignore_ascii_case(target_hex)
}

/// Verifies a batch of MD4 candidates against a batch of hex digests, pairing
/// them by position.
///
/// The comparison encodes each digest into a stack buffer instead of a `String`.
/// `hex::encode` allocates one string per candidate, which on this host cost
/// more than the hashing it was reporting: it is the reason the first version of
/// the NTLM batch path measured 0.65x the scalar path instead of above it.
pub fn md4_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    let n = passwords.len().min(targets.len());
    let digests = md4_batch(&passwords[..n]);
    let mut out = vec![false; n];
    let mut hexbuf = [0u8; 32];
    for i in 0..n {
        // `hexbuf` is exactly the hex length of a 16 byte digest, so a target of
        // any other length fails the comparison on length.
        let ok = hex::encode_to_slice(digests[i], &mut hexbuf).is_ok();
        out[i] = ok && targets[i].as_bytes().eq_ignore_ascii_case(&hexbuf);
    }
    out
}

/// Appends the UTF-16LE encoding of a UTF-8 password to `out`.
///
/// Returns `false` and appends nothing when the input is not valid UTF-8. A
/// version that appended as it went would leave half an encoding in the arena
/// and shift every later candidate, so the UTF-8 check happens first.
pub fn ntlm_encode_into(password: &[u8], out: &mut Vec<u8>) -> bool {
    let text = match std::str::from_utf8(password) {
        Ok(t) => t,
        Err(_) => return false,
    };
    out.reserve(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    true
}

/// Encodes a UTF-8 password as UTF-16LE, which is the byte string NTLM hashes.
///
/// Returns `None` for input that is not valid UTF-8. There is no correct
/// UTF-16LE form to hash in that case, and substituting replacement characters
/// would produce a digest that looks valid and matches nothing.
pub fn ntlm_encode(password: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if ntlm_encode_into(password, &mut out) { Some(out) } else { None }
}

/// Candidate group size for the NTLM path.
///
/// The batch entry point is called with the whole candidate list, but the encode
/// arena has to stay cache resident: measured on this host, a single 16384
/// candidate group ran at 0.96x the scalar path while groups of 512 ran at
/// 1.36x, because the arena stops fitting in L2 and every lane pays for memory
/// traffic instead of hashing. The chunk caps that, and the arena, span and
/// position vectors are reused across chunks so the allocation happens once.
const NTLM_CHUNK: usize = 1024;

/// Verifies a batch of NTLM candidates: MD4 over each password as UTF-16LE.
///
/// Candidates that are not valid UTF-8 are reported as mismatches without
/// reaching the kernel. The remaining ones keep their positions, so the returned
/// vector lines up with `passwords` even when invalid input is interleaved with
/// valid input in the same batch.
///
/// Every candidate is encoded into a single arena rather than into a `Vec` of
/// its own. Measured on this host with a 16 byte password corpus, one allocation
/// per candidate made this function run at 0.65x the scalar path: the encoding
/// cost is real work that has to happen, but its allocation traffic is not, and
/// hashing eight lanes at a time cannot pay for sixteen allocations per group.
pub fn ntlm_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    let n = passwords.len().min(targets.len());
    let mut results = vec![false; n];

    let mut arena: Vec<u8> = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut positions: Vec<usize> = Vec::new();
    let mut hexbuf = [0u8; 32];

    let mut chunk_start = 0usize;
    while chunk_start < n {
        let chunk_end = (chunk_start + NTLM_CHUNK).min(n);
        arena.clear();
        spans.clear();
        positions.clear();

        for i in chunk_start..chunk_end {
            let start = arena.len();
            if ntlm_encode_into(passwords[i], &mut arena) {
                spans.push((start, arena.len() - start));
                positions.push(i);
            }
        }

        let refs: Vec<&[u8]> = spans.iter().map(|&(s, l)| &arena[s..s + l]).collect();
        let digests = md4_batch(&refs);

        for (k, &i) in positions.iter().enumerate() {
            let ok = hex::encode_to_slice(digests[k], &mut hexbuf).is_ok();
            results[i] = ok && targets[i].as_bytes().eq_ignore_ascii_case(&hexbuf);
        }
        chunk_start = chunk_end;
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::scalar_ntlm_verify;

    /// RFC 1320 Appendix A.5, the same seven values `scripts/gen-rtl-vectors.py`
    /// checks its independent Python MD4 against. The seventh is included
    /// because a transcription error in it was once mistaken for an
    /// implementation defect, so it is asserted here too.
    ///
    /// Built at run time rather than declared `const` because the eighth entry
    /// repeats a literal eight times, which is not a constant expression.
    fn rfc1320_suite() -> Vec<(Vec<u8>, &'static str)> {
        vec![
            (b"".to_vec(), "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a".to_vec(), "bde52cb31de33e46245e05fbdbd6fb24"),
            (b"abc".to_vec(), "a448017aaf21d8525fc10ae87aa6729d"),
            (b"message digest".to_vec(), "d9130a8164549fe818874806e1c7014b"),
            (b"abcdefghijklmnopqrstuvwxyz".to_vec(), "d79e1c308aa5bbcdeea8ed63df412da9"),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (b"1234567890".repeat(8), "e33b4ddc9c38f2199c3e7b164fcc0536"),
        ]
    }

    #[test]
    fn scalar_matches_the_rfc1320_suite() {
        for (msg, want) in rfc1320_suite() {
            assert_eq!(hex::encode(scalar_digest(&msg)), want, "message {msg:?}");
        }
    }

    #[test]
    fn the_vectorised_kernel_matches_the_rfc1320_suite() {
        let suite = rfc1320_suite();
        let refs: Vec<&[u8]> = suite.iter().map(|(m, _)| m.as_slice()).collect();
        let got = md4_batch(&refs);
        for (i, (msg, want)) in suite.iter().enumerate() {
            assert_eq!(hex::encode(got[i]), *want, "lane {i} message {msg:?}");
        }
    }

    #[test]
    fn every_length_from_0_to_200_agrees_with_the_reference() {
        // Padding is where these kernels go wrong, and a wrong padding rule can
        // hold for one block and fail for two. Walking every length covers both
        // cases and the boundaries at 56 and 120 without relying on the choice
        // of boundary in the test.
        for len in 0..=200usize {
            let m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let got = md4_batch(&[&m]);
            assert_eq!(got[0], scalar_digest(&m), "length {len} disagreed");
        }
    }

    #[test]
    fn a_full_group_of_eight_is_correct_for_every_lane() {
        let msgs: Vec<Vec<u8>> =
            (0..LANES).map(|i| (0..40 + i).map(|j| (j % 251) as u8).collect()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md4_batch(&refs);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(got[i], scalar_digest(m), "lane {i} disagreed");
        }
    }

    #[test]
    fn lanes_finishing_at_different_blocks_each_stop_correctly() {
        // A one block message next to a two block one. The short lane must keep
        // the state it had after its single block instead of being advanced a
        // second time over zero words.
        let short: Vec<u8> = b"short".to_vec();
        let long: Vec<u8> = (0..100).map(|i| (i % 251) as u8).collect();
        let got = md4_batch(&[&short, &long]);
        assert_eq!(got[0], scalar_digest(&short), "the short lane advanced too far");
        assert_eq!(got[1], scalar_digest(&long));
    }

    #[test]
    fn a_ragged_batch_leaves_unused_lanes_out() {
        let msgs: Vec<Vec<u8>> = (0..3).map(|i| format!("candidate{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        let got = md4_batch(&refs);
        assert_eq!(got.len(), 3);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(got[i], scalar_digest(m));
        }
    }

    #[test]
    fn messages_past_the_two_block_window_fall_back_to_scalar() {
        let long = vec![b'z'; 500];
        let got = md4_batch(&[&long]);
        assert_eq!(got[0], scalar_digest(&long));
    }

    #[test]
    fn a_mixed_long_and_short_batch_is_all_correct() {
        let short = b"short".to_vec();
        let long = vec![b'y'; 300];
        let got = md4_batch(&[&short, &long]);
        assert_eq!(got[0], scalar_digest(&short));
        assert_eq!(got[1], scalar_digest(&long));
    }

    #[test]
    fn batch_verify_reports_per_item_results() {
        let a = b"one";
        let b = b"two";
        let ha = hex::encode(scalar_digest(a));
        let wrong = "00000000000000000000000000000000";
        assert_eq!(md4_batch_verify(&[a, b], &[ha.as_str(), wrong]), vec![true, false]);
    }

    #[test]
    fn an_empty_batch_is_empty() {
        assert!(md4_batch(&[]).is_empty());
    }

    #[test]
    fn ntlm_ascii_matches_the_reference() {
        let pw = b"password";
        let want = hex::encode(scalar_digest(b"p\0a\0s\0s\0w\0o\0r\0d\0"));
        assert_eq!(hex::encode(md4_batch(&[ntlm_encode(pw).unwrap().as_slice()])[0]), want);
        assert!(ntlm_batch_verify(&[pw], &[want.as_str()])[0]);
    }

    #[test]
    fn ntlm_multibyte_utf8_is_encoded_not_byte_mapped() {
        // "é" is two UTF-8 bytes and one UTF-16 code unit. Mapping input bytes
        // to code units would hash four bytes instead of two.
        let pw = "é".as_bytes();
        let want = hex::encode(scalar_digest(b"\xe9\0"));
        let got = ntlm_batch_verify(&[pw], &[want.as_str()]);
        assert!(got[0], "the multi-byte candidate did not match its own digest");
        assert!(scalar_ntlm_verify(pw, &want));
    }

    #[test]
    fn ntlm_rejects_input_that_is_not_utf8() {
        let bad = b"\xff\xfe";
        let target = "00000000000000000000000000000000";
        assert!(!ntlm_batch_verify(&[bad], &[target])[0]);
    }

    #[test]
    fn ntlm_invalid_input_does_not_disturb_its_neighbours() {
        // The invalid candidate is in the middle, so a batch that dropped it and
        // shifted the rest would report the wrong lanes.
        let good1 = b"alpha";
        let bad = b"\xff\xfe";
        let good2 = b"beta";
        let d1 = hex::encode(scalar_digest(b"a\0l\0p\0h\0a\0"));
        let d2 = hex::encode(scalar_digest(b"b\0e\0t\0a\0"));
        let wrong = "00000000000000000000000000000000";
        let got = ntlm_batch_verify(&[good1, bad, good2], &[d1.as_str(), wrong, d2.as_str()]);
        assert_eq!(got, vec![true, false, true]);
    }

    #[test]
    fn ntlm_batch_agrees_with_the_scalar_verifier_for_every_length() {
        // ASCII candidates from 1 to 60 bytes: 60 bytes is the last length whose
        // UTF-16LE form still fits the two block window, so 59 and 60 are the
        // interesting pair.
        for len in 1..=60usize {
            let pw: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let encoded = ntlm_encode(&pw).unwrap();
            let want = hex::encode(scalar_digest(&encoded));
            assert!(scalar_ntlm_verify(&pw, &want), "scalar disagrees at length {len}");
            assert!(ntlm_batch_verify(&[pw.as_slice()], &[want.as_str()])[0], "batch disagrees at length {len}");
        }
    }

    #[test]
    fn ntlm_verify_is_case_insensitive_on_hex() {
        let pw = b"case";
        let d = hex::encode(scalar_digest(&ntlm_encode(pw).unwrap()));
        assert!(ntlm_batch_verify(&[pw], &[d.to_uppercase().as_str()])[0]);
        assert!(ntlm_batch_verify(&[pw], &[d.to_lowercase().as_str()])[0]);
    }

    #[test]
    fn the_differential_tests_are_not_vacuous_on_this_host() {
        // Without this, `md4_batch` could fall back to scalar on a host that
        // reports AVX2 and every differential test above would still pass while
        // proving nothing about the vector code. The kernel is therefore called
        // directly here, and a wrong digest from it fails the test rather than
        // being absorbed by the fallback.
        if !avx2_available() {
            return;
        }
        let msgs: Vec<Vec<u8>> =
            (0..LANES).map(|i| (0..70 + i).map(|j| (j % 251) as u8).collect()).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        // SAFETY: `avx2_available` returned true.
        let direct = unsafe { md4_multi8(&refs) }
            .expect("the kernel refused a two block batch it must accept");
        assert_eq!(direct.len(), LANES);
        for (i, m) in msgs.iter().enumerate() {
            assert_eq!(direct[i], scalar_digest(m), "lane {i} disagreed through the kernel");
        }
    }
}
