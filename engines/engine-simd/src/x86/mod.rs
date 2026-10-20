//! x86 and x86_64 SIMD implementations.
//!
//! # What is actually implemented
//!
//! | Extension | Module | State |
//! |-----------|--------|-------|
//! | AVX2 MD5 | [`avx2_md5`] | Implemented, 8 lanes, differentially tested against the reference digest |
//! | AVX2 MD4 / NTLM | [`avx2_md4`] | Implemented, 8 lanes, differentially tested against the reference digest |
//! | SSE2 | [`sse2`] | Pass through to scalar |
//! | SSE4.2 | [`sse42`] | Pass through to scalar |
//! | SHA extensions | [`shani`] | Pass through to scalar |
//! | AVX-512 | [`avx512`] | Pass through to scalar |
//!
//! The first two rows are vectorised, and [`md_pad`] is the padding they share.
//! Each pass-through module documents why the `target_feature` attribute by
//! itself does not produce the corresponding instructions, because that mistake
//! was previously documented as if it worked.
//!
//! Extension availability by generation, for reference when reading the table:
//! SSE2 is baseline on x86_64, SSE4.2 arrived with Nehalem in 2008, the SHA
//! extensions with Goldmont and Zen, AVX2 with Haswell in 2013, and AVX-512
//! with Skylake-X and Zen 4.

pub mod avx2_md5;
pub mod avx2_md4;
pub mod avx2;
pub mod avx512;
pub mod shani;
pub mod sse2;
pub mod sse42;
pub(crate) mod md_pad;

/// Lane count of the AVX2 MD5 kernel.
pub use avx2_md5::LANES;

/// Whether the AVX2 kernels can run on this host.
pub use avx2_md5::avx2_available;

/// Batched MD5, which is the entry point that reaches the vector path.
pub use avx2_md5::{md5_batch, md5_batch_verify, md5_batch_verify_one, md5_multi8};

/// Batched MD4 and NTLM, which reach the same vector path.
pub use avx2_md4::{
    md4_batch, md4_batch_verify, md4_batch_verify_one, md4_multi8, ntlm_batch_verify,
    ntlm_batch_verify_one, ntlm_encode,
};

use crate::SimdLevel;
use crate::dispatch::{scalar_md5_verify, scalar_sha256_verify};

/// Selects the MD5 verification function for a detected level.
///
/// Every arm except AVX2 currently resolves to a function that does the same work
/// as the scalar fallback, so this table exists to make the dispatch explicit
/// rather than to express a real performance difference. Only the AVX2 arm has a
/// vector implementation behind it, and even that one is reached through
/// [`md5_batch_verify`] rather than the single candidate function, because a one
/// message batch has no lanes to fill.
#[allow(dead_code)]
pub fn dispatch_md5(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    match level {
        SimdLevel::Avx512 => avx512::md5_verify,
        SimdLevel::Avx2 => avx2::md5_verify,
        _ => scalar_md5_verify,
    }
}

/// Selects the SHA-256 verification function for a detected level.
///
/// SHA-256 is scalar in every arm today. The SHA extensions would be the way to
/// accelerate it and [`shani`] is where that kernel belongs.
#[allow(dead_code)]
pub fn dispatch_sha256(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    let _ = level;
    scalar_sha256_verify
}