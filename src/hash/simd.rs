//! Batch verification routed through the SIMD engine, when it is compiled in.
//!
//! # Why this module exists
//!
//! [`crate::hash::HashCracker::verify_batch`] gets called once per target with a
//! whole group of candidates, which is the one place where a multi-buffer kernel
//! can be used at all: the vector kernels hash eight independent messages at
//! once, so a caller that hands them a single candidate wastes seven lanes.
//!
//! # What happens without the engine
//!
//! [`batch_matches`] returns `None`, and every caller falls back to its own per
//! candidate loop. That is the same answer by construction, because the fallback
//! is the default implementation of `verify_batch`. The engine is therefore a
//! speed change and never a behaviour change, which is what makes it safe to
//! enable it by default.
//!
//! # Why the AVX2 check is repeated here
//!
//! The engine's own dispatch falls back to scalar when the host lacks AVX2, but
//! that fallback still builds a `Vec<bool>` for the group and copies every
//! candidate through it, so on a host without AVX2 the batched route is slower
//! than the plain loop while computing the same digests. The capability is
//! checked here so that route is never taken.

/// Which accelerated kernel can verify a hash type, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kernel {
    /// No kernel handles this hash type in the engine.
    None,
    /// AVX2 multi-buffer MD5.
    Md5,
    /// AVX2 multi-buffer MD4.
    Md4,
    /// AVX2 multi-buffer MD4 over UTF-16LE.
    Ntlm,
}

/// Whether the AVX2 kernels can run on this host.
///
/// On any architecture without those kernels this is `false` at compile time, so
/// the batched route is unreachable rather than merely unused.
#[cfg(feature = "engine-simd")]
fn kernels_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        engine_simd::x86::avx2_md5::avx2_available()
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Returns the candidates in `passwords` that match `target_hex`.
///
/// `None` means no kernel was used and the caller has to run its own loop.
#[cfg(feature = "engine-simd")]
pub(crate) fn batch_matches<'a>(
    kernel: Kernel,
    passwords: &[&'a str],
    target_hex: &str,
) -> Option<Vec<&'a str>> {
    if kernel == Kernel::None || !kernels_available() {
        return None;
    }

    announce(kernel);

    let refs: Vec<&[u8]> = passwords.iter().map(|p| p.as_bytes()).collect();
    let flags = match kernel {
        Kernel::Md5 => engine_simd::dispatch::md5_batch_verify_one(&refs, target_hex),
        Kernel::Md4 => engine_simd::dispatch::md4_batch_verify_one(&refs, target_hex),
        Kernel::Ntlm => engine_simd::dispatch::ntlm_batch_verify_one(&refs, target_hex),
        Kernel::None => return None,
    };

    Some(passwords.iter().zip(flags).filter(|(_, ok)| *ok).map(|(pw, _)| *pw).collect())
}

/// Logs, once per process and per kernel, that the vector path is in use.
///
/// `verify_batch` is called for every group of candidates, so logging
/// unconditionally would emit millions of identical lines. A bitmask makes the
/// line appear exactly once per kernel, at debug level, which is what `--verbose`
/// shows. The point is that a user can confirm acceleration is active without
/// reading the source, and a run that silently fell back to scalar emits nothing.
#[cfg(feature = "engine-simd")]
fn announce(kernel: Kernel) {
    use std::sync::atomic::{AtomicU8, Ordering};

    static ANNOUNCED: AtomicU8 = AtomicU8::new(0);
    let bit = match kernel {
        Kernel::Md5 => 1u8,
        Kernel::Md4 => 2u8,
        Kernel::Ntlm => 4u8,
        Kernel::None => return,
    };
    if ANNOUNCED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        log::debug!("SIMD: {kernel:?} batch path uses the AVX2 multi-buffer kernel");
    }
}

/// Without the engine there is no kernel, so the caller always runs its loop.
#[cfg(not(feature = "engine-simd"))]
pub(crate) fn batch_matches<'a>(
    _kernel: Kernel,
    _passwords: &[&'a str],
    _target_hex: &str,
) -> Option<Vec<&'a str>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MD5 of every message, computed with the digest crate directly.
    fn md5_hex(message: &[u8]) -> String {
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(message);
        hex::encode(h.finalize())
    }

    #[test]
    fn a_kernel_none_type_never_uses_a_kernel() {
        assert!(batch_matches(Kernel::None, &["a"], "00").is_none());
    }

    #[test]
    fn md5_batch_matches_the_digest_crate() {
        let words: Vec<String> = (0..600).map(|i| format!("candidate{i}")).collect();
        let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let target = md5_hex(b"candidate137");

        match batch_matches(Kernel::Md5, &refs, &target) {
            // A host without AVX2 cannot run the kernel, so the caller's loop is
            // what produces the answer there and there is nothing to check here.
            None => {}
            Some(hits) => assert_eq!(hits, vec!["candidate137"]),
        }
    }

    #[test]
    fn md4_and_ntlm_batches_match_their_references() {
        use md4::{Md4, Digest};

        let words: Vec<String> = (0..600).map(|i| format!("candidate{i}")).collect();
        let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();

        let md4_target = {
            let mut h = Md4::new();
            h.update(b"candidate42");
            hex::encode(h.finalize())
        };
        if let Some(hits) = batch_matches(Kernel::Md4, &refs, &md4_target) {
            assert_eq!(hits, vec!["candidate42"]);
        }

        // NTLM is MD4 over UTF-16LE, so the reference encodes explicitly.
        let ntlm_target = {
            let mut h = Md4::new();
            for unit in "candidate99".encode_utf16() {
                h.update(unit.to_le_bytes());
            }
            hex::encode(h.finalize())
        };
        if let Some(hits) = batch_matches(Kernel::Ntlm, &refs, &ntlm_target) {
            assert_eq!(hits, vec!["candidate99"]);
        }
    }

    #[test]
    fn a_group_with_no_match_returns_nothing() {
        let refs = ["alpha", "beta", "gamma"];
        if let Some(hits) = batch_matches(Kernel::Md5, &refs, &"00".repeat(16)) {
            assert!(hits.is_empty(), "an unrelated digest matched something");
        }
    }
}
