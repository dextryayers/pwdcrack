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
    /// GPU SHA-1.
    Sha1,
    /// GPU SHA-256.
    Sha256,
    /// GPU SHA-384.
    Sha384,
    /// GPU SHA-512.
    Sha512,
    /// GPU SHA-512/224.
    Sha512_224,
    /// GPU SHA-512/256.
    Sha512_256,
    /// GPU RIPEMD-160.
    Ripemd160,
    /// GPU BLAKE2b-512.
    Blake2b,
}

impl Kernel {
    /// The SIMD kernel for this hash type, when one exists.
    fn simd(self) -> Option<Self> {
        match self {
            Kernel::Md5 | Kernel::Md4 | Kernel::Ntlm => Some(self),
            _ => None,
        }
    }

    /// The name `engine-gpu` uses for this hash type, when it supports it.
    fn gpu_name(self) -> Option<&'static str> {
        match self {
            Kernel::Md5 => Some("md5"),
            Kernel::Md4 => Some("md4"),
            Kernel::Ntlm => Some("ntlm"),
            Kernel::Sha1 => Some("sha1"),
            Kernel::Sha256 => Some("sha256"),
            Kernel::Sha384 => Some("sha384"),
            Kernel::Sha512 => Some("sha512"),
            Kernel::Sha512_224 => Some("sha512_224"),
            Kernel::Sha512_256 => Some("sha512_256"),
            Kernel::Ripemd160 => Some("ripemd160"),
            Kernel::Blake2b => Some("blake2b"),
            Kernel::None => None,
        }
    }
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

/// GPU cracker installed by the process, when `--gpu` brought one up.
///
/// The engine is optional and the core crate must still build with no GPU, so
/// this is a `OnceLock` of an `Option`: set once to `Some` by the CLI, or left
/// empty and every caller takes the CPU path. It is never set to a cracker with
/// zero working pipelines, because `gpu_matches` checks the pipeline list before
/// dispatching.
#[cfg(feature = "engine-gpu")]
static GPU_CRACKER: std::sync::OnceLock<
    Option<std::sync::Arc<engine_gpu::cracker::GpuCracker>>,
> = std::sync::OnceLock::new();

/// Brings up the GPU batch path for this process.
///
/// Returns the number of hash types whose pipeline compiled. A zero means the
/// device exists but no shader built, and every caller then stays on the CPU.
/// Calling it again returns the count from the first call and does not create a
/// second device.
#[cfg(feature = "engine-gpu")]
pub(crate) fn install_gpu(engine: std::sync::Arc<engine_gpu::GpuEngine>) -> usize {
    if let Some(existing) = GPU_CRACKER.get() {
        return existing
            .as_ref()
            .map(|cracker| cracker.available().len())
            .unwrap_or(0);
    }

    let cracker = engine_gpu::cracker::GpuCracker::new_blocking(engine);
    let count = cracker.available().len();
    if count > 0 {
        log::info!(
            "GPU: batch verification available for {}",
            cracker.available().join(", ")
        );
    } else {
        log::warn!("GPU: no compute pipeline built, batch verification stays on the CPU");
    }
    let _ = GPU_CRACKER.set(Some(std::sync::Arc::new(cracker)));
    count
}

/// Smallest group worth sending to the GPU.
///
/// A 512-candidate dispatch measured 1.3M to 1.9M hashes per second on the
/// development host, slower than one scalar CPU core for the cheaper hashes,
/// because the submit and readback cost dominates. At 16,384 candidates the same
/// kernel measured 6.3M to 30M per second. The dictionary loop reads this value
/// so a GPU run actually hands the device that many candidates.
pub(crate) const MIN_GPU_GROUP: usize = 4_096;

/// The candidate group size the attack loop should use.
///
/// Returns `default` unless a GPU with at least one compiled kernel is installed,
/// in which case it raises the group to 16,384. That is the smallest measured
/// size where every supported kernel beat the scalar CPU path; see
/// `docs/PHASE5_STATUS.md` for the table.
pub(crate) fn preferred_group_size(default: usize) -> usize {
    #[cfg(feature = "engine-gpu")]
    {
        if let Some(Some(cracker)) = GPU_CRACKER.get() {
            if !cracker.available().is_empty() {
                return default.max(16_384);
            }
        }
    }
    default
}

/// Runs one group on the installed GPU, or returns `None` when it cannot.
///
/// `None` is the signal for the caller to try the SIMD kernel or its own loop.
/// It is returned when no device was installed, when the kernel for this hash
/// type did not build, or when this build has no GPU feature.
#[cfg(feature = "engine-gpu")]
fn gpu_matches<'a>(
    kernel: Kernel,
    passwords: &[&'a str],
    target_hex: &str,
) -> Option<Vec<&'a str>> {
    if passwords.len() < MIN_GPU_GROUP {
        return None;
    }
    let name = kernel.gpu_name()?;
    let cracker = GPU_CRACKER.get()?.as_ref()?;
    if !cracker.supports(name) {
        return None;
    }

    announce_gpu(name);
    let refs: Vec<&[u8]> = passwords.iter().map(|p| p.as_bytes()).collect();
    let flags = cracker.verify_many(name, &refs, target_hex);
    if flags.len() != passwords.len() {
        log::warn!(
            "GPU: {name} returned {} flags for {} candidates, using the CPU for this group",
            flags.len(),
            passwords.len()
        );
        return None;
    }
    Some(
        passwords
            .iter()
            .zip(flags)
            .filter(|(_, ok)| *ok)
            .map(|(pw, _)| *pw)
            .collect(),
    )
}

/// Logs, once per process and per GPU hash type, that the GPU path ran.
#[cfg(feature = "engine-gpu")]
fn announce_gpu(name: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};

    static ANNOUNCED: AtomicU64 = AtomicU64::new(0);
    let bit = match name {
        "md5" => 1 << 0,
        "md4" => 1 << 1,
        "ntlm" => 1 << 2,
        "sha1" => 1 << 3,
        "sha256" => 1 << 4,
        "sha384" => 1 << 5,
        "sha512" => 1 << 6,
        "sha512_224" => 1 << 7,
        "sha512_256" => 1 << 8,
        "ripemd160" => 1 << 9,
        "blake2b" => 1 << 10,
        _ => return,
    };
    if ANNOUNCED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        log::debug!("GPU: {name} batch path uses the compute kernel");
    }
}

/// Returns the candidates in `passwords` that match `target_hex`.
///
/// `None` means no kernel was used and the caller has to run its own loop. The
/// AVX2 kernel is preferred for the three hash types it implements, because it
/// measured faster than a small GPU dispatch on this host. Every other type goes
/// to the GPU when one is installed.
pub(crate) fn batch_matches<'a>(
    kernel: Kernel,
    passwords: &[&'a str],
    target_hex: &str,
) -> Option<Vec<&'a str>> {
    if kernel == Kernel::None {
        return None;
    }

    #[cfg(feature = "engine-simd")]
    if let Some(simd_kernel) = kernel.simd() {
        if kernels_available() {
            announce(simd_kernel);
            let refs: Vec<&[u8]> = passwords.iter().map(|p| p.as_bytes()).collect();
            let flags = match simd_kernel {
                Kernel::Md5 => engine_simd::dispatch::md5_batch_verify_one(&refs, target_hex),
                Kernel::Md4 => engine_simd::dispatch::md4_batch_verify_one(&refs, target_hex),
                Kernel::Ntlm => engine_simd::dispatch::ntlm_batch_verify_one(&refs, target_hex),
                _ => return None,
            };
            return Some(
                passwords
                    .iter()
                    .zip(flags)
                    .filter(|(_, ok)| *ok)
                    .map(|(pw, _)| *pw)
                    .collect(),
            );
        }
    }

    #[cfg(feature = "engine-gpu")]
    if let Some(hits) = gpu_matches(kernel, passwords, target_hex) {
        return Some(hits);
    }

    None
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
        _ => return,
    };
    if ANNOUNCED.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        log::debug!("SIMD: {kernel:?} batch path uses the AVX2 multi-buffer kernel");
    }
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

    /// Forces the GPU path for every installed kernel and compares it with the
    /// digest crates. The test skips on a host with no adapter or no compiled
    /// pipeline, which is the same condition that makes the CLI stay on the CPU.
    #[cfg(feature = "engine-gpu")]
    #[test]
    fn gpu_batch_matches_the_reference_for_every_installed_kernel() {
        use sha2::Digest;

        let Some(engine) = engine_gpu::GpuEngine::init_blocking() else {
            return;
        };
        let count = install_gpu(std::sync::Arc::new(engine));
        if count == 0 {
            return;
        }
        assert!(
            preferred_group_size(512) >= 16_384,
            "an installed GPU must raise the verification group to its measured size"
        );

        // 5,000 is above the 4,096-candidate floor where the GPU is used at
        // all, and below one full 16,384 group, so this also checks the tail.
        let words: Vec<String> = (0..5_000).map(|i| format!("candidate{i}")).collect();
        let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let password = b"candidate4137";

        let md5_target = hex::encode(md5::Md5::digest(password));
        let md4_target = hex::encode(md4::Md4::digest(password));
        let ntlm_target = {
            let mut h = md4::Md4::new();
            for unit in "candidate4137".encode_utf16() {
                h.update(unit.to_le_bytes());
            }
            hex::encode(h.finalize())
        };
        let sha1_target = hex::encode(sha1::Sha1::digest(password));
        let sha256_target = hex::encode(sha2::Sha256::digest(password));
        let sha384_target = hex::encode(sha2::Sha384::digest(password));
        let sha512_target = hex::encode(sha2::Sha512::digest(password));
        let sha512_224_target = hex::encode(sha2::Sha512_224::digest(password));
        let sha512_256_target = hex::encode(sha2::Sha512_256::digest(password));
        let ripemd_target = hex::encode(ripemd::Ripemd160::digest(password));
        let blake2b_target = hex::encode(blake2::Blake2b512::digest(password));

        for (kernel, target) in [
            (Kernel::Md5, md5_target),
            (Kernel::Md4, md4_target),
            (Kernel::Ntlm, ntlm_target),
            (Kernel::Sha1, sha1_target),
            (Kernel::Sha256, sha256_target),
            (Kernel::Sha384, sha384_target),
            (Kernel::Sha512, sha512_target),
            (Kernel::Sha512_224, sha512_224_target),
            (Kernel::Sha512_256, sha512_256_target),
            (Kernel::Ripemd160, ripemd_target),
            (Kernel::Blake2b, blake2b_target),
        ] {
            let hits = gpu_matches(kernel, &refs, &target)
                .unwrap_or_else(|| panic!("{kernel:?} has no installed GPU pipeline"));
            assert_eq!(hits, vec!["candidate4137"], "{kernel:?}");
        }

        // A candidate longer than the 64 byte record must still be answered by
        // the CPU fallback inside `verify_many`, and it must agree with the
        // digest crate for every kernel whose record limit it exceeds.
        let long = "x".repeat(65);
        let long_target = hex::encode(md5::Md5::digest(long.as_bytes()));
        let fillers: Vec<String> = (0..MIN_GPU_GROUP).map(|i| format!("filler{i}")).collect();
        let mut long_group: Vec<&str> = fillers.iter().map(|s| s.as_str()).collect();
        long_group.push(long.as_str());
        let hits = gpu_matches(Kernel::Md5, &long_group, &long_target)
            .expect("MD5 pipeline is installed");
        assert_eq!(hits, vec![long.as_str()]);
    }
}
