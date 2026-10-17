//! AVX2 hash verification.
//!
//! The MD5 implementation here is real: it is the eight lane multi-buffer kernel
//! in [`super::avx2_md5`], which is the only genuinely vectorised kernel in this
//! crate as of this writing. SHA-256 is not implemented and passes through to
//! scalar.
//!
//! [`md5_verify`] is a single candidate entry point and is deliberately not
//! accelerated. A multi-buffer kernel fills eight lanes with eight independent
//! messages, so giving it one message wastes seven lanes and costs more in
//! gather and store overhead than it saves. Callers with a list of candidates
//! should use [`md5_batch_verify`].

pub use super::avx2_md5::{LANES, avx2_available, md5_batch, md5_multi8};

use super::avx2_md5 as kernel;

/// Verifies one MD5 candidate against the scalar reference. See the module note
/// for why a single message is not sent through the vector path.
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    kernel::md5_verify(password, target_hex)
}

/// Verifies a batch of MD5 candidates, eight at a time when AVX2 is present.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    kernel::md5_batch_verify(passwords, targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avx2_is_present_on_the_build_host() {
        // The rest of this module is only meaningful where AVX2 exists. If this
        // ever fails the differential tests below are silently exercising the
        // scalar path instead, which would make them much weaker.
        assert!(
            avx2_available(),
            "this host lacks AVX2, so the vector path is not being exercised"
        );
    }

    #[test]
    fn batch_path_agrees_with_the_single_candidate_path() {
        let inputs: Vec<Vec<u8>> = (0..24u32).map(|i| format!("pw{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|m| m.as_slice()).collect();

        let digests: Vec<String> = inputs
            .iter()
            .map(|m| hex::encode(kernel::scalar_digest(m)))
            .collect();
        let targets: Vec<&str> = digests.iter().map(|s| s.as_str()).collect();

        let batched = md5_batch_verify(&refs, &targets);
        let single: Vec<bool> = refs
            .iter()
            .zip(targets.iter())
            .map(|(p, t)| md5_verify(p, t))
            .collect();

        assert_eq!(batched, single);
        assert!(batched.iter().all(|&b| b));
    }

    #[test]
    fn wrong_targets_are_reported_as_mismatches() {
        let a = b"alpha";
        let b = b"beta";
        let good = hex::encode(kernel::scalar_digest(a));
        let bad = "11111111111111111111111111111111";
        assert_eq!(md5_batch_verify(&[a, b], &[good.as_str(), bad]), vec![true, false]);
    }
}