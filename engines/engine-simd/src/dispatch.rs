#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SimdLevel {
    Scalar  = 0,
    Sse2    = 1,
    Sse42   = 2,
    ShaNi   = 3,
    Avx2    = 4,
    Avx512  = 5,
    Vaes    = 6,
    Neon32  = 7,
    Neon64  = 8,
    Sve     = 9,
}

/// Verifies one MD5 candidate.
///
/// A single candidate is routed to the scalar implementation on purpose. The
/// AVX2 kernel in `x86::avx2_md5` is a multi-buffer design that fills eight
/// lanes with eight independent messages; handing it one message wastes the
/// other seven lanes and costs more in gather and store overhead than it saves.
/// Callers with a list of candidates should use [`md5_batch_verify`].
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

// The SHA extension is not implemented yet; `x86::shani` is a documented pass
    // through to the scalar path. The level check is kept so that adding real
    // SHA-NI kernels later needs no change here, but it currently selects a
    // function that does the same work as the fallback.
pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_verify(password, target_hex);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha256_verify(password, target_hex);
    }
    scalar_sha256_verify(password, target_hex)
}

// The SHA extension is not implemented yet; `x86::shani` is a documented pass
    // through to the scalar path. The level check is kept so that adding real
    // SHA-NI kernels later needs no change here, but it currently selects a
    // function that does the same work as the fallback.
pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_verify(password, target_hex);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha1_verify(password, target_hex);
    }
    scalar_sha1_verify(password, target_hex)
}

pub fn ntlm_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_ntlm_verify(password, target_hex)
}

/// Verifies a batch of MD5 candidates against their targets.
///
/// This is the entry point that reaches the vectorised kernel. On an x86 or
/// x86_64 host with AVX2 the work is done eight candidates at a time; everywhere
/// else, and for any candidate long enough to fall outside the two block fast
/// path, `md5_batch` handles it scalar and the result is unchanged. Either way
/// the per lane answer is the same as hashing each candidate on its own.
///
/// The gate is the runtime feature check, not [`crate::current_level`]. Gating
/// on the detected level made the vector path depend on [`crate::init`] having
/// run first: every library caller, meaning the dashboard, the C ABI, the
/// language bindings and the tests, would silently get the scalar path instead,
/// with no error and no way to tell from the outside. The feature check is the
/// ground truth and needs no setup.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if crate::x86::avx2_md5::avx2_available() {
            return crate::x86::avx2_md5::md5_batch_verify(passwords, targets);
        }
    }
    passwords.iter().zip(targets).map(|(pw, t)| md5_verify(pw, t)).collect()
}

/// Verifies one MD4 candidate.
///
/// A single candidate cannot fill eight lanes, so this is the scalar path. Use
/// [`md4_batch_verify`] for a list.
pub fn md4_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md4_verify(password, target_hex)
}

/// Verifies a batch of MD4 candidates against their targets.
///
/// Reaches the AVX2 multi-buffer kernel, eight candidates per pass, when the
/// host has AVX2 and the messages fit the two block window.
pub fn md4_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if crate::x86::avx2_md5::avx2_available() {
            return crate::x86::avx2_md4::md4_batch_verify(passwords, targets);
        }
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_md4_verify(pw, t)).collect()
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_batch_verify(passwords, targets);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha256_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_batch_verify(passwords, targets);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha1_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha1_verify(pw, t)).collect()
}

/// Verifies a batch of NTLM candidates against their targets.
///
/// NTLM is MD4 over the password encoded as UTF-16LE, so the vector path is the
/// MD4 kernel with an encoding step in front of it. Candidates that are not
/// valid UTF-8 have no UTF-16LE form; they are reported as mismatches and do not
/// disturb the lanes around them.
pub fn ntlm_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if crate::x86::avx2_md5::avx2_available() {
            return crate::x86::avx2_md4::ntlm_batch_verify(passwords, targets);
        }
    }
    passwords.iter().zip(targets).map(|(pw, t)| ntlm_verify(pw, t)).collect()
}

// Scalar fallbacks
pub fn scalar_md4_verify(password: &[u8], target_hex: &str) -> bool {
    use md4::{Md4, Digest};
    let mut hasher = Md4::new();
    hasher.update(password);
    hex::encode(hasher.finalize()).eq_ignore_ascii_case(target_hex)
}
pub fn scalar_md5_verify(password: &[u8], target_hex: &str) -> bool {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

pub fn scalar_sha1_verify(password: &[u8], target_hex: &str) -> bool {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

pub fn scalar_sha256_verify(password: &[u8], target_hex: &str) -> bool {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

/// NTLM hashes the password as UTF-16LE, so the input has to be decoded from
/// UTF-8 into code points first.
///
/// The previous implementation mapped each input *byte* straight to a `u16`.
/// That happens to agree with UTF-16LE for ASCII, because an ASCII byte is its
/// own code point, which is why no test caught it. It diverges for every
/// multi-byte UTF-8 sequence: "é" is two input bytes `c3 a9` and became the two
/// code points U+00C3 U+00A9 instead of the single U+00E9, so the hash was over
/// four bytes instead of two and no NTLM hash of a non-ASCII password could
/// ever match.
///
/// Returns false for input that is not valid UTF-8, because there is no correct
/// UTF-16LE representation to hash and silently substituting replacement
/// characters would produce a digest that looks valid but matches nothing.
pub fn scalar_ntlm_verify(password: &[u8], target_hex: &str) -> bool {
    use md4::{Md4, Digest};

    let text = match std::str::from_utf8(password) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let mut hasher = Md4::new();
    let units = text.encode_utf16();
    // MD4 is defined over bytes, so each code unit is fed as little endian.
    let mut buf = [0u8; 2];
    for unit in units {
        buf.copy_from_slice(&unit.to_le_bytes());
        hasher.update(buf);
    }
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MD4 over UTF-16LE, computed independently of the code under test.
    fn ntlm_reference(password: &str) -> String {
        use md4::{Md4, Digest};
        let mut hasher = Md4::new();
        for unit in password.encode_utf16() {
            hasher.update(unit.to_le_bytes());
        }
        hex::encode(hasher.finalize())
    }

    #[test]
    fn ntlm_matches_reference_for_ascii() {
        for pw in ["", "password", "P@ssw0rd123", "admin"] {
            assert_eq!(
                scalar_ntlm_verify(pw.as_bytes(), &ntlm_reference(pw)),
                true,
                "ascii input {pw:?} disagreed"
            );
        }
    }

    #[test]
    fn ntlm_handles_multibyte_utf8_as_single_code_points() {
        // The previous implementation mapped each input byte to a u16, which
        // agrees with UTF-16LE only while every byte is ASCII. These cases are
        // what that bug broke.
        for pw in ["é", "café", "naïve", "日本語", "🔑pass", "Ωmega"] {
            assert_eq!(
                scalar_ntlm_verify(pw.as_bytes(), &ntlm_reference(pw)),
                true,
                "multibyte input {pw:?} disagreed"
            );
        }
    }

    #[test]
    fn ntlm_rejects_invalid_utf8() {
        // A lone continuation byte is not valid UTF-8 and has no correct
        // UTF-16LE form, so no NTLM hash can match it.
        assert!(!scalar_ntlm_verify(&[0x80], &ntlm_reference("\u{80}")));
    }

    #[test]
    fn ntlm_would_fail_under_the_old_byte_to_u16_mapping() {
        // Documents why the case above matters: under the old mapping the two
        // inputs hash differently, proving the two implementations disagree on
        // non-ASCII and that the fix is what closed the gap.
        let old_style = {
            use md4::{Md4, Digest};
            let utf16: Vec<u16> = "é".as_bytes().iter().map(|&b| b as u16).collect();
            let mut bytes = Vec::new();
            for c in utf16 {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
            let mut h = Md4::new();
            h.update(&bytes);
            hex::encode(h.finalize())
        };
        assert_ne!(old_style, ntlm_reference("é"));
    }

    #[test]
    fn md5_verify_accepts_its_own_digest() {
        use md5::Digest;
        let mut h = md5::Md5::new();
        h.update(b"secret");
        let d = hex::encode(h.finalize());
        assert!(md5_verify(b"secret", &d));
        assert!(!md5_verify(b"secre", &d));
    }

    #[test]
    fn md5_batch_verify_agrees_with_single_verify() {
        // The dispatch level batch path may or may not take the vector route
        // depending on the host, but either way it must return what hashing each
        // candidate individually returns.
        let candidates: Vec<Vec<u8>> = (0..32u32).map(|i| format!("candidate{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = candidates.iter().map(|m| m.as_slice()).collect();
        let digests: Vec<String> = candidates.iter().map(|m| hex::encode(crate::x86::avx2_md5::scalar_digest(m))).collect();
        let target_refs: Vec<&str> = digests.iter().map(|s| s.as_str()).collect();

        let batched = md5_batch_verify(&refs, &target_refs);
        let one_at_a_time: Vec<bool> = refs
            .iter()
            .zip(target_refs.iter())
            .map(|(pw, t)| md5_verify(pw, t))
            .collect();

        assert_eq!(batched, one_at_a_time);
        assert!(batched.iter().all(|&b| b), "every candidate matches its own digest");
    }

    #[test]
    fn md5_batch_verify_reports_mismatches() {
        let a = b"one";
        let b = b"two";
        let ha = hex::encode(crate::x86::avx2_md5::scalar_digest(a));
        let wrong = "00000000000000000000000000000000";
        assert_eq!(md5_batch_verify(&[a, b], &[ha.as_str(), wrong]), vec![true, false]);
    }

    #[test]
    fn sha256_and_sha1_verify_their_own_digests() {
        use sha1::Sha1;
        use sha2::Sha256;
        use sha2::digest::Digest as _;

        let mut h1 = Sha1::new();
        h1.update(b"secret");
        let d1 = hex::encode(h1.finalize());
        assert!(sha1_verify(b"secret", &d1));
        assert!(!sha1_verify(b"secre", &d1));

        let mut h2 = Sha256::new();
        h2.update(b"secret");
        let d2 = hex::encode(h2.finalize());
        assert!(sha256_verify(b"secret", &d2));
        assert!(!sha256_verify(b"secre", &d2));
    }

    #[test]
    fn md4_batch_verify_agrees_with_single_verify() {
        let candidates: Vec<Vec<u8>> =
            (0..32u32).map(|i| format!("candidate{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = candidates.iter().map(|m| m.as_slice()).collect();
        let digests: Vec<String> = candidates
            .iter()
            .map(|m| hex::encode(crate::x86::avx2_md4::scalar_digest(m)))
            .collect();
        let targets: Vec<&str> = digests.iter().map(|s| s.as_str()).collect();

        assert_eq!(md4_batch_verify(&refs, &targets), {
            let one_at_a_time: Vec<bool> =
                refs.iter().zip(targets.iter()).map(|(pw, t)| md4_verify(pw, t)).collect();
            one_at_a_time
        });
        assert!(md4_batch_verify(&refs, &targets).iter().all(|&b| b));
    }

    #[test]
    fn ntlm_batch_verify_agrees_with_single_verify() {
        // Multi-byte and invalid UTF-8 candidates in one batch, so the result
        // vector has to stay aligned with the input rather than dropping lanes.
        let candidates: Vec<Vec<u8>> = vec![
            b"password".to_vec(),
            b"P@ssw0rd".to_vec(),
            "café".as_bytes().to_vec(),
            "日本語".as_bytes().to_vec(),
            vec![0x80],
            "🔑pass".as_bytes().to_vec(),
        ];
        let refs: Vec<&[u8]> = candidates.iter().map(|m| m.as_slice()).collect();
        let targets: Vec<String> = candidates
            .iter()
            .map(|m| match crate::x86::avx2_md4::ntlm_encode(m) {
                Some(enc) => hex::encode(crate::x86::avx2_md4::scalar_digest(&enc)),
                None => "0".repeat(32),
            })
            .collect();
        let target_refs: Vec<&str> = targets.iter().map(|s| s.as_str()).collect();

        assert_eq!(ntlm_batch_verify(&refs, &target_refs), vec![true, true, true, true, false, true]);
    }
}
