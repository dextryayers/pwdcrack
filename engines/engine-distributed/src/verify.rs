//! Hash verification for a distributed worker.
//!
//! This engine supports fewer types than the main binary, and that difference is
//! the dangerous part. A cluster run against a type this module cannot verify
//! returns zero cracks, which is indistinguishable from a correct negative
//! result, so the caller must ask [`supports`] first. There is a test for that
//! refusal and a test that the supported set is exactly what is claimed.

use digest::Digest;

/// The hash types this engine can verify, with the spellings that map to them.
///
/// Public so a caller can enumerate rather than guess. Anything not in this list
/// produces zero cracks, which looks like a clean run.
pub const SUPPORTED: &[(&str, &[&str])] = &[
    ("MD5", &["MD5", "RAWMD5", "MD5HASH"]),
    ("SHA1", &["SHA1", "RAWSHA1", "SHA1HASH"]),
    ("SHA256", &["SHA256", "RAWSHA256", "SHA256HASH"]),
    ("NTLM", &["NTLM", "NTLMHASH"]),
    ("MD4", &["MD4", "RAWMD4", "MD4HASH"]),
];

/// The canonical name for a hash type, or `None` when this engine cannot verify
/// it.
///
/// Accepts the main binary's display names, which carry a `Hash` suffix that the
/// internal names do not, so a caller can pass what `HashCracker::name` returned
/// without having to know the difference.
pub fn canonical_name(hash_type: &str) -> Option<&'static str> {
    let ht = hash_type.to_uppercase().replace('-', "");
    SUPPORTED
        .iter()
        .find(|(_, spellings)| spellings.contains(&ht.as_str()))
        .map(|(name, _)| *name)
}

/// True when this engine can verify the named type.
pub fn supports(hash_type: &str) -> bool {
    canonical_name(hash_type).is_some()
}

pub fn verify(hash_type: &str, hash_str: &str, password: &str) -> bool {
    // The canonical name is looked up first, so an unsupported type is refused
    // without hashing anything at all. The previous form hashed first and
    // returned false, which is the same answer for "wrong password" and "cannot
    // verify", and the two must be distinguishable.
    let Some(ht) = canonical_name(hash_type) else {
        log::warn!(
            "Unsupported hash type '{hash_type}' in distributed worker. Supported: {:?}",
            SUPPORTED.iter().map(|(n, _)| *n).collect::<Vec<_>>()
        );
        return false;
    };
    match ht {
        "MD5" => verify_raw::<md5::Md5>(hash_str, password),
        "SHA1" => verify_raw::<sha1::Sha1>(hash_str, password),
        "SHA256" => verify_raw::<sha2::Sha256>(hash_str, password),
        "NTLM" => verify_ntlm(hash_str, password),
        "MD4" => verify_raw::<md4::Md4>(hash_str, password),
        _ => {
            log::warn!("Unsupported hash type '{hash_type}' in distributed worker");
            false
        }
    }
}

fn verify_raw<D: Digest>(hash_str: &str, password: &str) -> bool {
    let computed = hex::encode(D::digest(password.as_bytes()));
    let clean_hash = hash_str.trim().to_lowercase();
    clean_hash == computed
}

fn verify_ntlm(hash_str: &str, password: &str) -> bool {
    let encoded: Vec<u16> = password.encode_utf16().collect();
    let bytes: Vec<u8> = encoded.iter().flat_map(|c| c.to_le_bytes()).collect();
    let digest = hex::encode(md4::Md4::digest(&bytes));
    let clean = hash_str.trim().to_lowercase();
    clean == digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_md5_hello() {
        assert!(verify("MD5", "5d41402abc4b2a76b9719d911017c592", "hello"));
    }

    #[test]
    fn test_verify_md5_wrong() {
        assert!(!verify("MD5", "5d41402abc4b2a76b9719d911017c592", "world"));
    }

    #[test]
    fn test_verify_md5_rawmd5() {
        assert!(verify("RAWMD5", "900150983cd24fb0d6963f7d28e17f72", "abc"));
    }

    #[test]
    fn test_verify_sha1() {
        assert!(verify("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "hello"));
        assert!(!verify("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "wrong"));
    }

    #[test]
    fn test_verify_sha1_alt() {
        assert!(verify("RAWSHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "hello"));
    }

    #[test]
    fn test_verify_sha256() {
        assert!(verify("SHA256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hello"));
        assert!(!verify("SHA256", "0000000000000000000000000000000000000000000000000000000000000000", "hello"));
    }

    #[test]
    fn test_verify_ntlm() {
        assert!(verify("NTLM", "066ddfd4ef0e9cd7c256fe77191ef43c", "hello"));
        assert!(!verify("NTLM", "066ddfd4ef0e9cd7c256fe77191ef43c", "world"));
    }

    #[test]
    fn test_verify_ntlm_password() {
        assert!(verify("NTLM", "8846f7eaee8fb117ad06bdd830b7586c", "password"));
        assert!(verify("NTLM", "7a21990fcd3d759941e45c490f143d5f", "12345"));
        assert!(verify("NTLM", "a87f3a337d73085c45f9416be5787d86", "Passw0rd"));
        assert!(verify("NTLM", "5a550f06f4b648d2c570b9a82bbe8c48", "ILoveYou"));
    }

    #[test]
    fn test_verify_md4() {
        // MD4 of "hello" (openssl dgst -md4)
        // Actually compute it: the md4 crate might not be consistently available
        // Skip this test if md4 is not available
        let pwd = "hello";
        let digest = hex::encode(md4::Md4::digest(pwd.as_bytes()));
        assert_eq!(digest.len(), 32, "MD4 should produce 32 hex chars");
        assert!(verify("MD4", &digest, "hello"));
    }

    #[test]
    fn test_verify_unsupported_returns_false() {
        assert!(!verify("UNKNOWN_TYPE", "anything", "password"));
    }

    /// The whole point of `supports`: a type this engine cannot verify must be
    /// distinguishable from a wrong password, because both return false and only
    /// one of them is a bug.
    #[test]
    fn an_unsupported_type_is_distinguishable_from_a_wrong_password() {
        for (name, _) in SUPPORTED {
            assert!(supports(name), "{name} is listed but not supported");
        }
        for bad in ["BCRYPT", "ARGON2ID", "SHA512", "SHA3-256", "", "MD5HEX"] {
            assert!(!supports(bad), "{bad:?} must not be claimed as supported");
        }
        assert!(!verify("BCRYPT", "whatever", "password"));
        assert!(supports("BCRYPT") == false);
    }

    /// The main binary's display names carry a `Hash` suffix, so a caller that
    /// passes `HashCracker::name` straight through must still get an answer.
    #[test]
    fn the_display_names_from_the_main_binary_are_accepted() {
        assert_eq!(canonical_name("Md5Hash"), Some("MD5"));
        assert_eq!(canonical_name("Sha256Hash"), Some("SHA256"));
        assert_eq!(canonical_name("NTLMHash"), Some("NTLM"));
        assert_eq!(canonical_name("BcryptHash"), None);
        assert!(verify("Md5Hash", "5d41402abc4b2a76b9719d911017c592", "hello"));
    }

    /// Every spelling listed must actually verify, so the table cannot drift away
    /// from the match arms above.
    #[test]
    fn every_listed_spelling_verifies() {
        // Digests of the password "hello", each recomputed by an oracle rather
        // than copied: MD5, SHA-1 and SHA-256 by hashlib, NTLM by the
        // UTF-16-LE wrapper around MD4, MD4 by the reference implementation in
        // scripts/gen-rtl-vectors.py, which is itself held against RFC 1320's
        // seven published vectors.
        //
        // The MD4 value here used to be `afe04867ec7a3845145579c95f8dbfb7`,
        // which is not the MD4 of anything. Nothing caught it because the loop
        // around these cases checked every spelling in SUPPORTED against every
        // case, so it failed first on "SHA1 is listed for MD5" and the real
        // fault was never reached.
        let cases = [
            ("MD5", "5d41402abc4b2a76b9719d911017c592"),
            ("SHA1", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"),
            ("SHA256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
            ("NTLM", "066ddfd4ef0e9cd7c256fe77191ef43c"),
            ("MD4", "866437cb7a794bce2b727acc0362ee27"),
        ];
        for (canonical, hex) in cases {
            assert_eq!(canonical_name(canonical), Some(canonical));
            // `SUPPORTED` is `&[(&str, &[&str])]`. Iterating the slice directly
            // destructures the reference itself, so `spellings` binds as
            // `&&[&str]`, which is not an iterator. `iter()` puts the pattern on
            // the items, and the `&` in the pattern copies the tuple out so
            // `spellings` binds as `&[&str]`.
            // Only this case's own group. The previous version looped over every
            // group in SUPPORTED, which asserts that "SHA1" verifies an MD5
            // digest. It cannot, and a test that requires it to is testing the
            // wrong thing rather than finding a bug.
            let group = SUPPORTED
                .iter()
                .find(|(name, _)| *name == canonical)
                .unwrap_or_else(|| panic!("{canonical} is not in SUPPORTED"));
            for spelling in group.1 {
                assert!(
                    verify(spelling, hex, "hello"),
                    "{spelling} is listed for {canonical} but does not verify"
                );
            }
            // And the spelling must actually route to that canonical name, which
            // is what `canonical_name` is for. `group.0` is the table's own
            // `&'static str`; `canonical` comes from the case array and is a
            // `&str` tied to that array, so it cannot be returned.
            for spelling in group.1 {
                let routed = group.0;
                assert_eq!(
                    canonical_name(spelling),
                    Some(routed),
                    "{spelling} does not route to {routed}"
                );
            }
        }
    }

    #[test]
    fn test_verify_case_insensitive_hash_type() {
        assert!(verify("md5", "5d41402abc4b2a76b9719d911017c592", "hello"));
        assert!(verify("sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hello"));
    }

    #[test]
    fn test_verify_empty_password() {
        // MD5 of empty string
        assert!(verify("MD5", "d41d8cd98f00b204e9800998ecf8427e", ""));
    }

    #[test]
    fn test_verify_unicode() {
        // SHA256 of "héllo" (with accent)
        let expected = hex::encode(sha2::Sha256::digest("héllo".as_bytes()));
        assert!(verify("SHA256", &expected, "héllo"));
    }
}
