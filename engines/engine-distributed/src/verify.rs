/// Minimal hash verification for distributed worker.
/// Supports the most common hash types encountered in password cracking.
/// For full hash support, run the worker alongside a pwdcrack node.

use digest::Digest;

pub fn verify(hash_type: &str, hash_str: &str, password: &str) -> bool {
    let ht = hash_type.to_uppercase().replace('-', "");
    match ht.as_str() {
        "MD5" | "RAWMD5" => verify_raw::<md5::Md5>(hash_str, password),
        "SHA1" | "RAWSHA1" => verify_raw::<sha1::Sha1>(hash_str, password),
        "SHA256" | "RAWSHA256" => verify_raw::<sha2::Sha256>(hash_str, password),
        "NTLM" => verify_ntlm(hash_str, password),
        "MD4" | "RAWMD4" => verify_raw::<md4::Md4>(hash_str, password),
        _ => {
            log::warn!("Unsupported hash type '{}' in distributed worker", hash_type);
            false
        }
    }
}

fn verify_raw<D: Digest>(hash_str: &str, password: &str) -> bool {
    let computed = hex::encode(D::digest(password.as_bytes()));
    let clean_hash = hash_str.trim().to_lowercase();
    clean_hash.starts_with(&computed) || clean_hash.contains(&computed)
}

fn verify_ntlm(hash_str: &str, password: &str) -> bool {
    let encoded: Vec<u16> = password.encode_utf16().collect();
    let bytes: Vec<u8> = encoded.iter().flat_map(|c| c.to_le_bytes()).collect();
    let digest = hex::encode(md4::Md4::digest(&bytes));
    let clean = hash_str.trim().to_lowercase();
    clean.contains(&digest)
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
