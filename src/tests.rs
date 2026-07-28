use crate::hash::detector::Detector;
use crate::hash::raw::Md5Hash;
use crate::hash::{HashEntry, HashCracker, HashType};
use crate::potfile::Potfile;

fn detect_type(hash_str: &str) -> HashType {
    Detector::new().detect(hash_str).map(|(c, _)| c.hash_type()).unwrap_or(HashType::Unknown)
}

#[test]
fn test_detector_md5() {
    assert_eq!(detect_type("5d41402abc4b2a76b9719d911017c592"), HashType::MD5);
    let (cracker, entry) = Detector::new().detect("5d41402abc4b2a76b9719d911017c592").unwrap();
    assert!(cracker.verify("hello", &entry));
    assert!(!cracker.verify("wrong", &entry));
}

#[test]
fn test_detector_sha1() {
    assert_eq!(detect_type("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"), HashType::SHA1);
    let (cracker, entry) = Detector::new().detect("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();
    assert!(cracker.verify("hello", &entry));
}

#[test]
fn test_detector_sha256() {
    let h = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    assert_eq!(detect_type(h), HashType::SHA256);
    let (cracker, entry) = Detector::new().detect(h).unwrap();
    assert!(cracker.verify("hello", &entry));
}

#[test]
fn test_detector_ntlm() {
    let (cracker, entry) = Detector::new().detect("$NT$066ddfd4ef0e9cd7c256fe77191ef43c").unwrap();
    assert_eq!(cracker.hash_type(), HashType::NTLM);
    assert!(cracker.verify("hello", &entry));
    assert!(!cracker.verify("wrong", &entry));
}

#[test]
fn test_detector_sha512() {
    let hash = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7\
                 2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
    assert_eq!(detect_type(hash), HashType::SHA512);
}

#[test]
fn test_detector_bcrypt() {
    // Generated with bcrypt crate v0.16, cost=4
    let h = "$2b$04$2WYyN.eiXbyOO340HLSZYOh7.Nag8klMznoYg9ishyhAaURBnrgPi";
    let (cracker, entry) = Detector::new().detect(h).unwrap();
    assert_eq!(cracker.hash_type(), HashType::BCrypt);
    assert!(cracker.verify("password", &entry));
    assert!(!cracker.verify("wrong", &entry));
}

#[test]
fn test_md5_hello() {
    let cracker = Md5Hash;
    let entry = HashEntry {
        raw: "5d41402abc4b2a76b9719d911017c592".to_string(),
        hash_type: crate::hash::HashType::MD5,
        hash_bytes: hex::decode("5d41402abc4b2a76b9719d911017c592").unwrap(),
        salt: None,
        username: None,
        cracked: false,
        password: None,
    };
    assert!(cracker.verify("hello", &entry));
    assert!(!cracker.verify("world", &entry));
}

#[test]
fn test_potfile_roundtrip() {
    let dir = std::env::temp_dir();
    let path = dir.join("pwdcrack_test_potfile");
    let _ = std::fs::remove_file(&path);

    {
        let pf = Potfile::new(path.to_str().unwrap());
        assert!(!pf.is_cracked("hash1"));
        pf.save("hash1", "password1");
        assert!(pf.is_cracked("hash1"));
        assert_eq!(pf.count(), 1);
    }

    // Re-load from disk
    {
        let pf = Potfile::new(path.to_str().unwrap());
        assert!(pf.is_cracked("hash1"));
        assert_eq!(pf.count(), 1);
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_detector_identify_file() {
    let d = Detector::new();
    let candidates = [
        "tests/test_vectors/md5.txt",
        "../tests/test_vectors/md5.txt",
        "engines/../tests/test_vectors/md5.txt",
    ];
    for p in &candidates {
        if std::path::Path::new(p).exists() {
            let results = d.identify(p);
            assert!(!results.is_empty(), "No hash entries found in {}", p);
            return;
        }
    }
    eprintln!("test_vectors directory not found, skipping test");
}

#[test]
fn test_hash_entry_serde() {
    let entry = HashEntry {
        raw: "5d41402abc4b2a76b9719d911017c592".to_string(),
        hash_type: crate::hash::HashType::MD5,
        hash_bytes: vec![0x5d, 0x41, 0x40, 0x2a],
        salt: None,
        username: Some("admin".to_string()),
        cracked: true,
        password: Some("hello".to_string()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: HashEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.raw, entry.raw);
    assert_eq!(deserialized.hash_type, entry.hash_type);
    assert_eq!(deserialized.username, entry.username);
    assert_eq!(deserialized.password, entry.password);
    assert!(deserialized.cracked);
}

// ── New hash type tests ──

fn make_entry(raw: &str, ht: HashType) -> HashEntry {
    HashEntry {
        raw: raw.to_string(),
        hash_type: ht,
        hash_bytes: hex::decode(raw).unwrap(),
        salt: None,
        username: None,
        cracked: false,
        password: None,
    }
}

/// Test that a specific cracker type correctly verifies a password.
/// Bypasses auto-detection (which is ambiguous for same-length raw hashes).
fn test_cracker_verify(ht: HashType, raw: &str, pw: &str) {
    let detector = Detector::new();
    let cracker = detector.cracker_for_type(ht).expect("cracker not found for hash type");
    let entry = make_entry(raw, ht);
    assert!(cracker.verify(pw, &entry), "{} should verify '{}'", ht.name(), pw);
    assert!(!cracker.verify("wrong-password", &entry), "{} should reject 'wrong-password'", ht.name());
}

// ── SHA3 family ──

#[test]
fn test_sha3_224_verify() {
    test_cracker_verify(HashType::SHA3224, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7", "");
}

#[test]
fn test_sha3_256_verify() {
    test_cracker_verify(HashType::SHA3256, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", "");
}

#[test]
fn test_sha3_384_verify() {
    test_cracker_verify(HashType::SHA3384, "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004", "");
}

// ── SHA-512/t variants ──

#[test]
fn test_sha512_224_verify() {
    test_cracker_verify(HashType::SHA512_224, "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4", "");
    test_cracker_verify(HashType::SHA512_224, "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c", "hello");
}

#[test]
fn test_sha512_256_verify() {
    test_cracker_verify(HashType::SHA512_256, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", "");
    test_cracker_verify(HashType::SHA512_256, "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a", "hello");
}

// ── BLAKE2 family ──

#[test]
fn test_blake2b_256_verify() {
    test_cracker_verify(HashType::BLAKE2B256, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", "");
    test_cracker_verify(HashType::BLAKE2B256, "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf", "hello");
}

#[test]
fn test_blake2s_256_verify() {
    test_cracker_verify(HashType::BLAKE2S256, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", "");
    test_cracker_verify(HashType::BLAKE2S256, "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25", "hello");
}

// ── RIPEMD family ──

#[test]
fn test_ripemd128_verify() {
    test_cracker_verify(HashType::RIPEMD128, "cdf26213a150dc3ecb610f18f6b38b46", "");
    test_cracker_verify(HashType::RIPEMD128, "789d569f08ed7055e94b4289a4195012", "hello");
}

#[test]
fn test_ripemd256_verify() {
    test_cracker_verify(HashType::RIPEMD256, "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d", "");
    test_cracker_verify(HashType::RIPEMD256, "cc1d2594aece0a064b7aed75a57283d9490fd5705ed3d66bf9adfe3a58b25de5", "hello");
}

#[test]
fn test_ripemd320_verify() {
    test_cracker_verify(HashType::RIPEMD320, "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8", "");
    test_cracker_verify(HashType::RIPEMD320, "eb0cf45114c56a8421fbcb33430fa22e0cd607560a88bbe14ce70bdf59bf55b11a3906987c487992", "hello");
}

// ── Detection tests for uniquely-identifiable lengths ──

#[test]
fn test_detect_ripemd320() {
    // RIPEMD-320 is 80 hex chars — unique length, no collision
    assert_eq!(detect_type("22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8"), HashType::RIPEMD320);
}
