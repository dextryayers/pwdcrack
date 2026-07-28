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
