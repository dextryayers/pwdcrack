use super::{HashCracker, HashEntry, HashType, HashParser};

macro_rules! impl_detection_only_hex {
    ($name:ident, $hash_type:expr, $hex_len:expr, $bits:expr) => {
        pub struct $name;
        impl HashCracker for $name {
            fn hash_type(&self) -> HashType { $hash_type }
            fn name(&self) -> &'static str { stringify!($name) }
            fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
            fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
        }
        impl HashParser for $name {
            fn parse(&self, line: &str) -> Option<HashEntry> {
                let t = line.trim();
                if t.len() != $hex_len || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
                Some(HashEntry { raw: t.to_lowercase(), hash_type: $hash_type,
                    hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
                    cracked: false, password: None })
            }
            fn can_parse(&self, line: &str) -> bool {
                let t = line.trim(); t.len() == $hex_len && t.chars().all(|c| c.is_ascii_hexdigit())
            }
        }
    };
}

// ── Standard Algorithms ──
impl_detection_only_hex!(Sm3Hash, HashType::SM3, 64, 256);
impl_detection_only_hex!(Has160Hash, HashType::HAS160, 40, 160);
impl_detection_only_hex!(Groestl224Hash, HashType::Groestl224, 56, 224);
impl_detection_only_hex!(Groestl256Hash, HashType::Groestl256, 64, 256);
impl_detection_only_hex!(Groestl384Hash, HashType::Groestl384, 96, 384);
impl_detection_only_hex!(Groestl512Hash, HashType::Groestl512, 128, 512);
impl_detection_only_hex!(Bmw224Hash, HashType::BMW224, 56, 224);
impl_detection_only_hex!(Bmw256Hash, HashType::BMW256, 64, 256);
impl_detection_only_hex!(Bmw384Hash, HashType::BMW384, 96, 384);
impl_detection_only_hex!(Bmw512Hash, HashType::BMW512, 128, 512);
impl_detection_only_hex!(Echo224Hash, HashType::Echo224, 56, 224);
impl_detection_only_hex!(Echo256Hash, HashType::Echo256, 64, 256);
impl_detection_only_hex!(Echo384Hash, HashType::Echo384, 96, 384);
impl_detection_only_hex!(Echo512Hash, HashType::Echo512, 128, 512);
impl_detection_only_hex!(Shavite3224Hash, HashType::Shavite2224, 56, 224);
impl_detection_only_hex!(Shavite3256Hash, HashType::Shavite2256, 64, 256);
impl_detection_only_hex!(Shavite3384Hash, HashType::Shavite2384, 96, 384);
impl_detection_only_hex!(Shavite3512Hash, HashType::Shavite2512, 128, 512);
impl_detection_only_hex!(Simd224Hash, HashType::SIMD224, 56, 224);
impl_detection_only_hex!(Simd256Hash, HashType::SIMD256, 64, 256);
impl_detection_only_hex!(Simd384Hash, HashType::SIMD384, 96, 384);
impl_detection_only_hex!(Simd512Hash, HashType::SIMD512, 128, 512);
impl_detection_only_hex!(Luffa224Hash, HashType::Luffa224, 56, 224);
impl_detection_only_hex!(Luffa256Hash, HashType::Luffa256, 64, 256);
impl_detection_only_hex!(Luffa384Hash, HashType::Luffa384, 96, 384);
impl_detection_only_hex!(Luffa512Hash, HashType::Luffa512, 128, 512);
impl_detection_only_hex!(CubeHash224Hash, HashType::CubeHash224, 56, 224);
impl_detection_only_hex!(CubeHash256Hash, HashType::CubeHash256, 64, 256);
impl_detection_only_hex!(CubeHash384Hash, HashType::CubeHash384, 96, 384);
impl_detection_only_hex!(CubeHash512Hash, HashType::CubeHash512, 128, 512);
impl_detection_only_hex!(Fugue224Hash, HashType::Fugue224, 56, 224);
impl_detection_only_hex!(Fugue256Hash, HashType::Fugue256, 64, 256);
impl_detection_only_hex!(Fugue384Hash, HashType::Fugue384, 96, 384);
impl_detection_only_hex!(Fugue512Hash, HashType::Fugue512, 128, 512);
impl_detection_only_hex!(Hamsi224Hash, HashType::Hamsi224, 56, 224);
impl_detection_only_hex!(Hamsi256Hash, HashType::Hamsi256, 64, 256);
impl_detection_only_hex!(Hamsi384Hash, HashType::Hamsi384, 96, 384);
impl_detection_only_hex!(Hamsi512Hash, HashType::Hamsi512, 128, 512);
impl_detection_only_hex!(Panama128Hash, HashType::Panama128, 32, 128);
impl_detection_only_hex!(RadioGatun32Hash, HashType::RadioGatun32, 8, 32);
impl_detection_only_hex!(RadioGatun64Hash, HashType::RadioGatun64, 16, 64);
impl_detection_only_hex!(Haval128Hash, HashType::Haval128, 32, 128);
impl_detection_only_hex!(Haval160Hash, HashType::Haval160, 40, 160);
impl_detection_only_hex!(Haval192Hash, HashType::Haval192, 48, 192);
impl_detection_only_hex!(Haval224Hash, HashType::Haval224, 56, 224);
impl_detection_only_hex!(Haval256Hash, HashType::Haval256, 64, 256);
impl_detection_only_hex!(Fsb160Hash, HashType::FSB160, 40, 160);
impl_detection_only_hex!(Fsb224Hash, HashType::FSB224, 56, 224);
impl_detection_only_hex!(Fsb256Hash, HashType::FSB256, 64, 256);
impl_detection_only_hex!(Fsb384Hash, HashType::FSB384, 96, 384);
impl_detection_only_hex!(Fsb512Hash, HashType::FSB512, 128, 512);
impl_detection_only_hex!(Ecoh128Hash, HashType::ECOH128, 32, 128);
impl_detection_only_hex!(Ecoh192Hash, HashType::ECOH192, 48, 192);
impl_detection_only_hex!(Ecoh256Hash, HashType::ECOH256, 64, 256);

// ── More CRC & Checksums ──
impl_detection_only_hex!(Crc10Hash, HashType::CRC10, 3, 10);
impl_detection_only_hex!(Crc11Hash, HashType::CRC11, 3, 11);
impl_detection_only_hex!(Crc12Hash, HashType::CRC12, 3, 12);
impl_detection_only_hex!(Crc13Hash, HashType::CRC13, 4, 13);
impl_detection_only_hex!(Crc14Hash, HashType::CRC14, 4, 14);
impl_detection_only_hex!(Crc15Hash, HashType::CRC15, 4, 15);
impl_detection_only_hex!(Crc17Hash, HashType::CRC17, 5, 17);
impl_detection_only_hex!(Crc21Hash, HashType::CRC21, 6, 21);
impl_detection_only_hex!(Crc24CHash, HashType::CRC24C, 6, 24);
impl_detection_only_hex!(Crc30Hash, HashType::CRC30, 8, 30);
impl_detection_only_hex!(Crc31Hash, HashType::CRC31, 8, 31);
impl_detection_only_hex!(Crc40Hash, HashType::CRC40, 10, 40);
impl_detection_only_hex!(Crc82Hash, HashType::CRC82, 21, 82);
impl_detection_only_hex!(CrcDnpHash, HashType::CRCDNP, 6, 24);
impl_detection_only_hex!(CrcJamHash, HashType::CRCJAM, 8, 32);
impl_detection_only_hex!(Fletcher4Hash, HashType::Fletcher4, 1, 4);
impl_detection_only_hex!(Fletcher8Hash, HashType::Fletcher8, 2, 8);
impl_detection_only_hex!(Fletcher16Hash, HashType::Fletcher16, 4, 16);
impl_detection_only_hex!(Fletcher32Hash, HashType::Fletcher32, 8, 32);
impl_detection_only_hex!(Xor8Hash, HashType::XOR8, 2, 8);
impl_detection_only_hex!(Sum8Hash, HashType::Sum8, 2, 8);
impl_detection_only_hex!(Sum16Hash, HashType::Sum16, 4, 16);
impl_detection_only_hex!(Sum24Hash, HashType::Sum24, 6, 24);
impl_detection_only_hex!(Sum32Hash, HashType::Sum32, 8, 32);
impl_detection_only_hex!(Sum64Hash, HashType::Sum64, 16, 64);

// ── Application / CMS / Framework ──

// Django MD5: MD5(password+salt) as hex: salt format
pub struct DjangoMd5Hash;
impl HashCracker for DjangoMd5Hash {
    fn hash_type(&self) -> HashType { HashType::DjangoMD5 }
    fn name(&self) -> &'static str { "Django MD5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DjangoMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split('$').collect();
        if parts.len() == 3 && parts[0] == "" {
            let hash = parts[2];
            if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::DjangoMD5,
                    hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
                    username: None, cracked: false, password: None });
            }
        }
        None
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split('$').collect();
        parts.len() == 3 && parts[0] == "" && parts[2].len() == 32 && parts[2].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Django SHA256: pbkdf2_sha256$iterations$salt$hash
pub struct DjangoSha256Hash;
impl HashCracker for DjangoSha256Hash {
    fn hash_type(&self) -> HashType { HashType::DjangoSHA256 }
    fn name(&self) -> &'static str { "Django SHA-256" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DjangoSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split('$').collect();
        if parts.len() == 4 && parts[0] == "" {
            let hash = parts[3];
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::DjangoSHA256,
                    hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[2].to_string()),
                    username: None, cracked: false, password: None });
            }
        }
        None
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split('$').collect();
        parts.len() == 4 && parts[0] == "" && parts[3].len() == 64 && parts[3].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Django PBKDF2: pbkdf2_sha256$iterations$salt$hash (base64 encoded)
pub struct DjangoPbkdf2Hash;
impl HashCracker for DjangoPbkdf2Hash {
    fn hash_type(&self) -> HashType { HashType::DjangoPBKDF2 }
    fn name(&self) -> &'static str { "Django PBKDF2" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DjangoPbkdf2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("pbkdf2_sha256$") || s.starts_with("pbkdf2_sha1$") || s.starts_with("pbkdf2_sha512$") {
            let parts: Vec<&str> = s.split('$').collect();
            if parts.len() == 4 {
                return Some(HashEntry { raw: parts[3].to_string(), hash_type: HashType::DjangoPBKDF2,
                    hash_bytes: parts[3].as_bytes().to_vec(), salt: Some(parts[2].to_string()),
                    username: None, cracked: false, password: None });
            }
        }
        None
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("pbkdf2_sha256$") || s.starts_with("pbkdf2_sha1$") || s.starts_with("pbkdf2_sha512$")) && s.split('$').count() == 4
    }
}

// Joomla MD5: <32hex>:<salt>
pub struct JoomlaMd5Hash;
impl HashCracker for JoomlaMd5Hash {
    fn hash_type(&self) -> HashType { HashType::JoomlaMD5 }
    fn name(&self) -> &'static str { "Joomla MD5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for JoomlaMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::JoomlaMD5,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Joomla SHA256: <64hex>:<salt>
pub struct JoomlaSha256Hash;
impl HashCracker for JoomlaSha256Hash {
    fn hash_type(&self) -> HashType { HashType::JoomlaSHA256 }
    fn name(&self) -> &'static str { "Joomla SHA-256" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for JoomlaSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::JoomlaSHA256,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Drupal 8: $S$...
pub struct Drupal8Hash;
impl HashCracker for Drupal8Hash {
    fn hash_type(&self) -> HashType { HashType::Drupal8 }
    fn name(&self) -> &'static str { "Drupal 8" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Drupal8Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("$S$") && s.len() >= 55 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Drupal8,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$S$")
    }
}

// XenForo: <hash>:<salt>
pub struct XenForoHash;
impl HashCracker for XenForoHash {
    fn hash_type(&self) -> HashType { HashType::XenForo }
    fn name(&self) -> &'static str { "XenForo" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for XenForoHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::XenForo,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Woltlab: <hash>:<salt>
pub struct WoltlabHash;
impl HashCracker for WoltlabHash {
    fn hash_type(&self) -> HashType { HashType::Woltlab }
    fn name(&self) -> &'static str { "Woltlab" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for WoltlabHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Woltlab,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MyBB: <hash>:<salt>
pub struct MyBbHash;
impl HashCracker for MyBbHash {
    fn hash_type(&self) -> HashType { HashType::MyBBHash }
    fn name(&self) -> &'static str { "MyBB 1.x" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MyBbHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::MyBBHash,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Vanilla: <hash>:<salt>
pub struct VanillaHash;
impl HashCracker for VanillaHash {
    fn hash_type(&self) -> HashType { HashType::Vanilla }
    fn name(&self) -> &'static str { "Vanilla" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for VanillaHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() >= 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Vanilla,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1..].join(":")),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// FluxBB: <hash>:<salt>
pub struct FluxBbHash;
impl HashCracker for FluxBbHash {
    fn hash_type(&self) -> HashType { HashType::FluxBB }
    fn name(&self) -> &'static str { "FluxBB" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for FluxBbHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::FluxBB,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// CakePHP: <hash>:<salt>
pub struct CakePhpHash;
impl HashCracker for CakePhpHash {
    fn hash_type(&self) -> HashType { HashType::CakePHP }
    fn name(&self) -> &'static str { "CakePHP" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for CakePhpHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::CakePHP,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// CodeIgniter: <hash>:<salt>
pub struct CodeIgniterHash;
impl HashCracker for CodeIgniterHash {
    fn hash_type(&self) -> HashType { HashType::CodeIgniter }
    fn name(&self) -> &'static str { "CodeIgniter" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for CodeIgniterHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::CodeIgniter,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Laravel bcrypt: $2y$...
pub struct LaravelBcryptHash;
impl HashCracker for LaravelBcryptHash {
    fn hash_type(&self) -> HashType { HashType::LaravelBCrypt }
    fn name(&self) -> &'static str { "Laravel bcrypt" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for LaravelBcryptHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if (s.starts_with("$2y$") || s.starts_with("$2b$")) && s.len() == 60 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::LaravelBCrypt,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("$2y$") || s.starts_with("$2b$")) && s.len() == 60
    }
}

// Magento: <hash>:<salt>
pub struct MagentoHash;
impl HashCracker for MagentoHash {
    fn hash_type(&self) -> HashType { HashType::Magento }
    fn name(&self) -> &'static str { "Magento" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MagentoHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Magento,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MODX: <hash>:<salt>
pub struct ModxHash;
impl HashCracker for ModxHash {
    fn hash_type(&self) -> HashType { HashType::MODX }
    fn name(&self) -> &'static str { "MODX" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ModxHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::MODX,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Moodle: <hash>:<salt>
pub struct MoodleHash;
impl HashCracker for MoodleHash {
    fn hash_type(&self) -> HashType { HashType::Moodle }
    fn name(&self) -> &'static str { "Moodle" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MoodleHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Moodle,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// PrestaShop: <hash>:<salt>
pub struct PrestaShopHash;
impl HashCracker for PrestaShopHash {
    fn hash_type(&self) -> HashType { HashType::PrestaShop }
    fn name(&self) -> &'static str { "PrestaShop" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PrestaShopHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::PrestaShop,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// TYPO3: <hash>:<salt>
pub struct Typo3Hash;
impl HashCracker for Typo3Hash {
    fn hash_type(&self) -> HashType { HashType::TYPO3 }
    fn name(&self) -> &'static str { "TYPO3" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Typo3Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::TYPO3,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Umbraco: <hash>:<salt>
pub struct UmbracoHash;
impl HashCracker for UmbracoHash {
    fn hash_type(&self) -> HashType { HashType::Umbraco }
    fn name(&self) -> &'static str { "Umbraco" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for UmbracoHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Umbraco,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// WHMCS: <hash>:<salt>
pub struct WhmcsHash;
impl HashCracker for WhmcsHash {
    fn hash_type(&self) -> HashType { HashType::WHMCS }
    fn name(&self) -> &'static str { "WHMCS" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for WhmcsHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::WHMCS,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Zikula: <hash>:<salt>
pub struct ZikulaHash;
impl HashCracker for ZikulaHash {
    fn hash_type(&self) -> HashType { HashType::Zikula }
    fn name(&self) -> &'static str { "Zikula" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ZikulaHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Zikula,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Elgg: <hash>:<salt>
pub struct ElggHash;
impl HashCracker for ElggHash {
    fn hash_type(&self) -> HashType { HashType::Elgg }
    fn name(&self) -> &'static str { "Elgg" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ElggHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::Elgg,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// WordPress PHPass: $P$ / $H$
pub struct WordPressPhpassHash;
impl HashCracker for WordPressPhpassHash {
    fn hash_type(&self) -> HashType { HashType::WordPressPHPass }
    fn name(&self) -> &'static str { "WordPress PHPass" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for WordPressPhpassHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if (s.starts_with("$P$") || s.starts_with("$H$")) && s.len() == 34 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::WordPressPHPass,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("$P$") || s.starts_with("$H$")) && s.len() == 34
    }
}

// PHP Hash: various php hash formats
pub struct PhpHashHash;
impl HashCracker for PhpHashHash {
    fn hash_type(&self) -> HashType { HashType::PHPHash }
    fn name(&self) -> &'static str { "PHP Hash" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PhpHashHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::PHPHash,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else if parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::PHPHash,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && ((parts[0].len() == 32 || parts[0].len() == 40) && parts[0].chars().all(|c| c.is_ascii_hexdigit()))
    }
}

// ── Enterprise & Database ──
impl_detection_only_hex!(Oracle8Hash, HashType::Oracle8, 16, 64);
impl_detection_only_hex!(Oracle9Hash, HashType::Oracle9, 16, 64);

// Oracle 12c: T_HASH
pub struct Oracle12cHash;
impl HashCracker for Oracle12cHash {
    fn hash_type(&self) -> HashType { HashType::Oracle12c }
    fn name(&self) -> &'static str { "Oracle 12c" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Oracle12cHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("T_HASH") {
            let hash = &s[6..];
            if hash.len() >= 128 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::Oracle12c,
                    hash_bytes: hex::decode(hash).ok()?, salt: None, username: None,
                    cracked: false, password: None });
            }
        }
        None
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("T_HASH") && s.len() > 6
    }
}

// IBM DB2: <hash>:<salt>
pub struct IbmdB2Hash;
impl HashCracker for IbmdB2Hash {
    fn hash_type(&self) -> HashType { HashType::IBMDB2 }
    fn name(&self) -> &'static str { "IBM DB2" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for IbmdB2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::IBMDB2,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Progress: <hash>
pub struct ProgressHash;
impl HashCracker for ProgressHash {
    fn hash_type(&self) -> HashType { HashType::Progress }
    fn name(&self) -> &'static str { "Progress" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ProgressHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Progress,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Sybase: <hash>
pub struct SybaseHash;
impl HashCracker for SybaseHash {
    fn hash_type(&self) -> HashType { HashType::Sybase }
    fn name(&self) -> &'static str { "Sybase" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for SybaseHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Sybase,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Teradata: <hash>
pub struct TeradataHash;
impl HashCracker for TeradataHash {
    fn hash_type(&self) -> HashType { HashType::Teradata }
    fn name(&self) -> &'static str { "Teradata" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for TeradataHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Teradata,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MSSQL 2000: <hash>
pub struct Mssql2000Hash;
impl HashCracker for Mssql2000Hash {
    fn hash_type(&self) -> HashType { HashType::MSSQL2000 }
    fn name(&self) -> &'static str { "MSSQL 2000" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Mssql2000Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 44 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::MSSQL2000,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 44 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MSSQL 2008: <hash>
pub struct Mssql2008Hash;
impl HashCracker for Mssql2008Hash {
    fn hash_type(&self) -> HashType { HashType::MSSQL2008 }
    fn name(&self) -> &'static str { "MSSQL 2008" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Mssql2008Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::MSSQL2008,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MSSQL 2017: <hash>
pub struct Mssql2017Hash;
impl HashCracker for Mssql2017Hash {
    fn hash_type(&self) -> HashType { HashType::MSSQL2017 }
    fn name(&self) -> &'static str { "MSSQL 2017" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Mssql2017Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::MSSQL2017,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MySQL 5: SHA1 + hex
pub struct MySQL5Hash;
impl HashCracker for MySQL5Hash {
    fn hash_type(&self) -> HashType { HashType::MySQL5 }
    fn name(&self) -> &'static str { "MySQL 5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MySQL5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with('*') && s.len() == 41 && s[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::MySQL5,
                hash_bytes: hex::decode(&s[1..]).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('*') && s.len() == 41 && s[1..].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// MySQL 8: SHA256 format
pub struct MySQL8Hash;
impl HashCracker for MySQL8Hash {
    fn hash_type(&self) -> HashType { HashType::MySQL8 }
    fn name(&self) -> &'static str { "MySQL 8" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MySQL8Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("$A$") || (s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::MySQL8,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("$A$") || (s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
    }
}

// PostgreSQL SCRAM: SCRAM-SHA-256$...
pub struct PostgresqlScramHash;
impl HashCracker for PostgresqlScramHash {
    fn hash_type(&self) -> HashType { HashType::PostgreSQLSCRAM }
    fn name(&self) -> &'static str { "PostgreSQL SCRAM" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PostgresqlScramHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("SCRAM-SHA-256$") {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::PostgreSQLSCRAM,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("SCRAM-SHA-256$")
    }
}

// MongoDB: MongoDB hashes
pub struct MongoDbHash;
impl HashCracker for MongoDbHash {
    fn hash_type(&self) -> HashType { HashType::MongoDB }
    fn name(&self) -> &'static str { "MongoDB" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MongoDbHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::MongoDB,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Redis: Redis hashes
pub struct RedisHash;
impl HashCracker for RedisHash {
    fn hash_type(&self) -> HashType { HashType::Redis }
    fn name(&self) -> &'static str { "Redis" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for RedisHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Redis,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// RavenDB: <hash>
pub struct RavenDbHash;
impl HashCracker for RavenDbHash {
    fn hash_type(&self) -> HashType { HashType::RavenDB }
    fn name(&self) -> &'static str { "RavenDB" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for RavenDbHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::RavenDB,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// CouchDB: <hash>
pub struct CouchDbHash;
impl HashCracker for CouchDbHash {
    fn hash_type(&self) -> HashType { HashType::CouchDB }
    fn name(&self) -> &'static str { "CouchDB" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for CouchDbHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::CouchDB,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Cisco Type 7: 07...
pub struct CiscoType7Hash;
impl HashCracker for CiscoType7Hash {
    fn hash_type(&self) -> HashType { HashType::CiscoType7 }
    fn name(&self) -> &'static str { "Cisco Type 7" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for CiscoType7Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() >= 4 && s.len() <= 52 && s.chars().all(|c| c.is_ascii_digit() || (c.is_ascii_hexdigit() && c.is_ascii_uppercase())) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::CiscoType7,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() >= 4 && s.len() <= 52
    }
}

// Juniper: $9$
pub struct JuniperHash;
impl HashCracker for JuniperHash {
    fn hash_type(&self) -> HashType { HashType::Juniper }
    fn name(&self) -> &'static str { "Juniper" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for JuniperHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("$9$") {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Juniper,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$9$")
    }
}

// Huawei: <hash>
pub struct HuaweiHash;
impl HashCracker for HuaweiHash {
    fn hash_type(&self) -> HashType { HashType::Huawei }
    fn name(&self) -> &'static str { "Huawei" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for HuaweiHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Huawei,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Nokia: <hash>
pub struct NokiaHash;
impl HashCracker for NokiaHash {
    fn hash_type(&self) -> HashType { HashType::Nokia }
    fn name(&self) -> &'static str { "Nokia" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for NokiaHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Nokia,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Alcatel: <hash>
pub struct AlcatelHash;
impl HashCracker for AlcatelHash {
    fn hash_type(&self) -> HashType { HashType::Alcatel }
    fn name(&self) -> &'static str { "Alcatel" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for AlcatelHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Alcatel,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ZTE: <hash>
pub struct ZteHash;
impl HashCracker for ZteHash {
    fn hash_type(&self) -> HashType { HashType::ZTE }
    fn name(&self) -> &'static str { "ZTE" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ZteHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::ZTE,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Ericsson: <hash>
pub struct EricssonHash;
impl HashCracker for EricssonHash {
    fn hash_type(&self) -> HashType { HashType::Ericsson }
    fn name(&self) -> &'static str { "Ericsson" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for EricssonHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Ericsson,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// SNMP: community string
pub struct SnmpHash;
impl HashCracker for SnmpHash {
    fn hash_type(&self) -> HashType { HashType::SNMP }
    fn name(&self) -> &'static str { "SNMP" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for SnmpHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() >= 4 && s.len() <= 32 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::SNMP,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() >= 4 && s.len() <= 32
    }
}

// RADIUS CHAP: <user>:<challenge>:<response>
pub struct RadiusChapHash;
impl HashCracker for RadiusChapHash {
    fn hash_type(&self) -> HashType { HashType::RADIUSCHAP }
    fn name(&self) -> &'static str { "RADIUS CHAP" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for RadiusChapHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() >= 3 && parts[0].len() >= 1 && parts[2].len() == 32 && parts[2].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[2].to_lowercase(), hash_type: HashType::RADIUSCHAP,
                hash_bytes: hex::decode(parts[2]).ok()?, salt: Some(parts[1].to_string()),
                username: Some(parts[0].to_string()), cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 3 && parts[2].len() == 32 && parts[2].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Kerberos 5: $krb5$
pub struct Kerberos5Hash;
impl HashCracker for Kerberos5Hash {
    fn hash_type(&self) -> HashType { HashType::Kerberos5 }
    fn name(&self) -> &'static str { "Kerberos 5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Kerberos5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("$krb5$") || s.starts_with("$krb5a$") {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Kerberos5,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("$krb5$") || s.starts_with("$krb5a$")
    }
}

// AFS: <hash>
pub struct AfsHash;
impl HashCracker for AfsHash {
    fn hash_type(&self) -> HashType { HashType::AFS }
    fn name(&self) -> &'static str { "AFS" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for AfsHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::AFS,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// DPAPI: <hash>
pub struct DpapiHash;
impl HashCracker for DpapiHash {
    fn hash_type(&self) -> HashType { HashType::DPAPI }
    fn name(&self) -> &'static str { "DPAPI" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DpapiHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        Some(HashEntry { raw: s.to_string(), hash_type: HashType::DPAPI,
            hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { false }
}

// BitLocker: <hash>
pub struct BitLockerHash;
impl HashCracker for BitLockerHash {
    fn hash_type(&self) -> HashType { HashType::BitLocker }
    fn name(&self) -> &'static str { "BitLocker" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for BitLockerHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// TrueCrypt: <hash>
pub struct TrueCryptHash;
impl HashCracker for TrueCryptHash {
    fn hash_type(&self) -> HashType { HashType::TrueCrypt }
    fn name(&self) -> &'static str { "TrueCrypt" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for TrueCryptHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// FileVault: <hash>
pub struct FileVaultHash;
impl HashCracker for FileVaultHash {
    fn hash_type(&self) -> HashType { HashType::FileVault }
    fn name(&self) -> &'static str { "FileVault" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for FileVaultHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// LUKS: <hash>
pub struct LuksHash;
impl HashCracker for LuksHash {
    fn hash_type(&self) -> HashType { HashType::LUKS }
    fn name(&self) -> &'static str { "LUKS" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for LuksHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// VeraCrypt: <hash>
pub struct VeraCryptHash;
impl HashCracker for VeraCryptHash {
    fn hash_type(&self) -> HashType { HashType::VeraCrypt }
    fn name(&self) -> &'static str { "VeraCrypt" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for VeraCryptHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// Windows Hello: <hash>
pub struct WindowsHelloHash;
impl HashCracker for WindowsHelloHash {
    fn hash_type(&self) -> HashType { HashType::WindowsHello }
    fn name(&self) -> &'static str { "Windows Hello" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for WindowsHelloHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// ── Blockchain & Crypto ──
impl_detection_only_hex!(X11Hash, HashType::X11, 64, 256);
impl_detection_only_hex!(X13Hash, HashType::X13, 64, 256);
impl_detection_only_hex!(X15Hash, HashType::X15, 64, 256);
impl_detection_only_hex!(X17Hash, HashType::X17, 64, 256);
impl_detection_only_hex!(QuarkHash, HashType::Quark, 64, 256);
impl_detection_only_hex!(NeoscryptHash, HashType::Neoscrypt, 64, 256);
impl_detection_only_hex!(Lyra2ReHash, HashType::Lyra2RE, 64, 256);
impl_detection_only_hex!(YescryptHash, HashType::Yescrypt, 64, 256);
impl_detection_only_hex!(ScryptNHash, HashType::ScryptN, 64, 256);
impl_detection_only_hex!(ScryptJHash, HashType::ScryptJ, 64, 256);
impl_detection_only_hex!(BitcoinHash, HashType::Bitcoin, 64, 256);
impl_detection_only_hex!(EthereumHash, HashType::Ethereum, 40, 160);
impl_detection_only_hex!(LitecoinHash, HashType::Litecoin, 64, 256);

// Dogecoin
pub struct DogecoinHash;
impl HashCracker for DogecoinHash {
    fn hash_type(&self) -> HashType { HashType::Dogecoin }
    fn name(&self) -> &'static str { "Dogecoin" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DogecoinHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Dogecoin,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Ripple
pub struct RippleHash;
impl HashCracker for RippleHash {
    fn hash_type(&self) -> HashType { HashType::Ripple }
    fn name(&self) -> &'static str { "Ripple" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for RippleHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Ripple,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Monero
pub struct MoneroHash;
impl HashCracker for MoneroHash {
    fn hash_type(&self) -> HashType { HashType::Monero }
    fn name(&self) -> &'static str { "Monero" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MoneroHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Monero,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Dash
pub struct DashHash;
impl HashCracker for DashHash {
    fn hash_type(&self) -> HashType { HashType::Dash }
    fn name(&self) -> &'static str { "Dash" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DashHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Dash,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Zcash
pub struct ZcashHash;
impl HashCracker for ZcashHash {
    fn hash_type(&self) -> HashType { HashType::Zcash }
    fn name(&self) -> &'static str { "Zcash" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for ZcashHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Zcash,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Namecoin
pub struct NamecoinHash;
impl HashCracker for NamecoinHash {
    fn hash_type(&self) -> HashType { HashType::Namecoin }
    fn name(&self) -> &'static str { "Namecoin" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for NamecoinHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Namecoin,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// Peercoin
pub struct PeercoinHash;
impl HashCracker for PeercoinHash {
    fn hash_type(&self) -> HashType { HashType::Peercoin }
    fn name(&self) -> &'static str { "Peercoin" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PeercoinHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::Peercoin,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Legacy & Unix ──

// DES Crypt: DES-standard crypt
pub struct DesCryptHash;
impl HashCracker for DesCryptHash {
    fn hash_type(&self) -> HashType { HashType::DESCrypt }
    fn name(&self) -> &'static str { "DES Crypt" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DesCryptHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 13 && s.starts_with('_') {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::DESCrypt,
                hash_bytes: s.as_bytes().to_vec(), salt: Some(s[1..9].to_string()),
                username: None, cracked: false, password: None })
        } else if s.len() == 13 && !s.contains('$') {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::DESCrypt,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 13 && !s.contains('$')
    }
}

// BSD Auth: BSDi-style
pub struct BsdAuthHash;
impl HashCracker for BsdAuthHash {
    fn hash_type(&self) -> HashType { HashType::BSDAuth }
    fn name(&self) -> &'static str { "BSD Auth" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for BsdAuthHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("_") && s.len() >= 20 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::BSDAuth,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("_") && s.len() >= 20
    }
}

// MD5 Crypt APR: $apr1$
pub struct Md5CryptAprHash;
impl HashCracker for Md5CryptAprHash {
    fn hash_type(&self) -> HashType { HashType::MD5CryptAPR }
    fn name(&self) -> &'static str { "MD5 Crypt APR" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Md5CryptAprHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("$apr1$") {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::MD5CryptAPR,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$apr1$")
    }
}

// Blowfish OpenBSD: $2a$ / $2b$ / $2y$
pub struct BlowfishOpenbsdHash;
impl HashCracker for BlowfishOpenbsdHash {
    fn hash_type(&self) -> HashType { HashType::BlowfishOpenBSD }
    fn name(&self) -> &'static str { "Blowfish OpenBSD" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for BlowfishOpenbsdHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if (s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$")) && s.len() == 60 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::BlowfishOpenBSD,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$")) && s.len() == 60
    }
}

// Linux Overflow: overflow hash format
pub struct LinuxOverflowHash;
impl HashCracker for LinuxOverflowHash {
    fn hash_type(&self) -> HashType { HashType::LinuxOverflow }
    fn name(&self) -> &'static str { "Linux Overflow" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for LinuxOverflowHash {
    fn parse(&self, _: &str) -> Option<HashEntry> { None }
    fn can_parse(&self, _: &str) -> bool { false }
}

// Unix Old: old DES-based crypt
pub struct UnixOldHash;
impl HashCracker for UnixOldHash {
    fn hash_type(&self) -> HashType { HashType::UnixOld }
    fn name(&self) -> &'static str { "Unix Old" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for UnixOldHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 13 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '/') {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::UnixOld,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 13 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '/')
    }
}

// DES BSDi
pub struct DesBsdiHash;
impl HashCracker for DesBsdiHash {
    fn hash_type(&self) -> HashType { HashType::DESBSDi }
    fn name(&self) -> &'static str { "DES BSDi" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for DesBsdiHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("_") && s.len() >= 20 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::DESBSDi,
                hash_bytes: s.as_bytes().to_vec(), salt: Some(s[1..5].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("_") && s.len() >= 20
    }
}

// HP Managed
pub struct HpManagedHash;
impl HashCracker for HpManagedHash {
    fn hash_type(&self) -> HashType { HashType::HPManaged }
    fn name(&self) -> &'static str { "HP Managed" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for HpManagedHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::HPManaged,
                hash_bytes: hex::decode(s).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// SNEFRU-128 Legacy
pub struct Snefru128LegacyHash;
impl HashCracker for Snefru128LegacyHash {
    fn hash_type(&self) -> HashType { HashType::SNEFRU128Legacy }
    fn name(&self) -> &'static str { "SNEFRU-128 Legacy" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Snefru128LegacyHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::SNEFRU128Legacy,
                hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── New Hash Types (25 variants) ──

impl_detection_only_hex!(HmacSha256_128Hash, HashType::HMACSHA256_128, 32, 128);
impl_detection_only_hex!(HmacSha1_96Hash, HashType::HMACSHA1_96, 24, 96);
impl_detection_only_hex!(MySqlOld1Hash, HashType::MySQLOld1, 16, 64);
impl_detection_only_hex!(FreeRadiusMd5Hash, HashType::FreeRADIUSMD5, 32, 128);
impl_detection_only_hex!(OpenVpnMd5Hash, HashType::OpenVPNMD5, 32, 128);
impl_detection_only_hex!(DigestMd5Hash, HashType::DigestMD5, 32, 128);
impl_detection_only_hex!(Aws4HmacSha256Hash, HashType::AWS4HMACSHA256, 64, 256);
impl_detection_only_hex!(IScsiChapHash, HashType::iSCSI_CHAP, 32, 128);
impl_detection_only_hex!(PythonMd5Hash, HashType::PythonMD5, 32, 128);
impl_detection_only_hex!(RabbitMqMd5Hash, HashType::RabbitMQMD5, 32, 128);
impl_detection_only_hex!(RedisMd5Hash, HashType::RedisMD5, 32, 128);
impl_detection_only_hex!(WpaPbkdf2Hash, HashType::WPAPBKDF2, 64, 256);
impl_detection_only_hex!(Wpa3SaeHash, HashType::WPA3SAE, 64, 256);

pub struct GpgHash;
impl HashCracker for GpgHash {
    fn hash_type(&self) -> HashType { HashType::GPG }
    fn name(&self) -> &'static str { "GPG" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for GpgHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        Some(HashEntry { raw: line.trim().to_string(), hash_type: HashType::GPG,
            hash_bytes: vec![], salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("-----BEGIN PGP")
    }
}

pub struct PgpS2kHash;
impl HashCracker for PgpS2kHash {
    fn hash_type(&self) -> HashType { HashType::PGPS2K }
    fn name(&self) -> &'static str { "PGP S2K" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PgpS2kHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() == 2 && parts[0].len() <= 16 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[1].to_string(), hash_type: HashType::PGPS2K,
                hash_bytes: hex::decode(parts[1]).ok()?, salt: Some(parts[0].to_string()),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() <= 16 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

pub struct LotusNotes5Hash;
impl HashCracker for LotusNotes5Hash {
    fn hash_type(&self) -> HashType { HashType::LotusNotes5 }
    fn name(&self) -> &'static str { "Lotus Notes 5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for LotusNotes5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() >= 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::LotusNotes5,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1..].join(":")),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

pub struct MssqlOldHash;
impl HashCracker for MssqlOldHash {
    fn hash_type(&self) -> HashType { HashType::MSSQLOld }
    fn name(&self) -> &'static str { "MSSQL Old" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for MssqlOldHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() >= 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::MSSQLOld,
                hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1..].join(":")),
                username: None, cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

pub struct PostgresqlScramSha256Hash;
impl HashCracker for PostgresqlScramSha256Hash {
    fn hash_type(&self) -> HashType { HashType::PostgreSQLSCRAMSHA256 }
    fn name(&self) -> &'static str { "PostgreSQL SCRAM-SHA-256" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PostgresqlScramSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("SCRAM-SHA-256$") {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::PostgreSQLSCRAMSHA256,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("SCRAM-SHA-256$")
    }
}

pub struct Wpa2PmkidHash;
impl HashCracker for Wpa2PmkidHash {
    fn hash_type(&self) -> HashType { HashType::WPA2PMKID }
    fn name(&self) -> &'static str { "WPA2 PMKID" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Wpa2PmkidHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with('*') && s.len() == 65 && s[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::WPA2PMKID,
                hash_bytes: hex::decode(&s[1..]).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('*') && s.len() == 65 && s[1..].chars().all(|c| c.is_ascii_hexdigit())
    }
}

pub struct EthereumWalletHash;
impl HashCracker for EthereumWalletHash {
    fn hash_type(&self) -> HashType { HashType::EthereumWallet }
    fn name(&self) -> &'static str { "Ethereum Wallet" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for EthereumWalletHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::EthereumWallet,
                hash_bytes: hex::decode(&s[2..]).ok()?, salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("0x") && s.len() == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
    }
}

pub struct RippleWalletHash;
impl HashCracker for RippleWalletHash {
    fn hash_type(&self) -> HashType { HashType::RippleWallet }
    fn name(&self) -> &'static str { "Ripple Wallet" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for RippleWalletHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with('r') && s.len() >= 25 && s.len() <= 35 && s.chars().all(|c| c.is_alphanumeric()) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::RippleWallet,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('r') && s.len() >= 25 && s.len() <= 35 && s.chars().all(|c| c.is_alphanumeric())
    }
}

pub struct StellarHash;
impl HashCracker for StellarHash {
    fn hash_type(&self) -> HashType { HashType::Stellar }
    fn name(&self) -> &'static str { "Stellar" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for StellarHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with('G') && s.len() == 56 && s.chars().all(|c| c.is_alphanumeric()) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Stellar,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('G') && s.len() == 56 && s.chars().all(|c| c.is_alphanumeric())
    }
}

pub struct CardanoHash;
impl HashCracker for CardanoHash {
    fn hash_type(&self) -> HashType { HashType::Cardano }
    fn name(&self) -> &'static str { "Cardano" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for CardanoHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("addr") && s.len() >= 58 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Cardano,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("addr")
    }
}

pub struct PolkadotHash;
impl HashCracker for PolkadotHash {
    fn hash_type(&self) -> HashType { HashType::Polkadot }
    fn name(&self) -> &'static str { "Polkadot" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for PolkadotHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with('1') && s.len() >= 46 && s.len() <= 48 && s.chars().all(|c| c.is_alphanumeric()) {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Polkadot,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('1') && s.len() >= 46 && s.len() <= 48 && s.chars().all(|c| c.is_alphanumeric())
    }
}

pub struct SolanaHash;
impl HashCracker for SolanaHash {
    fn hash_type(&self) -> HashType { HashType::Solana }
    fn name(&self) -> &'static str { "Solana" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for SolanaHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.starts_with("sol") && s.len() >= 32 && s.len() <= 44 {
            Some(HashEntry { raw: s.to_string(), hash_type: HashType::Solana,
                hash_bytes: s.as_bytes().to_vec(), salt: None, username: None,
                cracked: false, password: None })
        } else { None }
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with("sol") && s.len() >= 32 && s.len() <= 44
    }
}
