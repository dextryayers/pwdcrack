//! Differential tests: every GPU kernel is checked against the RustCrypto
//! implementation of the same hash on the same 1,000 candidates.
//!
//! The test calls `dispatch_batch` directly rather than `verify_many`, because
//! `verify_many` falls back to the CPU when a dispatch fails. A fallback would
//! hide a broken kernel behind correct answers.

use engine_gpu::cracker::{self, GpuCracker, HASH_TYPES};

fn digest(hash_type: &str, password: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match hash_type {
        "md2" => {
            let mut h = md2::Md2::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "md5" => {
            let mut h = md5::Md5::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha1" => {
            let mut h = sha1::Sha1::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha224" => {
            let mut h = sha2::Sha224::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha256" => {
            let mut h = sha2::Sha256::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha3_224" => {
            let mut h = sha3::Sha3_224::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha3_256" => {
            let mut h = sha3::Sha3_256::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha3_384" => {
            let mut h = sha3::Sha3_384::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha3_512" => {
            let mut h = sha3::Sha3_512::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha384" => {
            let mut h = sha2::Sha384::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha512" => {
            let mut h = sha2::Sha512::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha512_224" => {
            let mut h = sha2::Sha512_224::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "sha512_256" => {
            let mut h = sha2::Sha512_256::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "md4" => {
            let mut h = md4::Md4::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "ntlm" => {
            let mut h = md4::Md4::new();
            let text = std::str::from_utf8(password).expect("test generates ASCII");
            let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            h.update(&utf16);
            h.finalize().to_vec()
        }
        "ripemd128" => {
            let mut h = ripemd::Ripemd128::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "ripemd160" => {
            let mut h = ripemd::Ripemd160::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "blake2b" => {
            let mut h = blake2::Blake2b512::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "blake2b_256" => {
            let mut h = blake2::Blake2b::<blake2::digest::consts::U32>::new();
            h.update(password);
            h.finalize().to_vec()
        }
        "blake2s_256" => {
            let mut h = blake2::Blake2s256::new();
            h.update(password);
            h.finalize().to_vec()
        }
        other => panic!("no reference for {other}"),
    }
}

/// Deterministic xorshift64 so a failure reproduces.
fn rng(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// 1,000 candidates per hash type. The first six hit the padding boundaries;
/// the rest are random lengths up to the 64 byte limit.
fn candidates(hash_type: &str) -> Vec<Vec<u8>> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let ntlm = hash_type == "ntlm";
    let fixed_lengths = if ntlm {
        [0usize, 1, 2, 27, 28, 32]
    } else {
        [0, 1, 55, 56, 63, 64]
    };

    (0..1000)
        .map(|i| {
            let len = if i < fixed_lengths.len() {
                fixed_lengths[i]
            } else if ntlm {
                (rng(&mut state) % 33) as usize
            } else {
                (rng(&mut state) % 65) as usize
            };
            (0..len)
                .map(|_| {
                    let byte = rng(&mut state) as u8;
                    if ntlm {
                        // Valid UTF-8, one byte per character.
                        b'!' + (byte % 94)
                    } else {
                        byte
                    }
                })
                .collect()
        })
        .collect()
}

#[test]
fn gpu_kernels_match_the_reference_on_one_thousand_candidates() {
    let engine = match pollster::block_on(engine_gpu::GpuEngine::init()) {
        Some(e) => e,
        None => {
            eprintln!("skipped: no GPU adapter is available on this host");
            return;
        }
    };
    eprintln!("engine: {}", engine.info());
    let cracker = pollster::block_on(GpuCracker::new(std::sync::Arc::new(engine)));

    for hash_type in HASH_TYPES {
        let kernel = if hash_type == "ntlm" { "md4" } else { hash_type };
        assert!(
            cracker.available().contains(&kernel),
            "{hash_type}: the {kernel} pipeline was not built, available: {:?}",
            cracker.available()
        );

        let candidates = candidates(hash_type);
        let target_index = 777;
        let target = hex::encode(digest(hash_type, &candidates[target_index]));

        let mut packed = Vec::with_capacity(candidates.len() * cracker::CANDIDATE_BYTES);
        for candidate in &candidates {
            let buf = GpuCracker::pack_candidate(hash_type, candidate)
                .unwrap_or_else(|| panic!("{hash_type}: candidate of {} bytes did not pack", candidate.len()));
            packed.extend_from_slice(&buf);
        }

        let flags = cracker
            .dispatch_batch(hash_type, &packed, &target)
            .unwrap_or_else(|e| panic!("{hash_type}: GPU dispatch failed: {e}"));
        assert_eq!(flags.len(), candidates.len(), "{hash_type}: one flag per candidate");

        let expected: Vec<bool> = candidates
            .iter()
            .map(|c| digest(hash_type, c) == digest(hash_type, &candidates[target_index]))
            .collect();
        assert_eq!(flags, expected, "{hash_type}: GPU flags disagree with the reference");
        assert!(flags[target_index], "{hash_type}: the target candidate must match");
        assert_eq!(
            flags.iter().filter(|f| **f).count(),
            1,
            "{hash_type}: exactly one candidate should match"
        );

        // The same call through the batch API, which is what an attack uses.
        let refs: Vec<&[u8]> = candidates.iter().map(|c| c.as_slice()).collect();
        let batched = cracker.verify_many(hash_type, &refs, &target);
        assert_eq!(batched, expected, "{hash_type}: verify_many disagrees with the reference");

        eprintln!("{hash_type}: {} candidates agree with the reference", candidates.len());
    }
}

/// Published vectors, independent of the RustCrypto crates the differential test
/// uses. A kernel that agrees with a wrong reference would still fail here.
#[test]
fn gpu_matches_published_vectors() {
    let engine = match pollster::block_on(engine_gpu::GpuEngine::init()) {
        Some(e) => e,
        None => {
            eprintln!("skipped: no GPU adapter is available on this host");
            return;
        }
    };
    let cracker = pollster::block_on(GpuCracker::new(std::sync::Arc::new(engine)));

    let vectors: [(&str, &[u8], &str); 22] = [
        ("md2", b"", "8350e5a3e24c153df2275c9f80692773"),
        ("md2", b"abc", "da853b0d3f88d99b30283a69e6ded6bb"),
        ("md5", b"", "d41d8cd98f00b204e9800998ecf8427e"),
        ("md5", b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("md4", b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        ("ntlm", b"password", "8846f7eaee8fb117ad06bdd830b7586c"),
        ("sha1", b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        ("sha224", b"abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
        ("sha256", b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("sha3_224", b"abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
        ("sha3_256", b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("sha3_384", b"abc", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
        ("sha3_512", b"abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
        ("sha384", b"abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        ("sha512", b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ("sha512_224", b"abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"),
        ("sha512_256", b"abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
        ("ripemd128", b"abc", "c14a12199c66e4ba84636b0f69144c77"),
        ("ripemd160", b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        ("blake2b", b"abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
        ("blake2b_256", b"abc", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"),
        ("blake2s_256", b"abc", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    ];

    for (hash_type, candidate, expected) in vectors {
        let packed = GpuCracker::pack_candidate(hash_type, candidate).unwrap();
        let flags = cracker
            .dispatch_batch(hash_type, &packed, expected)
            .unwrap_or_else(|e| panic!("{hash_type}: {e}"));
        assert_eq!(flags, vec![true], "{hash_type}: {:?} did not match {expected}", candidate);
    }
}

#[test]
fn a_target_of_the_wrong_length_is_rejected() {
    let engine = match pollster::block_on(engine_gpu::GpuEngine::init()) {
        Some(e) => e,
        None => {
            eprintln!("skipped: no GPU adapter is available on this host");
            return;
        }
    };
    let cracker = pollster::block_on(GpuCracker::new(std::sync::Arc::new(engine)));

    let packed = GpuCracker::pack_candidate("md5", b"abc").unwrap();
    // 32 hex digits is SHA-256 length, not MD5.
    let err = cracker
        .dispatch_batch("md5", &packed, &"00".repeat(32))
        .expect_err("a 32 byte target must not be accepted for MD5");
    assert!(err.to_string().contains("16"), "unexpected error: {err}");

    let err = cracker
        .dispatch_batch("md5", &packed[..packed.len() - 1], &"00".repeat(16))
        .expect_err("a partial record must not be accepted");
    assert!(err.to_string().contains("multiple"), "unexpected error: {err}");
}
