//! Measures GPU dispatch throughput against a single-threaded CPU hash of the
//! same candidates.
//!
//! Run with: cargo run --release -p engine-gpu --example throughput
//!
//! The number printed is the median of three timed dispatches, with the packing
//! done before the timer starts. This is a kernel measurement, not an end to end
//! attack measurement: it does not include reading a wordlist or reporting.

use std::time::Instant;

use engine_gpu::cracker::{self, GpuCracker, HASH_TYPES};

const CANDIDATES: usize = 1_000_000;
const PASSWORD_LEN: usize = 11;

fn cpu_hash(hash_type: &str, password: &[u8]) {
    use sha2::Digest;
    match hash_type {
        "md5" => {
            let mut h = md5::Md5::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "sha1" => {
            let mut h = sha1::Sha1::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "sha256" => {
            let mut h = sha2::Sha256::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "sha512" => {
            let mut h = sha2::Sha512::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "md4" => {
            let mut h = md4::Md4::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "ntlm" => {
            let utf16: Vec<u8> = std::str::from_utf8(password)
                .unwrap()
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            let mut h = md4::Md4::new();
            h.update(&utf16);
            std::hint::black_box(h.finalize());
        }
        "ripemd160" => {
            let mut h = ripemd::Ripemd160::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        "blake2b" => {
            let mut h = blake2::Blake2b512::new();
            h.update(password);
            std::hint::black_box(h.finalize());
        }
        _ => unreachable!(),
    }
}

fn main() {
    let Some(engine) = pollster::block_on(engine_gpu::GpuEngine::init()) else {
        eprintln!("no GPU adapter on this host");
        return;
    };
    eprintln!("{}", engine.info());
    let cracker = pollster::block_on(GpuCracker::new(std::sync::Arc::new(engine)));
    eprintln!("batch size: {}", cracker.batch_size());

    let passwords: Vec<Vec<u8>> = (0..CANDIDATES)
        .map(|i| {
            let mut v = Vec::with_capacity(PASSWORD_LEN);
            let mut x = i as u64;
            for _ in 0..PASSWORD_LEN {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                v.push(b'a' + ((x >> 33) % 26) as u8);
            }
            v
        })
        .collect();
    let refs: Vec<&[u8]> = passwords.iter().map(|p| p.as_slice()).collect();

    println!("{:>10} {:>12} {:>12} {:>8}", "hash", "gpu M/s", "cpu M/s", "speedup");
    for hash_type in HASH_TYPES {
        let mut packed = Vec::with_capacity(CANDIDATES * cracker::CANDIDATE_BYTES);
        for password in &passwords {
            packed.extend_from_slice(&GpuCracker::pack_candidate(hash_type, password).unwrap());
        }

        // A one-batch warm up, so the timed runs do not include pipeline and
        // buffer creation.
        let target = "00".repeat(cracker::digest_len(hash_type).unwrap());
        let _ = cracker.dispatch_batch(hash_type, &packed[..cracker::CANDIDATE_BYTES * 64], &target);

        let mut gpu_times = Vec::new();
        for _ in 0..3 {
            let start = Instant::now();
            let flags = cracker.dispatch_batch(hash_type, &packed, &target).unwrap();
            gpu_times.push(start.elapsed());
            assert_eq!(flags.len(), CANDIDATES);
        }

        let mut cpu_times = Vec::new();
        for _ in 0..3 {
            let start = Instant::now();
            for password in &refs {
                cpu_hash(hash_type, password);
            }
            cpu_times.push(start.elapsed());
        }

        gpu_times.sort();
        cpu_times.sort();
        let gpu_mps = CANDIDATES as f64 / gpu_times[1].as_secs_f64() / 1e6;
        let cpu_mps = CANDIDATES as f64 / cpu_times[1].as_secs_f64() / 1e6;
        println!(
            "{:>10} {:>12.3} {:>12.3} {:>7.2}x",
            hash_type,
            gpu_mps,
            cpu_mps,
            gpu_mps / cpu_mps
        );
    }
}
