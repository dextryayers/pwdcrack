//! Measures one-dispatch latency at the batch sizes an attack actually uses.
//!
//! The 1,000,000-candidate throughput in `throughput.rs` says nothing about a
//! dictionary group of 512. This prints the median wall time of a complete
//! dispatch, including the upload, submit, poll and readback, for sizes from one
//! verification group to one full batch.
//!
//! Run with: cargo run --release -p engine-gpu --example latency

use std::time::Instant;

use engine_gpu::cracker::{self, GpuCracker};

fn main() {
    let Some(engine) = pollster::block_on(engine_gpu::GpuEngine::init()) else {
        eprintln!("no GPU adapter on this host");
        return;
    };
    let cracker = pollster::block_on(GpuCracker::new(std::sync::Arc::new(engine)));
    eprintln!("batch size: {}", cracker.batch_size());

    let candidates = 65_536usize;
    let passwords: Vec<Vec<u8>> = (0..candidates)
        .map(|i| format!("candidate{i}").into_bytes())
        .collect();

    println!(
        "{:>10} {:>10} {:>12} {:>12}",
        "hash", "count", "median ms", "M hash/s"
    );
    for hash_type in ["md5", "ntlm", "sha1", "sha256", "sha512", "ripemd160", "blake2b"] {
        let mut packed = Vec::with_capacity(candidates * cracker::CANDIDATE_BYTES);
        for password in &passwords {
            packed.extend_from_slice(&GpuCracker::pack_candidate(hash_type, password).unwrap());
        }
        let target = "00".repeat(cracker::digest_len(hash_type).unwrap());

        for count in [512usize, 4_096, 16_384, 65_536] {
            let bytes = &packed[..count * cracker::CANDIDATE_BYTES];
            // One warm up at this size, then nine timed runs; the median is the
            // fifth sorted value.
            let _ = cracker.dispatch_batch(hash_type, bytes, &target);
            let mut times = Vec::with_capacity(9);
            for _ in 0..9 {
                let start = Instant::now();
                let flags = cracker.dispatch_batch(hash_type, bytes, &target).unwrap();
                times.push(start.elapsed());
                assert_eq!(flags.len(), count);
            }
            times.sort();
            let median = times[4].as_secs_f64();
            println!(
                "{hash_type:>10} {count:>10} {:>12.3} {:>12.3}",
                median * 1e3,
                count as f64 / median / 1e6
            );
        }
    }
}
