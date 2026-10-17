//! Throughput comparison between the scalar path and the AVX2 multi-buffer path.
//!
//! Declared with `harness = false` because this is a plain measurement program,
//! not a set of pass/fail tests. Run it with:
//!
//! ```text
//! cargo bench -p engine-simd --bench md5 --target-dir .build
//! ```
//!
//! A speedup figure is only meaningful with the batch size reported alongside
//! it. `md5_batch` is a multi-buffer kernel, so its advantage grows with the
//! number of candidates handed to it at once and it is deliberately not used
//! for a single candidate.

use engine_simd::x86::avx2_md5::{avx2_available, md5_batch, scalar_digest};
use std::time::Instant;

/// Builds a deterministic corpus of password shaped inputs.
fn corpus(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("Passw0rd-{i:08}").into_bytes())
        .collect()
}

/// Hashes every message one at a time through the scalar reference.
fn bench_scalar(msgs: &[Vec<u8>], rounds: usize) -> f64 {
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for m in msgs {
            acc ^= u64::from(scalar_digest(m)[0]);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (msgs.len() as f64 * rounds as f64) / elapsed
}

/// Hashes every message through the batched entry point.
fn bench_batch(msgs: &[Vec<u8>], rounds: usize) -> f64 {
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for d in md5_batch(&refs) {
            acc ^= u64::from(d[0]);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (msgs.len() as f64 * rounds as f64) / elapsed
}

fn main() {
    if !avx2_available() {
        println!("AVX2 is not available on this host, there is nothing to compare.");
        return;
    }

    println!("corpus: passwords of 16 bytes, total 65536 hashes per measurement");
    println!(
        "{:>10} {:>16} {:>18} {:>10}",
        "batch", "scalar /s", "avx2-multi8 /s", "speedup"
    );

    for batch in [8usize, 64, 512, 4096, 16384] {
        let msgs = corpus(batch);
        // Keep the total number of hashes constant so every row does the same
        // amount of work and the rates are directly comparable.
        let rounds = (65536 / batch).max(1);

        // Warm up once so the first row is not penalised by page faults.
        bench_scalar(&msgs, 1);
        bench_batch(&msgs, 1);

        let s = bench_scalar(&msgs, rounds);
        let b = bench_batch(&msgs, rounds);
        println!(
            "{:>10} {:>16.0} {:>18.0} {:>9.2}x",
            batch,
            s,
            b,
            b / s
        );
    }
}
