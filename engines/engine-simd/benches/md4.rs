//! Throughput comparison for the MD4 multi-buffer kernel, which is also the
//! NTLM kernel.
//!
//! Declared with `harness = false` because this is a plain measurement program,
//! not a set of pass/fail tests. Run it with:
//!
//! ```text
//! cargo bench -p engine-simd --bench md4 --target-dir .build
//! ```
//!
//! Two rows are reported for NTLM because the encoding step is part of its cost:
//! `ntlm scalar` hashes and encodes one candidate at a time, while `ntlm batch`
//! encodes first and then fills eight lanes. Both do the same work per
//! candidate, so the ratio is the kernel's contribution and not an artefact of
//! skipping the encoding.

use engine_simd::x86::avx2_md4::{
    kernel_available, md4_batch, ntlm_batch_verify, ntlm_encode, scalar_digest,
};
use std::time::Instant;

/// Builds a deterministic corpus of password shaped inputs.
fn corpus(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("Passw0rd-{i:08}").into_bytes())
        .collect()
}

/// Hashes every message one at a time through the scalar reference.
fn bench_md4_scalar(msgs: &[Vec<u8>], rounds: usize) -> f64 {
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
fn bench_md4_batch(msgs: &[Vec<u8>], rounds: usize) -> f64 {
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for d in md4_batch(&refs) {
            acc ^= u64::from(d[0]);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (msgs.len() as f64 * rounds as f64) / elapsed
}

/// Encodes and hashes every candidate one at a time, which is what the scalar
/// NTLM path does per candidate.
fn bench_ntlm_scalar(msgs: &[Vec<u8>], rounds: usize) -> f64 {
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for m in msgs {
            let encoded = ntlm_encode(m).expect("the corpus is valid UTF-8");
            acc ^= u64::from(scalar_digest(&encoded)[0]);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (msgs.len() as f64 * rounds as f64) / elapsed
}

/// Encodes every candidate, then verifies the batch against a target that does
/// not match, so the kernel's compare step is included in the measurement.
fn bench_ntlm_batch(msgs: &[Vec<u8>], rounds: usize) -> f64 {
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let target = "00000000000000000000000000000000";
    let targets: Vec<&str> = refs.iter().map(|_| target).collect();
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for hit in ntlm_batch_verify(&refs, &targets) {
            acc ^= u64::from(hit);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);
    (msgs.len() as f64 * rounds as f64) / elapsed
}

fn main() {
    if !kernel_available() {
        println!("AVX2 is not available on this host, there is nothing to compare.");
        return;
    }

    println!("corpus: passwords of 16 bytes, total 65536 hashes per measurement");
    println!("{:>16} {:>10} {:>16} {:>18} {:>10}", "kernel", "batch", "scalar /s", "vector /s", "speedup");

    for batch in [8usize, 64, 512, 4096, 16384] {
        let msgs = corpus(batch);
        // Keep the total number of hashes constant so every row does the same
        // amount of work and the rates are directly comparable.
        let rounds = (65536 / batch).max(1);

        bench_md4_scalar(&msgs, 1);
        bench_md4_batch(&msgs, 1);
        bench_ntlm_scalar(&msgs, 1);
        bench_ntlm_batch(&msgs, 1);

        let md4_s = bench_md4_scalar(&msgs, rounds);
        let md4_b = bench_md4_batch(&msgs, rounds);
        println!("{:>16} {:>10} {:>16.0} {:>18.0} {:>9.2}x", "md4", batch, md4_s, md4_b, md4_b / md4_s);

        let ntlm_s = bench_ntlm_scalar(&msgs, rounds);
        let ntlm_b = bench_ntlm_batch(&msgs, rounds);
        println!("{:>16} {:>10} {:>16.0} {:>18.0} {:>9.2}x", "ntlm", batch, ntlm_s, ntlm_b, ntlm_b / ntlm_s);
    }
}
