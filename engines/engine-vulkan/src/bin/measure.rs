//! Measures GPU MD5 throughput against the CPU reference on this machine.
//!
//! Run with:
//!
//! ```text
//! cargo run --release -p engine-vulkan --features vulkan --bin measure
//! ```
//!
//! Reports the ratio rather than asserting one. Whether a GPU helps depends on
//! the batch size and on the device: on a small integrated GPU the dispatch and
//! buffer setup can cost more than the hashing. Publishing a single speedup
//! number without the batch size and the device name would be a claim with no
//! context, which is what this binary exists to prevent.

#[cfg(feature = "vulkan")]
fn main() {
    println!("{:<10} {:>16} {:>16} {:>10}", "batch", "gpu /s", "cpu /s", "ratio");
    for batch in [64u32, 256] {
        let rounds = if batch <= 64 { 200 } else { 50 };
        match engine_vulkan::measure_throughput(batch, rounds) {
            Ok((gpu, cpu, ratio)) => println!(
                "{:<10} {:>16.0} {:>16.0} {:>9.2}x",
                batch, gpu, cpu, ratio
            ),
            Err(e) => {
                eprintln!("batch {batch}: {e}");
                std::process::exit(1);
            }
        }
    }
    println!();
    println!("Both figures are measured in this process on this machine.");
    println!("A ratio near or below 1 at small batch sizes is expected on an");
    println!("integrated GPU: dispatch and buffer setup cost more than the hashing.");
}

/// Without the feature there is no device path, so say so and exit rather than
/// reporting a zero rate that could be mistaken for a measurement.
#[cfg(not(feature = "vulkan"))]
fn main() {
    eprintln!(
        "engine-vulkan was built without the 'vulkan' feature, so there is no \
         GPU path to measure. Rebuild with --features vulkan."
    );
    std::process::exit(1);
}
