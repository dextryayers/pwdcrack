//! Device verification for the Vulkan compute path.
//!
//! Run by `scripts/verify-vulkan-kernels.sh`, and usable directly:
//!
//! ```text
//! PWDCRACK_MD5_CORPUS=/tmp/corpus cargo run -p engine-vulkan --features vulkan --bin device-check
//! ```
//!
//! The corpus file format is one line per candidate, `<length> <expected md5 hex>`,
//! with the expected values produced by python hashlib. They are read from the
//! environment rather than embedded here for two reasons: a digest written into
//! the crate is a digest that can be edited by accident, and the whole point of
//! this check is to compare against something this repository does not produce.

#[cfg(feature = "vulkan")]
fn main() {
    match engine_vulkan::run_device_check() {
        Ok(summary) => println!("{summary}"),
        Err(e) => {
            eprintln!("device check failed: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "vulkan"))]
fn main() {
    eprintln!(
        "engine-vulkan was built without the 'vulkan' feature, so there is no \
         device path to check. Rebuild with --features vulkan."
    );
    std::process::exit(1);
}