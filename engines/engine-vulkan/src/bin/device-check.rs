//! Reports Vulkan devices and their limits, and runs the MD5 kernel on the first
//! device that supports compute.
//!
//! This is the stage that can only be satisfied by real hardware, and it is the
//! one that matters. Everything upstream of it checks that the shader is well
//! formed and that its tables are right; this checks that the GPU actually
//! produces the digests.
//!
//! Run through `scripts/verify-vulkan-kernels.sh`.

fn main() {
    match engine_vulkan::run_md5_device_check() {
        Ok(summary) => {
            println!("{summary}");
        }
        Err(e) => {
            eprintln!("device check failed: {e}");
            std::process::exit(1);
        }
    }
}
