//! Compiles a WGSL shader to SPIR-V.
//!
//! Used by `scripts/verify-vulkan-kernels.sh` so the verification uses the same
//! naga version and the same options the library uses, rather than a second
//! compiler invocation that could drift.
//!
//! The previous `compile_glsl_to_spirv` in this crate returned an error saying
//! glslc was unavailable, and this engine had no working shader path at all.
//! Nothing is read from a file at run time and no external compiler binary is
//! required.

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(input), Some(output)) = (args.next(), args.next()) else {
        eprintln!("usage: compile-spirv <input.wgsl> <output.spv>");
        std::process::exit(2);
    };
    let input = PathBuf::from(input);
    let output = PathBuf::from(output);

    let source = match std::fs::read_to_string(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read {}: {e}", input.display());
            std::process::exit(1);
        }
    };

    let words = match engine_vulkan::shader::wgsl_to_spirv(&source, "main") {
        Ok(w) => w,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    if let Err(e) = std::fs::write(&output, &bytes) {
        eprintln!("cannot write {}: {e}", output.display());
        std::process::exit(1);
    }
    println!(
        "{}: {} SPIR-V words",
        input.display(),
        words.len()
    );
}