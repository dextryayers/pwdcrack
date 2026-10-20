//! Parses and validates every supported WGSL shader at build time.
//!
//! A shader that does not compile used to fail only when `GpuCracker::new` tried
//! to build its pipeline, and that failure was silently discarded. This turns it
//! into a compile error naming the file and the line.

use std::path::Path;

fn main() {
    let dir = Path::new("src/shaders");
    println!("cargo:rerun-if-changed={}", dir.display());

    let mut shaders = 0;
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));

    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_none_or(|e| e != "wgsl") {
            continue;
        }
        shaders += 1;
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.display();
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {name}: {e}"));

        let module = naga::front::wgsl::parse_str(&source)
            .unwrap_or_else(|e| panic!("{name} does not parse:\n{e}"));

        let mut validator = naga::valid::Validator::new(
            naga::valid::ValidationFlags::all(),
            naga::valid::Capabilities::empty(),
        );
        validator
            .validate(&module)
            .unwrap_or_else(|e| panic!("{name} does not validate:\n{e}"));

        if !module
            .entry_points
            .iter()
            .any(|entry| entry.name == "main" && entry.stage == naga::ShaderStage::Compute)
        {
            panic!("{name} has no compute entry point named `main`");
        }
    }

    assert!(shaders > 0, "no .wgsl files under {}", dir.display());
}
