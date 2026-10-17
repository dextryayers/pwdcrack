//! Build script for the OpenCL engine.
//!
//! # Why assembly happens here
//!
//! OpenCL C has no portable preprocessor include. A `.cl` file cannot
//! `#include` the shared hash core the way the CUDA kernel does, so the only way
//! for both engines to run the same verified compression code is to concatenate
//! the parts at build time.
//!
//! The output goes to `target-generated/opencl/`, which is inside the repository
//! rather than `OUT_DIR`, because `include_str!` needs a path that is stable
//! between the build script and the crate root, and `OUT_DIR` is not available to
//! `include_str!` without a `cargo:` environment variable.
//!
//! The directory is regenerated on every build and is not committed. If it is
//! missing when the crate is compiled without running this script, the build
//! fails with an instruction to run the generator rather than compiling against
//! an absent file.
//!
//! # What is verified
//!
//! `scripts/verify-opencl-kernels.sh` checks the assembled output: clang's
//! OpenCL front end accepts it, the compression matches python hashlib for 201
//! message lengths, and the kernel body executes correctly through a host shim.
//! A successful build is not evidence that any of that is true.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Kernel entry points, and the file each is written to.
const KERNELS: &[(&str, &str)] = &[
    ("md5", "md5.cl"),
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // manifest is <workspace>/engines/engine-opencl, so one parent up is
    // <workspace>/engines and two is <workspace>. The shared core lives under
    // engines, not at the workspace root; going up two levels first and then
    // joining "kernel-common" produced <workspace>/kernel-common, which does not
    // exist.
    let engines_dir = manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| manifest.clone());
    let workspace = engines_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| engines_dir.clone());

    let common = engines_dir.join("kernel-common");
    let shared_header = common.join("hash_core_shared.h");
    let generated_core = common.join("hash_core.cl");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", shared_header.display());
    println!("cargo:rerun-if-changed={}", generated_core.display());
    println!("cargo:rerun-if-env-changed=PW_OPENCL_SKIP_ASSEMBLY");

    let out_dir = workspace.join("target-generated/opencl");

    // A documented escape hatch for a checkout where the generator cannot run,
    // for example because python3 is absent. The crate will then fail to compile
    // on the missing include, which is the correct outcome and says why.
    if std::env::var("PW_OPENCL_SKIP_ASSEMBLY").is_ok() {
        println!(
            "cargo:warning=PW_OPENCL_SKIP_ASSEMBLY is set, not assembling OpenCL \
             kernels; engine-opencl will not compile unless {} already exists",
            out_dir.display()
        );
        return;
    }

    // Regenerate the core from the header so a stale generated file cannot pass.
    let generator = workspace.join("scripts/gen-opencl-core.py");
    let status = Command::new("python3")
        .arg(&generator)
        .current_dir(&workspace)
        .output();

    match status {
        Ok(out) if out.status.success() => {
            println!(
                "cargo:warning={}",
                String::from_utf8_lossy(&out.stdout).trim()
            );
        }
        Ok(out) => panic!(
            "generating the OpenCL core failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => panic!(
            "could not run {}: {e}\n\
             Install python3, or set PW_OPENCL_SKIP_ASSEMBLY=1 if {} already \
             contains an up to date generated core.",
            generator.display(),
            common.display()
        ),
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        panic!("could not create {}: {e}", out_dir.display());
    }

    let core = match std::fs::read_to_string(&generated_core) {
        Ok(s) => s,
        Err(e) => panic!(
            "{} was not produced: {e}\n\
             Run scripts/gen-opencl-core.py and check its output.",
            generated_core.display()
        ),
    };

    for (name, file) in KERNELS {
        let body_path = manifest.join("src/kernels").join(file);
        println!("cargo:rerun-if-changed={}", body_path.display());
        let body = match std::fs::read_to_string(&body_path) {
            Ok(s) => s,
            Err(e) => panic!("could not read {}: {e}", body_path.display()),
        };

        // Order matters: the core defines the helpers and tables, the body
        // defines the kernel that uses them. Reversed, the front end rejects it.
        let assembled = format!("{}\n{}", core, body);
        let dst = out_dir.join(file);
        if let Err(e) = std::fs::write(&dst, &assembled) {
            panic!("could not write {}: {e}", dst.display());
        }

        // Assemble the other kernels as well so a later change to KERNELS cannot
        // leave a stale file that the crate would happily include.
        let _ = name;
    }
}

/// Documents where the assembled sources live, for the crate's own build output.
#[allow(dead_code)]
fn assembled_dir(workspace: &Path) -> PathBuf {
    workspace.join("target-generated/opencl")
}