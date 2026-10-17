//! Build script for the CUDA engine.
//!
//! # What this does
//!
//! Locates `nvcc`, compiles each `.cu` in `src/kernels/` to PTX, and embeds the
//! PTX so the binary carries its own kernels and does not need a CUDA toolkit at
//! run time. The driver JITs the PTX for whatever compute capability the device
//! actually has, which is how one binary serves every supported card.
//!
//! # What this does NOT do, and why it cannot
//!
//! It does not compile the kernels on a machine without `nvcc`. That situation
//! is reported as a build failure with instructions rather than being skipped,
//! because silently producing a binary whose GPU path can never work is worse
//! than refusing to build.
//!
//! `PW_CUDA_ALLOW_NO_NVCC=1` downgrades that to a warning and builds the crate
//! with the GPU path compiled out. It exists so the rest of the workspace can be
//! built and tested on a machine with no CUDA toolkit, which is the normal case
//! for CI and for contributors who are not working on the GPU engine. A build
//! produced that way must not claim to support CUDA, and
//! `cfg(pw_cuda_no_ptx)` records that so the Rust side can say so at run time
//! instead of failing obscurely.
//!
//! # Verification
//!
//! The kernel arithmetic is verified on the host by `scripts/verify-kernels.sh`,
//! which compiles the same `hash_core.h` with the system C compiler and checks
//! 220 values against RFC vectors, python hashlib and openssl, then executes the
//! actual `.cu` kernel bodies through a host shim. Nothing in this build script
//! substitutes for that, and a successful build is not evidence that a kernel is
//! correct.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Output directory for the generated PTX.
const PTX_DIR: &str = "generated";

/// Minimum compute capability targeted.
///
/// Maxwell (5.x) is the floor for two reasons: it is the oldest architecture
/// `nvcc` still supports for these PTX versions, and every architecture from
/// Pascal upward can JIT this PTX upward. Targeting lower would gain nothing.
const COMPUTE_CAPABILITY: &str = "60";

/// Kernels compiled to PTX. Listed explicitly rather than globbed so that adding
/// a file without deciding its compute capability is a deliberate act.
const KERNELS: &[&str] = &["md5"];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let kernel_dir = manifest.join("src/kernels");

    println!("cargo:rerun-if-changed=src/kernels");
    println!("cargo:rerun-if-changed=build.rs");
    if let Some(p) = common_dir_path(&manifest) {
        println!("cargo:rerun-if-changed={}", p.join("hash_core_shared.h").display());
    }
    println!("cargo:rerun-if-env-changed=CUDA_PATH");
    println!("cargo:rerun-if-env-changed=CUDACXX");
    println!("cargo:rerun-if-env-changed=PW_CUDA_ALLOW_NO_NVCC");

    let nvcc = match find_nvcc() {
        Some(path) => path,
        None => {
            report_missing_nvcc(&manifest);
            return;
        }
    };

    println!("cargo:warning=using nvcc at {}", nvcc.display());
    emit_ptx(&nvcc, &kernel_dir, &out_dir);
}

/// Path to `engines/kernel-common`, which holds the shared hash core.
fn common_dir_path(manifest: &Path) -> Option<PathBuf> {
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("kernel-common"))
}

/// Looks for `nvcc` in the documented places, in order.
///
/// `CUDACXX` first because that is what cudarc's own build scripts consult, then
/// `CUDA_PATH`, then `PATH`. Checking them in that order means a developer with a
/// specific toolkit selected for cudarc gets the same one here.
fn find_nvcc() -> Option<PathBuf> {
    if let Ok(cxx) = std::env::var("CUDACXX") {
        if !cxx.is_empty() {
            let p = PathBuf::from(&cxx);
            if p.exists() {
                return Some(p);
            }
            warn(&format!(
                "CUDACXX is set to {cxx} but that path does not exist, continuing"
            ));
        }
    }

    if let Ok(cuda_path) = std::env::var("CUDA_PATH") {
        if !cuda_path.is_empty() {
            let p = Path::new(&cuda_path).join("bin/nvcc");
            if p.exists() {
                return Some(p);
            }
            warn(&format!(
                "CUDA_PATH is set to {cuda_path} but {}/bin/nvcc does not exist, continuing",
                cuda_path
            ));
        }
    }

    // `which nvcc`, done without a shell so a path with spaces still works.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let p = dir.join("nvcc");
            if p.is_file() {
                return Some(p);
            }
        }
    }

    None
}

/// Reports the absence of a CUDA toolkit, and either fails or degrades based on
/// `PW_CUDA_ALLOW_NO_NVCC`.
fn report_missing_nvcc(manifest: &Path) {
    let allow = std::env::var("PW_CUDA_ALLOW_NO_NVCC")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let message = format!(
        "\n\
         nvcc was not found, so no CUDA kernels were compiled.\n\
         \n\
         This crate looks for nvcc in this order:\n\
           1. $CUDACXX\n\
           2. $CUDA_PATH/bin/nvcc\n\
           3. nvcc on $PATH\n\
         \n\
         To fix it:\n\
           - Install the CUDA toolkit. On Debian and Ubuntu the package is\n\
             nvidia-cuda-toolkit. See https://developer.nvidia.com/cuda-downloads\n\
           - If it is installed somewhere unusual, set CUDA_PATH to that directory:\n\
               CUDA_PATH=/opt/cuda bash scripts/build.sh\n\
           - If nvcc is a wrapper script, point CUDACXX at it:\n\
               CUDACXX=/usr/local/bin/my-nvcc bash scripts/build.sh\n\
         \n\
         To build anyway with the CUDA path compiled out, for working on other\n\
         parts of the tree:\n\
           PW_CUDA_ALLOW_NO_NVCC=1 cargo build\n\
         \n\
         That build cannot run any GPU work. It sets cfg(pw_cuda_no_ptx) so the\n\
         binary reports the limitation at run time instead of failing obscurely.\n\
         \n\
         Crate: {}\n",
        manifest.display()
    );

    if allow {
        warn(&message);
        // Record the decision so the Rust side can report it honestly.
        println!("cargo:rustc-cfg=pw_cuda_no_ptx");
        println!("cargo:rustc-check-cfg=cfg(pw_cuda_no_ptx)");
    } else {
        panic!("{message}");
    }
}

/// Compiles every kernel in [`KERNELS`] to PTX.
fn emit_ptx(nvcc: &Path, kernel_dir: &Path, out_dir: &Path) {
    let ptx_out = out_dir.join(PTX_DIR);
    if let Err(e) = std::fs::create_dir_all(&ptx_out) {
        panic!("could not create {}: {e}", ptx_out.display());
    }

    // engines/kernel-common holds the one copy of the hash core. Both the CUDA
    // and OpenCL kernels include it, so the include path has to reach it.
    let common_dir = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("kernel-common"));
    let mut include = kernel_dir.to_string_lossy().to_string();
    if let Some(dir) = common_dir {
        if dir.exists() {
            include.push(':');
            include.push_str(&dir.to_string_lossy());
        }
    }

    for name in KERNELS {
        let src = kernel_dir.join(format!("{name}.cu"));
        if !src.exists() {
            panic!(
                "{} is listed in KERNELS but does not exist",
                src.display()
            );
        }

        let dst = ptx_out.join(format!("{name}.ptx"));

        let output = Command::new(nvcc)
            .arg(format!("-arch=compute_{COMPUTE_CAPABILITY}"))
            .arg("--ptx")
            .arg("-O3")
            .arg(format!("-I{include}"))
            .arg(&src)
            .arg("-o")
            .arg(&dst)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                println!(
                    "cargo:rustc-env=PW_PTX_{}={}",
                    name.to_uppercase(),
                    dst.display()
                );
                println!("cargo:rerun-if-changed={}", src.display());
            }
            Ok(out) => {
                // Surface nvcc's own diagnostics. Without this the failure is a
                // bare non-zero exit and the actual cause is invisible.
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                panic!(
                    "nvcc failed to compile {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                    src.display()
                );
            }
            Err(e) => panic!("could not run {}: {e}", nvcc.display()),
        }
    }
}

/// Emits a cargo warning. Does not use `cargo:warning` on its own so that the
/// build script stays testable outside a cargo invocation.
fn warn(msg: &str) {
    println!("cargo:warning={msg}");
}