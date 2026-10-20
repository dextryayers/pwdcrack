//! Checks every WGSL file in `src/shaders`.
//!
//! `GpuCracker::new` only builds pipelines for the hashes it has dispatch code
//! for, so a shader can sit in the tree with a syntax error and nothing notices.
//! These tests close that hole: one parses and validates every file with naga on
//! the CPU, the other hands every file to the real wgpu device, which is the same
//! path `create_shader_module` takes at run time.

use std::path::{Path, PathBuf};

fn shader_paths() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shaders");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()? == "wgsl").then_some(path)
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no shaders found under {}", dir.display());
    paths
}

#[test]
fn every_shader_parses_and_validates_with_naga() {
    let mut failures = Vec::new();
    let paths = shader_paths();

    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{name}: cannot read: {e}"));
                continue;
            }
        };

        let module = match naga::front::wgsl::parse_str(&source) {
            Ok(m) => m,
            Err(e) => {
                failures.push(format!("{name}: parse failed: {e}"));
                continue;
            }
        };

        let mut validator = naga::valid::Validator::new(
            naga::valid::ValidationFlags::all(),
            naga::valid::Capabilities::empty(),
        );
        if let Err(e) = validator.validate(&module) {
            failures.push(format!("{name}: validation failed: {e}"));
            continue;
        }

        if module.entry_points.is_empty() {
            failures.push(format!("{name}: no entry point"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} shaders failed:\n{}",
        failures.len(),
        paths.len(),
        failures.join("\n")
    );
}

#[test]
fn every_shader_compiles_on_the_gpu() {
    let Some(engine) = pollster::block_on(engine_gpu::GpuEngine::init()) else {
        eprintln!("skipped: no GPU adapter is available on this host");
        return;
    };

    let mut failures = Vec::new();
    for path in shader_paths() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let source = std::fs::read_to_string(&path).unwrap();

        // Uncapped device errors surface through the error scope rather than as a
        // panic inside `create_shader_module`, so a broken shader is reported with
        // its file name instead of a backtrace from the driver.
        engine.device.push_error_scope(wgpu::ErrorFilter::Validation);
        let _module = engine.device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some(&name),
            source: wgpu::ShaderSource::Wgsl(source.into()),
        });
        if let Some(error) = pollster::block_on(engine.device.pop_error_scope()) {
            failures.push(format!("{name}: {error}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} shader(s) failed to compile on {}:\n{}",
        failures.len(),
        engine.info(),
        failures.join("\n")
    );
}
