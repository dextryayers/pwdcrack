//! WGSL to SPIR-V and SPIR-V inspection.
//!
//! # What this replaces
//!
//! The previous version of this file was:
//!
//! ```text
//! pub fn compile_glsl_to_spirv(src: &str, stage: &str) -> Result<Vec<u32>, VulkanError> {
//!     let _ = (src, stage);
//!     Err(VulkanError::ShaderCompile("glslc not available at runtime".into()))
//! }
//! ```
//!
//! It named GLSL, not WGSL, and it always failed. There was no shader
//! compilation in this engine at all. `spirv_from_bytes` alongside it converted
//! bytes with `from_ne_bytes`, which happens to be right on a little endian host
//! and wrong on a big endian one, for no reason to prefer host order over the
//! format's.
//!
//! # Approach
//!
//! WGSL is the source language and naga compiles it to SPIR-V in process. There
//! is no external tool, no `glslc`, and nothing to install at build time beyond
//! the crate dependencies. The SPIR-V word order is little endian by
//! specification, and that is what is emitted.
//!
//! # Version note
//!
//! Pinned to naga 28. See `Cargo.toml` and `docs/PHASE7_STATUS.md`: naga 26, the
//! other version this toolchain accepts, maps every `var<storage>` to read only
//! and rejects any store to it at validation time, so a compute kernel that
//! writes results cannot be expressed in it at all.

use crate::error::VulkanError;

/// The WGSL source for the MD5 kernel.
pub const WGSL_MD5: &str = include_str!("../shaders/md5.wgsl");

/// Kernels this build can dispatch to.
pub fn available_kernels() -> &'static [&'static str] {
    &["md5"]
}

/// Returns the WGSL source for a kernel by name.
pub fn wgsl_for(name: &str) -> Result<&'static str, VulkanError> {
    match name {
        "md5" => Ok(WGSL_MD5),
        other => Err(VulkanError::UnknownKernel(other.to_string())),
    }
}

/// Compiles WGSL to SPIR-V words for a compute entry point.
#[cfg(feature = "vulkan")]
pub fn wgsl_to_spirv(source: &str, entry_point: &str) -> Result<Vec<u32>, VulkanError> {
    let module = naga::front::wgsl::parse_str(source).map_err(|e| {
        VulkanError::ShaderCompile(format!("WGSL parse error:\n{}", e.emit_to_string(source)))
    })?;

    // Validate before emitting. Emitting invalid IR produces a module the driver
    // rejects at pipeline creation, which is a much later and much less
    // informative failure than catching it here with the IR's own span
    // information attached.
    let info = naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::all(),
    )
    .validate(&module)
    .map_err(|e| VulkanError::ShaderCompile(format!("WGSL validation error: {e:?}")))?;

    let options = naga::back::spv::Options::default();
    let pipeline_options = naga::back::spv::PipelineOptions {
        shader_stage: naga::ShaderStage::Compute,
        entry_point: entry_point.to_string(),
    };

    naga::back::spv::write_vec(&module, &info, &options, Some(&pipeline_options))
        .map_err(|e| VulkanError::ShaderCompile(format!("SPIR-V emission failed: {e:?}")))
}

/// Without the `vulkan` feature there is no compiler in the build.
///
/// Reported as a distinct error so a caller can say "this build has no shader
/// compiler" rather than "your shader is broken".
#[cfg(not(feature = "vulkan"))]
pub fn wgsl_to_spirv(_source: &str, _entry_point: &str) -> Result<Vec<u32>, VulkanError> {
    Err(VulkanError::FeatureDisabled)
}

/// Converts SPIR-V bytes to words.
///
/// SPIR-V is little endian by specification, so this is an explicit conversion
/// rather than `from_ne_bytes`, which would only be correct by coincidence of
/// the host.
pub fn spirv_from_bytes(bytes: &[u8]) -> Result<Vec<u32>, VulkanError> {
    if bytes.len() % 4 != 0 {
        return Err(VulkanError::ShaderCompile(format!(
            "SPIR-V blob size {} is not a multiple of 4",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// The magic number every SPIR-V module starts with.
pub const SPIRV_MAGIC: u32 = 0x0723_0203;

/// Checks that a word vector really is a SPIR-V module.
///
/// Cheap, and it catches the one mistake that has no useful error message
/// otherwise: emitting byte swapped words, which the driver rejects with
/// something about an unrecognised header.
pub fn validate_spirv(words: &[u32]) -> Result<(), VulkanError> {
    match words.first() {
        None => Err(VulkanError::ShaderCompile("SPIR-V module is empty".into())),
        Some(&m) if m == SPIRV_MAGIC => Ok(()),
        Some(&m) if m.swap_bytes() == SPIRV_MAGIC => Err(VulkanError::ShaderCompile(
            format!("SPIR-V words are byte swapped, magic 0x{m:08x}"),
        )),
        Some(&m) => Err(VulkanError::ShaderCompile(format!(
            "not a SPIR-V module, magic 0x{m:08x} instead of 0x{SPIRV_MAGIC:08x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_source_is_present() {
        assert!(WGSL_MD5.len() > 2000);
        assert!(WGSL_MD5.contains("fn main"), "entry point missing");
        assert_eq!(available_kernels(), &["md5"]);
    }

    #[test]
    fn unknown_kernel_is_reported() {
        match wgsl_for("sha1") {
            Err(VulkanError::UnknownKernel(n)) => assert_eq!(n, "sha1"),
            other => panic!("expected UnknownKernel, got {other:?}"),
        }
    }

    #[test]
    fn spirv_conversion_is_little_endian_regardless_of_host() {
        // Bytes for 0x07230203 in specification order.
        let bytes = [0x03u8, 0x02, 0x23, 0x07];
        assert_eq!(spirv_from_bytes(&bytes).unwrap(), vec![0x0723_0203]);
        assert!(validate_spirv(&[0x0723_0203]).is_ok());
    }

    #[test]
    fn byte_swapped_magic_is_named_as_such() {
        let err = validate_spirv(&[0x0302_2307]).unwrap_err();
        assert!(
            err.to_string().contains("byte swapped"),
            "expected a byte swapped diagnosis, got: {err}"
        );
    }

    #[test]
    fn garbage_magic_is_rejected() {
        assert!(validate_spirv(&[0xdead_beef]).is_err());
        assert!(validate_spirv(&[]).is_err());
    }

    #[test]
    fn non_multiple_of_four_is_rejected() {
        assert!(spirv_from_bytes(&[1, 2, 3]).is_err());
    }

    #[cfg(feature = "vulkan")]
    #[test]
    fn md5_compiles_to_a_real_module() {
        let words = wgsl_to_spirv(WGSL_MD5, "main").expect("compile");
        assert!(words.len() > 100, "module is too small to be real");
        validate_spirv(&words).expect("valid module");
    }

    /// The output buffer must be declared writable.
    ///
    /// This is the check that naga 26 fails. It maps `var<storage, read_write>` to
    /// read only, and validation then rejects every store with
    /// `InvalidStorePointer`, which surfaced here as a shader that parsed fine and
    /// could not be used at all.
    #[cfg(feature = "vulkan")]
    #[test]
    fn output_buffer_is_declared_writable() {
        assert!(
            WGSL_MD5.contains("var<storage, read_write> out"),
            "the output binding must be declared read_write"
        );
        assert!(
            !WGSL_MD5.contains("var<storage> out"),
            "the output binding has no access mode, which reads as load only"
        );
    }

    /// The tables must be transcribed, not derived.
    ///
    /// Every previous GPU kernel in this repository derived at least one schedule
    /// from a formula and got it wrong after the first entry.
    #[cfg(feature = "vulkan")]
    #[test]
    fn tables_are_present_in_full() {
        assert!(WGSL_MD5.contains("0xd76aa478"), "first MD5 constant missing");
        assert!(WGSL_MD5.contains("0xeb86d391"), "last MD5 constant missing");
        assert!(WGSL_MD5.contains("const G: array<u32, 64>"), "word order table missing");
        assert!(WGSL_MD5.contains("const S: array<u32, 64>"), "rotation table missing");
    }

    /// No hardcoded digest may appear in the shader.
    #[cfg(feature = "vulkan")]
    #[test]
    fn no_digest_is_hardcoded() {
        assert!(
            !WGSL_MD5.contains("5d41402abc4b2a76b9719d911017c592"),
            "a digest appears in the shader source"
        );
        assert!(
            !WGSL_MD5.contains("900150983cd24fb0d6963f7d28e17f72"),
            "a digest appears in the shader source"
        );
    }
}