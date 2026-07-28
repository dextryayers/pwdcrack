use crate::error::VulkanError;

pub fn compile_glsl_to_spirv(src: &str, stage: &str) -> Result<Vec<u32>, VulkanError> {
    let _ = (src, stage);
    Err(VulkanError::ShaderCompile("glslc not available at runtime".into()))
}

pub fn spirv_from_bytes(bytes: &[u8]) -> Result<Vec<u32>, VulkanError> {
    if bytes.len() % 4 != 0 {
        return Err(VulkanError::ShaderCompile("SPIR-V blob size not multiple of 4".into()));
    }
    bytes.chunks(4).map(|c| {
        Some(u32::from_ne_bytes([c[0], c[1], c[2], c[3]]))
    }).collect::<Option<Vec<_>>>().ok_or_else(|| {
        VulkanError::ShaderCompile("Failed to parse SPIR-V bytes".into())
    })
}
