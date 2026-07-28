use thiserror::Error;

#[derive(Error, Debug)]
pub enum VulkanError {
    #[error("No Vulkan-capable GPU found")] NoDevice,
    #[error("Failed to create Vulkan instance: {0}")] InitFailed(String),
    #[error("SPIR-V shader compilation failed: {0}")] ShaderCompile(String),
    #[error("Compute pipeline creation failed: {0}")] PipelineFailed(String),
    #[error("Vulkan out of memory")] OutOfMemory,
    #[error("Vulkan not enabled at compile time")] NotEnabled,
    #[error("Unsupported hash type")] UnsupportedHash,
}
