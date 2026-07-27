//! engine-gpu — GPU-accelerated hash cracking via wgpu (Vulkan/Metal/DX12)
//!
//! Features:
//! - Multiple GPU support (split keyspace across GPUs)
//! - Integrated GPU (iGPU) and discrete GPU (dGPU) support
//! - Graceful fallback: no GPU → CPU
//! - Async buffer management (pinned memory)
//! - Compute shaders: MD5, SHA1, SHA256, NTLM, bcrypt

pub mod device;
pub mod pipeline;
pub mod buffer;
pub mod error;

use std::sync::Arc;
use wgpu::*;

pub struct GpuEngine {
    pub device: Arc<Device>,
    pub queue: Arc<Queue>,
    pub adapter: AdapterInfo,
    pub is_integrated: bool,
}

impl GpuEngine {
    /// Initialize GPU engine. Returns None if no GPU available.
    pub async fn init() -> Option<Self> {
        device::init_gpu().await
    }

    /// Get GPU info string
    pub fn info(&self) -> String {
        format!(
            "{} ({}) — {} VRAM",
            self.adapter.name,
            if self.is_integrated { "iGPU" } else { "dGPU" },
            self.adapter.vram_mb(),
        )
    }
}

/// Adapter information
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub driver: String,
    pub backend: Backend,
    pub device_type: DeviceType,
}

impl AdapterInfo {
    pub fn vram_mb(&self) -> u64 {
        // wgpu doesn't expose VRAM directly in stable API
        // Estimated from device type
        match self.device_type {
            DeviceType::DiscreteGpu => 8192,
            DeviceType::IntegratedGpu => 512,
            _ => 128,
        }
    }
}
