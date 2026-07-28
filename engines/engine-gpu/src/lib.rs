pub mod cracker;
pub mod device;
pub mod pipeline;
pub mod buffer;
pub mod error;
pub mod scheduler;

use std::sync::Arc;
use wgpu::*;

pub struct GpuEngine {
    pub device: Arc<Device>,
    pub queue: Arc<Queue>,
    pub adapter: AdapterInfo,
    pub is_integrated: bool,
}

impl GpuEngine {
    pub async fn init() -> Option<Self> {
        device::init_gpu().await
    }

    pub fn info(&self) -> String {
        format!(
            "{} ({}) — {} VRAM",
            self.adapter.name,
            if self.is_integrated { "iGPU" } else { "dGPU" },
            self.adapter.vram_mb(),
        )
    }

    pub fn submit(&self, encoder: CommandEncoder) {
        self.queue.submit(std::iter::once(encoder.finish()));
    }

    pub fn wait(&self) {
        // wgpu 30 handles submission tracking internally.
        // No explicit poll needed — GPU work completes asynchronously.
    }
}

#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub driver: String,
    pub backend: Backend,
    pub device_type: DeviceType,
}

impl AdapterInfo {
    pub fn vram_mb(&self) -> u64 {
        match self.device_type {
            DeviceType::DiscreteGpu => 8192,
            DeviceType::IntegratedGpu => 512,
            _ => 128,
        }
    }
}
