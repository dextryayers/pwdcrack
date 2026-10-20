pub mod cracker;
pub mod device;
pub mod pipeline;
pub mod buffer;
pub mod error;
pub mod scheduler;

mod hw;

use std::sync::Arc;
use wgpu::*;

pub struct GpuEngine {
    pub device: Arc<Device>,
    pub queue: Arc<Queue>,
    pub adapter: AdapterInfo,
    pub is_integrated: bool,
    /// Set by the device-lost callback. A lost device cannot be used again; the
    /// flag lets callers stop submitting and fall back without a failed wait per
    /// batch.
    lost: Arc<std::sync::atomic::AtomicBool>,
}

impl GpuEngine {
    pub async fn init() -> Option<Self> {
        device::init_gpu().await
    }

    /// Initialises the engine from synchronous code.
    ///
    /// The core crate used to call `pollster::block_on` itself, which meant the
    /// `engine-gpu` feature also had to add `pollster` to the root manifest. The
    /// runtime dependency belongs here, with the only crate that owns a device.
    pub fn init_blocking() -> Option<Self> {
        pollster::block_on(Self::init())
    }

    pub fn info(&self) -> String {
        let base = format!(
            "{} ({}): {}",
            self.adapter.name,
            if self.is_integrated { "iGPU" } else { "dGPU" },
            self.adapter.memory_summary(),
        );
        if self.is_lost() {
            format!("{base} (device lost)")
        } else {
            base
        }
    }

    /// Whether the backend has reported that the device was lost.
    pub fn is_lost(&self) -> bool {
        self.lost.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn submit(&self, encoder: CommandEncoder) {
        self.queue.submit(std::iter::once(encoder.finish()));
    }

    pub fn wait(&self) {
        // wgpu tracks submissions internally. Work completes when the device is
        // polled, which `GpuCracker::dispatch_batch` does before reading back.
    }
}

#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub driver: String,
    pub backend: Backend,
    pub device_type: DeviceType,
    /// PCI vendor id reported by the backend, or 0 when it reports none.
    pub vendor: u32,
    /// PCI device id reported by the backend, or 0 when it reports none.
    pub device: u32,
    /// Dedicated video memory in bytes, read from the kernel. `None` when the
    /// platform or the driver does not report it.
    pub vram_bytes: Option<u64>,
    /// System memory the GPU can address, in bytes, read from the kernel.
    pub gtt_bytes: Option<u64>,
}

impl AdapterInfo {
    /// Dedicated video memory in mebibytes, or `None` when it is not known.
    ///
    /// An earlier version of this method returned 8192, 512 or 128 depending on
    /// the device type. Those values were invented here, not read from the
    /// hardware, and are the reason this returns an `Option` now: an unknown size
    /// has to be able to say so.
    pub fn vram_mb(&self) -> Option<u64> {
        self.vram_bytes.map(|b| b / (1024 * 1024))
    }

    /// System memory the GPU can address, in mebibytes, or `None`.
    pub fn gtt_mb(&self) -> Option<u64> {
        self.gtt_bytes.map(|b| b / (1024 * 1024))
    }

    /// One line describing the memory the kernel reports.
    ///
    /// Unknown sizes are printed as `unknown` rather than left out, so a log line
    /// that omits a number is never mistaken for a complete report.
    pub fn memory_summary(&self) -> String {
        let vram = match self.vram_mb() {
            Some(m) => format!("{m} MiB dedicated"),
            None => "dedicated memory unknown".to_string(),
        };
        match self.gtt_mb() {
            Some(m) => format!("{vram}, {m} MiB shared"),
            None => vram,
        }
    }
}
