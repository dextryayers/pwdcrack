//! GPU device initialization and selection

use std::sync::Arc;
use wgpu::*;
use crate::{GpuEngine, AdapterInfo, hw};

/// Builds the instance every adapter query starts from.
///
/// `Instance::new` takes the descriptor by reference in wgpu 26. The display
/// handle and the experimental feature flags that wgpu 30 carries do not exist in
/// this version.
fn new_instance() -> Instance {
    Instance::new(&InstanceDescriptor {
        backends: Backends::all(),
        flags: InstanceFlags::default(),
        memory_budget_thresholds: MemoryBudgetThresholds::default(),
        backend_options: BackendOptions::default(),
    })
}

/// Initialize GPU: picks the best available adapter
pub async fn init_gpu() -> Option<GpuEngine> {
    let instance = new_instance();

    let adapter = instance.request_adapter(&RequestAdapterOptions {
        power_preference: PowerPreference::HighPerformance,
        compatible_surface: None,
        force_fallback_adapter: false,
    }).await.ok()?;

    let adapter_info = adapter.get_info();

    // No feature is required. The previous version demanded
    // `Features::TIMESTAMP_QUERY`, which no code here uses and which a software
    // adapter can refuse, turning a working device into "no GPU".
    let (device, queue) = adapter.request_device(&DeviceDescriptor {
        label: Some("pwdcrack GPU device"),
        required_features: Features::empty(),
        required_limits: Limits::default(),
        memory_hints: MemoryHints::Performance,
        trace: Trace::Off,
    }).await.ok()?;

    let is_integrated = matches!(adapter_info.device_type, DeviceType::IntegratedGpu);

    // The backend reports PCI ids on Vulkan and Metal, but gives zero on some
    // platforms. `memory_bytes` returns `None` for both sizes when no DRM card
    // matches, which is the honest answer.
    let memory = hw::memory_bytes(adapter_info.vendor, adapter_info.device);
    let info = AdapterInfo {
        name: adapter_info.name,
        driver: adapter_info.driver,
        backend: adapter_info.backend,
        device_type: adapter_info.device_type,
        vendor: adapter_info.vendor,
        device: adapter_info.device,
        vram_bytes: memory.vram,
        gtt_bytes: memory.gtt,
    };

    log::info!(
        "GPU: {} ({}, {:?}), {}",
        info.name,
        if is_integrated { "iGPU" } else { "dGPU" },
        info.backend,
        info.memory_summary(),
    );

    let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let lost = Arc::clone(&lost);
        device.set_device_lost_callback(move |reason, message| {
            lost.store(true, std::sync::atomic::Ordering::Relaxed);
            log::error!("GPU: device lost ({reason:?}): {message}");
        });
    }

    Some(GpuEngine {
        device: Arc::new(device),
        queue: Arc::new(queue),
        adapter: info,
        is_integrated,
        lost,
    })
}

/// Enumerate all available GPU adapters
pub async fn enumerate_adapters() -> Vec<(String, Backend, DeviceType)> {
    let instance = new_instance();

    // `enumerate_adapters` became synchronous in wgpu 26.
    instance.enumerate_adapters(Backends::all())
        .into_iter()
        .map(|adapter| {
            let info = adapter.get_info();
            (info.name, info.backend, info.device_type)
        })
        .collect()
}
