//! GPU device initialization and selection

use std::sync::Arc;
use wgpu::*;
use crate::{GpuEngine, AdapterInfo};

/// Initialize GPU — picks the best available adapter
pub async fn init_gpu() -> Option<GpuEngine> {
    let backends = wgpu::Backends::all();

    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
        backends,
        flags: wgpu::InstanceFlags::default(),
        memory_budget_thresholds: wgpu::MemoryBudgetThresholds::default(),
        backend_options: wgpu::BackendOptions::default(),
        display: None,
    });

    let adapter = instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: PowerPreference::HighPerformance,
        compatible_surface: None,
        force_fallback_adapter: false,
        apply_limit_buckets: false,
    }).await.ok()?;

    let adapter_info = adapter.get_info();
    let (device, queue) = adapter.request_device(
        &wgpu::DeviceDescriptor {
            label: Some("pwdcrack GPU device"),
            required_features: wgpu::Features::TIMESTAMP_QUERY,
            required_limits: wgpu::Limits::default(),
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
            memory_hints: wgpu::MemoryHints::Performance,
            trace: wgpu::Trace::Off,
        },
    ).await.ok()?;

    let is_integrated = matches!(adapter_info.device_type, DeviceType::IntegratedGpu);

    log::info!(
        "GPU: {} ({} — {:?})",
        adapter_info.name,
        if is_integrated { "iGPU" } else { "dGPU" },
        adapter_info.backend,
    );

    Some(GpuEngine {
        device: Arc::new(device),
        queue: Arc::new(queue),
        adapter: AdapterInfo {
            name: adapter_info.name.clone(),
            driver: adapter_info.driver.clone(),
            backend: adapter_info.backend,
            device_type: adapter_info.device_type,
        },
        is_integrated,
    })
}

/// Enumerate all available GPU adapters
pub async fn enumerate_adapters() -> Vec<(String, Backend, DeviceType)> {
    let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
        backends: wgpu::Backends::all(),
        flags: wgpu::InstanceFlags::default(),
        memory_budget_thresholds: wgpu::MemoryBudgetThresholds::default(),
        backend_options: wgpu::BackendOptions::default(),
        display: None,
    });

    instance.enumerate_adapters(wgpu::Backends::all())
        .await
        .into_iter()
        .map(|adapter| {
            let info = adapter.get_info();
            (info.name, info.backend, info.device_type)
        })
        .collect()
}
