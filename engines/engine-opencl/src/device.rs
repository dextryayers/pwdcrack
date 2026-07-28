use crate::{OpenclEngine, OpenclDevice};

pub fn init_opencl() -> Option<OpenclEngine> {
    #[cfg(feature = "opencl")]
    {
        let platform = ocl::Platform::default();
        let devices = ocl::Device::list(platform, None).ok()?;
        let platform_name = platform.name().ok()?;
        let mut devs = Vec::new();
        for (i, dev) in devices.iter().enumerate() {
            devs.push(OpenclDevice {
                index: i,
                name: dev.name().ok().unwrap_or_default(),
                vendor: dev.vendor().ok().unwrap_or_default(),
                vram_mb: dev.global_mem_size().ok().unwrap_or(0) / 1_048_576,
                compute_units: dev.max_compute_units().ok().unwrap_or(0),
                clock_mhz: dev.max_clock_frequency().ok().unwrap_or(0),
                device_type: format!("{:?}", dev.device_type().ok()),
            });
        }
        log::info!("OpenCL: {} device(s) on '{}'", devs.len(), platform_name);
        Some(OpenclEngine { platform_name, device_count: devs.len(), devices: devs })
    }
    #[cfg(not(feature = "opencl"))] { None }
}
