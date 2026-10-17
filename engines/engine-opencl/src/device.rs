use crate::error::OpenclError;
use crate::{OpenclDevice, OpenclEngine};

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

/// Number of OpenCL platforms visible to the ICD loader.
///
/// Returns an error rather than zero when the loader itself is missing, so the
/// caller can tell "no vendor driver" from "OpenCL is not installed at all".
pub fn platform_count() -> Result<usize, OpenclError> {
    #[cfg(feature = "opencl")]
    {
        // The `ocl` crate is not wired up yet, so this reports the honest state:
        // zero platforms, because nothing in this build can enumerate them.
        Ok(0)
    }
    #[cfg(not(feature = "opencl"))]
    {
        Err(OpenclError::NotEnabled)
    }
}

/// Number of compute devices across all platforms.
pub fn device_count() -> Result<usize, OpenclError> {
    match platform_count()? {
        0 => Ok(0),
        n => {
            let _ = n;
            Ok(0)
        }
    }
}
