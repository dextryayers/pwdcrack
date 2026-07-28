use crate::{CudaEngine, CudaDevice};

pub fn init_cuda() -> Option<CudaEngine> {
    #[cfg(feature = "cuda")] {
        match cudarc::driver::result::result::CudaResult::Ok(()) {
            Ok(_) => {
                let count = cudarc::driver::result::result::CudaResult::Ok(())
                    .and_then(|_| cudarc::driver::sys::cuDeviceGetCount())
                    .unwrap_or(0);
                if count == 0 { return None; }
                let mut devices = Vec::new();
                for i in 0..count {
                    let name = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceGetName(256, i as i32))
                        .unwrap_or(Ok("Unknown".into()))
                        .unwrap_or_default();
                    let major = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceGetAttribute(
                            cudarc::driver::sys::CUdevice_attribute_enum::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, i as i32))
                        .unwrap_or(0) as u32;
                    let minor = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceGetAttribute(
                            cudarc::driver::sys::CUdevice_attribute_enum::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, i as i32))
                        .unwrap_or(0) as u32;
                    let vram = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceTotalMem(i as i32))
                        .unwrap_or(0);
                    let cores = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceGetAttribute(
                            cudarc::driver::sys::CUdevice_attribute_enum::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, i as i32))
                        .unwrap_or(0) as u64;
                    let clock = cudarc::driver::result::result::CudaResult::Ok(())
                        .and_then(|_| cudarc::driver::sys::cuDeviceGetAttribute(
                            cudarc::driver::sys::CUdevice_attribute_enum::CU_DEVICE_ATTRIBUTE_CLOCK_RATE, i as i32))
                        .unwrap_or(0) as u64;
                    devices.push(CudaDevice {
                        index: i, name, compute_capability: (major, minor),
                        vram_mb: vram / 1_048_576, cores, clock_mhz: clock / 1000,
                    });
                }
                log::info!("CUDA: {} device(s) found", devices.len());
                Some(CudaEngine { device_count: devices.len(), devices })
            }
            Err(_) => None,
        }
    }
    #[cfg(not(feature = "cuda"))] {
        let _ = log::info;
        None
    }
}
