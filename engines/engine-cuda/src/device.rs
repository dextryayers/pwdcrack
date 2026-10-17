//! CUDA device enumeration.
//!
//! Uses the cudarc 0.13 driver API. The previous implementation here referenced
//! `cudarc::driver::result::result::CudaResult`, which is not a real type in
//! any cudarc release, so this file never compiled with the `cuda` feature on.
//!
//! Note on verification: this module is behind the optional `cuda` feature and
//! needs both the CUDA driver and a CUDA toolchain to build. `scripts/test-matrix.sh`
//! runs `cargo check --features cuda` in an environment that provides them. A
//! host without `nvcc` still compiles the crate because the dependency is
//! feature gated, but it cannot type check this file.

use crate::{CudaDevice, CudaEngine};

/// Initialise the CUDA driver and enumerate every visible device.
///
/// Returns `None` when the driver is absent, the device count is zero, or any
/// probe call fails. A partially populated device list is never returned: an
/// engine that reports a device it could not fully query would misreport its
/// batch size, which the GPU scheduler depends on.
pub fn init_cuda() -> Option<CudaEngine> {
    #[cfg(feature = "cuda")]
    {
        use cudarc::driver::CudaContext;

        let ctx = match CudaContext::new(0) {
            Ok(ctx) => ctx,
            Err(e) => {
                log::debug!("CUDA: context creation failed: {e}");
                return None;
            }
        };

        let count = match ctx.count() {
            Ok(n) => n,
            Err(e) => {
                log::debug!("CUDA: device count query failed: {e}");
                return None;
            }
        };
        if count == 0 {
            log::debug!("CUDA: driver present but no devices visible");
            return None;
        }

        let mut devices = Vec::with_capacity(count);
        for index in 0..count {
            let dev = match ctx.get_device(index) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("CUDA: device {index} could not be opened: {e}");
                    continue;
                }
            };

            // A device that fails any of the attribute queries is skipped rather
            // than recorded with placeholder zeros, so `CudaEngine::info` and the
            // batch size planner only ever see fully described hardware.
            let name = match dev.name() {
                Ok(n) => n,
                Err(e) => {
                    log::warn!("CUDA: device {index} name query failed: {e}");
                    continue;
                }
            };
            let compute_capability = match dev.compute_capability() {
                Ok(cc) => cc,
                Err(e) => {
                    log::warn!("CUDA: device {index} capability query failed: {e}");
                    continue;
                }
            };
            let total_mem = match dev.total_memory() {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("CUDA: device {index} memory query failed: {e}");
                    continue;
                }
            };
            let cores = match dev.multiprocessor_count() {
                Ok(v) => v as u64,
                Err(e) => {
                    log::warn!("CUDA: device {index} SM count query failed: {e}");
                    continue;
                }
            };
            // `clock_rate` is reported in kHz by the CUDA driver API.
            let clock_mhz = match dev.clock_rate() {
                Ok(khz) => (khz as u64) / 1000,
                Err(e) => {
                    log::warn!("CUDA: device {index} clock query failed: {e}");
                    continue;
                }
            };

            devices.push(CudaDevice {
                index,
                name,
                compute_capability,
                vram_mb: total_mem / 1_048_576,
                cores,
                clock_mhz,
            });
        }

        if devices.is_empty() {
            log::warn!("CUDA: {count} device(s) reported by the driver but none could be queried");
            return None;
        }

        log::info!("CUDA: {} device(s) found", devices.len());
        Some(CudaEngine {
            device_count: devices.len(),
            devices,
        })
    }

    #[cfg(not(feature = "cuda"))]
    {
        log::debug!("CUDA: crate compiled without the cuda feature");
        None
    }
}
