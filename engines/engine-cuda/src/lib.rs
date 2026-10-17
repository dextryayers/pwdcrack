pub mod device;
pub mod kernel;
pub mod cracker;
pub mod error;
pub mod scheduler;

use std::sync::Arc;
use log;

pub struct CudaEngine {
    pub device_count: usize,
    pub devices: Vec<CudaDevice>,
}

pub struct CudaDevice {
    pub index: usize,
    pub name: String,
    pub compute_capability: (u32, u32),
    pub vram_mb: u64,
    pub cores: u64,
    pub clock_mhz: u64,
}

impl CudaEngine {
    pub fn init() -> Option<Self> {
        device::init_cuda()
    }

    /// Whether this build carries CUDA kernels.
    ///
    /// False when the binary was produced with `PW_CUDA_ALLOW_NO_NVCC=1`, which
    /// compiles the GPU path out rather than failing the build. Reported
    /// separately from "is there a device" because the two are different problems
    /// with different fixes, and a user seeing only "CUDA unavailable" cannot
    /// tell which one they have.
    pub fn kernels_embedded() -> bool {
        kernel::kernels_embedded()
    }

    pub fn info(&self) -> String {
        let mut s = String::new();
        for dev in &self.devices {
            s.push_str(&format!(
                "CUDA[{}]: {} (CC {}.{}, {} MB VRAM, {} cores @ {} MHz)\n",
                dev.index, dev.name, dev.compute_capability.0,
                dev.compute_capability.1, dev.vram_mb, dev.cores, dev.clock_mhz,
            ));
        }
        s.trim_end().to_string()
    }
}

#[cfg(feature = "cuda")]
pub fn compile_ptx(src: &str, arch: &str) -> Result<Vec<u8>, error::CudaError> {
    use std::process::Command;
    let tmp = std::env::temp_dir().join(format!("pwdcrack_cuda_{}.cu", std::process::id()));
    std::fs::write(&tmp, src)?;
    let out = tmp.with_extension("ptx");
    let status = Command::new("nvcc")
        .args([
            "--ptx", "-o", &out.to_string_lossy(),
            &tmp.to_string_lossy(),
        ])
        .status().map_err(|e| error::CudaError::CompileFailed(e.to_string()))?;
    if !status.success() {
        return Err(error::CudaError::CompileFailed("nvcc failed".into()));
    }
    let ptx = std::fs::read(&out)?;
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&out);
    Ok(ptx)
}
