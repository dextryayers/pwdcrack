use crate::{CudaEngine, error::CudaError, kernel};

pub struct CudaCracker {
    engine: CudaEngine,
    batch_size: u32,
}

impl CudaCracker {
    pub fn new(engine: CudaEngine) -> Self {
        CudaCracker { engine, batch_size: 1024 }
    }

    pub fn crack_md5(&self, candidates: &[u8], target_hex: &str) -> Result<Vec<bool>, CudaError> {
        let _ = (candidates, target_hex);
        #[cfg(feature = "cuda")] {
            let ptx = kernel::compile_kernel(kernel::KERNEL_MD5, "md5_verify", "sm_75")?;
            let _ = ptx;
            // CUDA launch would use cudarc here
        }
        Err(CudaError::NoCudaSupport)
    }

    pub fn crack_sha1(&self, candidates: &[u8], target_hex: &str) -> Result<Vec<bool>, CudaError> {
        let _ = (candidates, target_hex);
        Err(CudaError::NoCudaSupport)
    }

    pub fn engine(&self) -> &CudaEngine { &self.engine }
}
