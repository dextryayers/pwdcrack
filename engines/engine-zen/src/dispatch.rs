use crate::arch::ZenArch;

pub enum DispatchLevel {
    Scalar,
    Sse2,
    Avx2,
    Avx512,
}

pub struct ZenDispatch {
    pub level: DispatchLevel,
    pub num_threads: usize,
}

impl ZenDispatch {
    pub fn new(arch: &ZenArch) -> Self {
        let level = if arch.supports_avx512() {
            DispatchLevel::Avx512
        } else if arch.supports_avx2() {
            DispatchLevel::Avx2
        } else {
            DispatchLevel::Sse2
        };
        Self {
            level,
            num_threads: arch.cores as usize,
        }
    }

    pub fn level_name(&self) -> &str {
        match self.level {
            DispatchLevel::Scalar => "scalar",
            DispatchLevel::Sse2 => "SSE2",
            DispatchLevel::Avx2 => "AVX2",
            DispatchLevel::Avx512 => "AVX-512",
        }
    }

    pub fn dispatch_md5(&self, data: &[u8]) -> Vec<u8> {
        let _ = data;
        vec![]
    }

    pub fn dispatch_sha256(&self, data: &[u8]) -> Vec<u8> {
        let _ = data;
        vec![]
    }
}
