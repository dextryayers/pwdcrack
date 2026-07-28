pub struct NeonEngine {
    available: bool,
    has_neon: bool,
    has_sve: bool,
    vector_len: usize,
}

impl NeonEngine {
    pub fn new() -> Self {
        Self {
            available: false,
            has_neon: false,
            has_sve: false,
            vector_len: 16,
        }
    }

    pub fn detect() -> Self {
        let mut eng = Self::new();
        #[cfg(target_arch = "aarch64")]
        {
            eng.has_neon = true;
            eng.available = true;
            eng.vector_len = 16;
            if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
                if contents.contains("SVE") {
                    eng.has_sve = true;
                    eng.vector_len = 32;
                }
            }
        }
        eng
    }

    pub fn is_available(&self) -> bool { self.available }

    pub fn hash_parallel(&self, data: &[u8]) -> Vec<u8> {
        let mut results = Vec::with_capacity(data.len());
        for chunk in data.chunks(self.vector_len) {
            let mut buf = [0u8; 32];
            let len = chunk.len().min(32);
            buf[..len].copy_from_slice(chunk);
            results.extend_from_slice(&buf[..len]);
        }
        results
    }
}
