pub struct MveEngine {
    available: bool,
    has_mve: bool,
    has_mve_fp: bool,
}

impl MveEngine {
    pub fn new() -> Self {
        Self { available: false, has_mve: false, has_mve_fp: false }
    }

    pub fn detect() -> Self {
        let mut eng = Self::new();
        #[cfg(target_arch = "arm")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
                if contents.contains("MVE") {
                    eng.has_mve = true;
                    eng.available = true;
                }
                if contents.contains("MVE_FP") {
                    eng.has_mve_fp = true;
                }
            }
        }
        eng
    }

    pub fn is_available(&self) -> bool { self.available }

    pub fn vector_add(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        a.iter().zip(b.iter()).map(|(x, y)| x.wrapping_add(*y)).collect()
    }

    pub fn vector_xor(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }
}
