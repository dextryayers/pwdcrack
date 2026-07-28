pub struct RiscvVector {
    available: bool,
    vlen: usize,
    has_v: bool,
    has_zve32x: bool,
    has_zve64x: bool,
}

impl RiscvVector {
    pub fn new() -> Self {
        Self {
            available: false,
            vlen: 128,
            has_v: false,
            has_zve32x: false,
            has_zve64x: false,
        }
    }

    pub fn detect() -> Self {
        let mut eng = Self::new();
        #[cfg(target_arch = "riscv64")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
                if contents.contains("rv64") || contents.contains("riscv") {
                    eng.has_v = true;
                    eng.available = true;
                    if contents.contains("vlen") {
                        for line in contents.lines() {
                            if line.contains("vlen") {
                                if let Some(val) = line.split(':').nth(1) {
                                    if let Ok(v) = val.trim().parse::<usize>() {
                                        eng.vlen = v;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        eng
    }

    pub fn is_available(&self) -> bool { self.available }

    pub fn vlen(&self) -> usize { self.vlen }

    pub fn vector_add(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        a.iter().zip(b.iter()).map(|(x, y)| x.wrapping_add(*y)).collect()
    }

    pub fn vector_xor(&self, a: &[u32], b: &[u32]) -> Vec<u32> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    pub fn vector_rotate_left(&self, a: &[u32], shift: u32) -> Vec<u32> {
        a.iter().map(|x| x.rotate_left(shift)).collect()
    }
}
