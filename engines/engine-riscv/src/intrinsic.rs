pub struct RiscvIntrinsic {
    available: bool,
    has_zbb: bool,
    has_zbkb: bool,
    has_zbkc: bool,
    has_zbkx: bool,
}

impl RiscvIntrinsic {
    pub fn new() -> Self {
        Self {
            available: false,
            has_zbb: false,
            has_zbkb: false,
            has_zbkc: false,
            has_zbkx: false,
        }
    }

    pub fn detect() -> Self {
        let mut eng = Self::new();
        #[cfg(target_arch = "riscv64")]
        {
            if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
                if contents.contains("zbb") { eng.has_zbb = true; }
                if contents.contains("zbkb") { eng.has_zbkb = true; }
                if contents.contains("zbkc") { eng.has_zbkc = true; }
                if contents.contains("zbkx") { eng.has_zbkx = true; }
                if eng.has_zbb || eng.has_zbkb {
                    eng.available = true;
                }
            }
        }
        eng
    }

    pub fn is_available(&self) -> bool { self.available }

    pub fn has_bitmanip(&self) -> bool { self.has_zbb }

    pub fn has_crypto(&self) -> bool { self.has_zbkb || self.has_zbkc }

    pub fn grev(&self, rs1: u32, rs2: u32) -> u32 {
        let mut result = rs1;
        for i in 0..32 {
            if (rs2 >> i) & 1 != 0 {
                let x = result;
                let y = x.rotate_right(i);
                result = x.wrapping_add(y);
            }
        }
        result
    }
}
