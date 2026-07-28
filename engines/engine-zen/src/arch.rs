pub struct ZenArch {
    pub family: String,
    pub model: String,
    pub steppings: u32,
    pub cores: u32,
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_vaes: bool,
    pub has_vpclmulqdq: bool,
}

impl ZenArch {
    pub fn new() -> Self {
        Self {
            family: "Unknown".into(),
            model: "Unknown".into(),
            steppings: 0,
            cores: num_cpus::get() as u32,
            has_avx2: false,
            has_avx512: false,
            has_vaes: false,
            has_vpclmulqdq: false,
        }
    }

    pub fn detect() -> Self {
        let mut arch = Self::new();
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in info.lines() {
                if line.starts_with("vendor_id") && line.contains("AuthenticAMD") {
                    arch.family = "AMD".into();
                }
                if line.starts_with("model name") {
                    arch.model = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
                if line.starts_with("flags") || line.starts_with("Features") {
                    arch.has_avx2 = line.contains("avx2");
                    arch.has_avx512 = line.contains("avx512f");
                    arch.has_vaes = line.contains("vaes");
                    arch.has_vpclmulqdq = line.contains("vpclmulqdq");
                }
                if line.starts_with("cpu cores") {
                    if let Ok(c) = line.split(':').nth(1).unwrap_or("").trim().parse::<u32>() {
                        arch.cores = c;
                    }
                }
            }
            if arch.family == "Unknown" && info.contains("GenuineIntel") {
                arch.family = "Intel".into();
            }
        }
        arch
    }

    pub fn supports_avx2(&self) -> bool { self.has_avx2 }

    pub fn supports_avx512(&self) -> bool { self.has_avx512 }

    pub fn description(&self) -> String {
        format!("{} {} ({} cores, AVX2: {}, AVX-512: {})",
            self.family, self.model, self.cores, self.has_avx2, self.has_avx512)
    }
}
