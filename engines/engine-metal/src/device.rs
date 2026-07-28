use std::collections::HashMap;

pub struct MetalDevice {
    pub name: String,
    pub vendor: String,
    pub compute_units: u32,
    pub max_threads_per_group: u32,
    pub has_unified_memory: bool,
    pub gpu_family: String,
}

impl MetalDevice {
    pub fn new() -> Self {
        Self {
            name: String::new(),
            vendor: String::new(),
            compute_units: 0,
            max_threads_per_group: 1024,
            has_unified_memory: false,
            gpu_family: String::new(),
        }
    }

    pub fn detect_all() -> Vec<Self> {
        let mut devices = Vec::new();
        #[cfg(target_os = "macos")]
        {
            devices.push(Self {
                name: "Apple GPU".into(),
                vendor: "Apple".into(),
                compute_units: 64,
                max_threads_per_group: 1024,
                has_unified_memory: true,
                gpu_family: "Apple9".into(),
            });
            devices.push(Self {
                name: "Intel GPU".into(),
                vendor: "Intel".into(),
                compute_units: 48,
                max_threads_per_group: 512,
                has_unified_memory: false,
                gpu_family: "Intel".into(),
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(info) = std::fs::read_to_string("/tmp/metal_devices.txt") {
                for line in info.lines() {
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 3 {
                        devices.push(Self {
                            name: parts[0].to_string(),
                            vendor: parts[1].to_string(),
                            compute_units: parts[2].parse().unwrap_or(16),
                            max_threads_per_group: 1024,
                            has_unified_memory: false,
                            gpu_family: "Generic".into(),
                        });
                    }
                }
            }
        }
        devices
    }
}
