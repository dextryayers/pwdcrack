pub mod device;
pub mod cracker;
pub mod error;

use log;

pub struct SyclEngine {
    pub platform_name: String,
    pub device_count: usize,
    pub devices: Vec<SyclDevice>,
}

pub struct SyclDevice {
    pub index: usize,
    pub name: String,
    pub vendor: String,
    pub vram_mb: u64,
    pub compute_units: u64,
    pub device_type: String,
}

impl SyclEngine {
    pub fn init() -> Option<Self> {
        device::init_sycl()
    }
    pub fn info(&self) -> String {
        let mut s = format!("SYCL Platform: {}\n", self.platform_name);
        for dev in &self.devices {
            s.push_str(&format!(
                "  SYCL[{}]: {} ({}) — {} CU\n",
                dev.index, dev.name, dev.device_type, dev.compute_units,
            ));
        }
        s.trim_end().to_string()
    }
}
