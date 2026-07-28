pub mod device;
pub mod kernel;
pub mod cracker;
pub mod error;
pub mod scheduler;

use log;

pub struct OpenclEngine {
    pub platform_name: String,
    pub device_count: usize,
    pub devices: Vec<OpenclDevice>,
}

pub struct OpenclDevice {
    pub index: usize,
    pub name: String,
    pub vendor: String,
    pub vram_mb: u64,
    pub compute_units: u64,
    pub clock_mhz: u64,
    pub device_type: String,
}

impl OpenclEngine {
    pub fn init() -> Option<Self> {
        device::init_opencl()
    }
    pub fn info(&self) -> String {
        let mut s = format!("OpenCL Platform: {}\n", self.platform_name);
        for dev in &self.devices {
            s.push_str(&format!(
                "  CL[{}]: {} ({}) — {} CU, {} MHz, {} MB VRAM\n",
                dev.index, dev.name, dev.device_type,
                dev.compute_units, dev.clock_mhz, dev.vram_mb,
            ));
        }
        s.trim_end().to_string()
    }
}

pub enum Vendor { Nvidia, Amd, Intel, Apple, Other }

impl OpenclDevice {
    pub fn vendor(&self) -> Vendor {
        let v = self.vendor.to_lowercase();
        if v.contains("nvidia") { Vendor::Nvidia }
        else if v.contains("amd") || v.contains("advanced micro") { Vendor::Amd }
        else if v.contains("intel") { Vendor::Intel }
        else if v.contains("apple") { Vendor::Apple }
        else { Vendor::Other }
    }
}
