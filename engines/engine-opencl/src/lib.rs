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

    /// An engine handle for a host where OpenCL enumerated nothing.
    ///
    /// `init` returns `None` in that case, which makes an empty engine awkward to
    /// pass around: callers that only want to ask "why can this not run" have no
    /// value to hand on. This constructor gives them one, with the platform name
    /// stating plainly that nothing was found rather than leaving it blank.
    pub fn unavailable() -> Self {
        OpenclEngine {
            platform_name: "none (no vendor OpenCL driver registered a platform)".to_string(),
            device_count: 0,
            devices: Vec::new(),
        }
    }

    /// Whether this handle refers to an engine with at least one usable device.
    ///
    /// Distinct from "the binary was built without the opencl feature", which is
    /// a build property rather than a host property.
    pub fn has_device(&self) -> bool {
        self.device_count > 0
    }

    pub fn info(&self) -> String {
        let mut s = format!("OpenCL Platform: {}\n", self.platform_name);
        for dev in &self.devices {
            s.push_str(&format!(
                "  CL[{}]: {} ({}): {} CU, {} MHz, {} MB VRAM\n",
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
