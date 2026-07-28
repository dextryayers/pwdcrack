pub mod device;
pub mod shader;
pub mod cracker;
pub mod error;

use log;

pub struct VulkanEngine {
    pub device_count: usize,
    pub devices: Vec<VulkanDevice>,
}

pub struct VulkanDevice {
    pub index: usize,
    pub name: String,
    pub vram_mb: u64,
    pub api_version: u32,
    pub device_type: String,
}

impl VulkanEngine {
    pub fn init() -> Option<Self> {
        device::init_vulkan()
    }
    pub fn info(&self) -> String {
        let mut s = String::new();
        for dev in &self.devices {
            s.push_str(&format!(
                "VK[{}]: {} ({} MB VRAM)\n",
                dev.index, dev.name, dev.vram_mb,
            ));
        }
        s.trim_end().to_string()
    }
}
