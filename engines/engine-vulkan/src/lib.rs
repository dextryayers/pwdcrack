pub mod device;
pub mod shader;
pub mod cracker;
pub mod error;
pub mod kernel;

pub use kernel::run_device_check;

#[cfg(feature = "vulkan")]
pub use kernel::measure_throughput;

#[allow(unused_imports)]
use log;

#[cfg(feature = "vulkan")]
use device::VulkanDeviceLimits;

/// A Vulkan engine handle.
///
/// Under the `vulkan` feature the entry point and instance are owned here and
/// kept alive for the engine's lifetime. Vulkan requires the instance for every
/// later call, so dropping it after enumeration, as the previous version of this
/// file did, leaves nothing to dispatch with.
pub struct VulkanEngine {
    pub device_count: usize,
    pub devices: Vec<VulkanDevice>,
    /// Kept alive for the engine's lifetime. Every later Vulkan call needs the
    /// instance, so dropping it after enumeration would leave nothing to dispatch
    /// with. Read by the compute path in `kernel`.
    #[cfg(feature = "vulkan")]
    #[allow(dead_code)]
    pub(crate) entry: ash::Entry,
    #[cfg(feature = "vulkan")]
    #[allow(dead_code)]
    pub(crate) instance: ash::Instance,
}

pub struct VulkanDevice {
    pub index: usize,
    /// Opaque `VkPhysicalDevice` handle. Retained so a dispatch can be targeted at
    /// this specific device rather than whichever one happens to be first.
    #[cfg(feature = "vulkan")]
    #[allow(dead_code)]
    pub(crate) handle: ash::vk::PhysicalDevice,
    pub name: String,
    pub vram_mb: u64,
    pub api_version: u32,
    pub device_type: String,
    /// Queried limits, used for batch sizing. Never defaulted to constants.
    #[cfg(feature = "vulkan")]
    pub limits: VulkanDeviceLimits,
}

impl VulkanEngine {
    pub fn init() -> Option<Self> {
        device::init_vulkan()
    }

    /// Whether this build carries the Vulkan API at all.
    ///
    /// False without the `vulkan` feature. Reported separately from "no device",
    /// because a binary with no Vulkan support and a machine with no GPU are
    /// different problems with different fixes.
    pub fn api_available() -> bool {
        cfg!(feature = "vulkan")
    }

    pub fn info(&self) -> String {
        let mut s = String::new();
        if !Self::api_available() {
            return "Vulkan: not compiled in (enable the 'vulkan' feature)\n".to_string();
        }
        if self.devices.is_empty() {
            return "Vulkan: no device found\n".to_string();
        }
        for dev in &self.devices {
            s.push_str(&format!(
                "Vulkan[{}]: {} ({}), {} MB, API {}.{}.{}\n",
                dev.index,
                dev.name,
                dev.device_type,
                dev.vram_mb,
                (dev.api_version >> 22) & 0x7f,
                (dev.api_version >> 12) & 0x3ff,
                (dev.api_version >> 0) & 0xfff,
            ));
            #[cfg(feature = "vulkan")]
            s.push_str(&format!(
                "  limits: {} invocations/workgroup, {} workgroups/dispatch, \
                 {} MiB storage buffer\n",
                dev.limits.max_work_group_invocations,
                dev.limits.max_work_group_count,
                dev.limits.max_storage_buffer_range / 1_048_576,
            ));
        }
        s.trim_end().to_string()
    }
}