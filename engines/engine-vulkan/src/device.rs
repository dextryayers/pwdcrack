use crate::{VulkanEngine, VulkanDevice};

pub fn init_vulkan() -> Option<VulkanEngine> {
    #[cfg(feature = "vulkan")] {
        unsafe {
            let entry = ash::Entry::linked();
            match entry.enumerate_instance_version() {
                Ok(Some(version)) => {
                    let app_info = ash::vk::ApplicationInfo::default()
                        .api_version(version);
                    let create_info = ash::vk::InstanceCreateInfo::default()
                        .application_info(&app_info);
                    match entry.create_instance(&create_info, None) {
                        Ok(instance) => {
                            let phys_devices = instance.enumerate_physical_devices().ok()?;
                            let mut devices = Vec::new();
                            for (i, pd) in phys_devices.iter().enumerate() {
                                let props = instance.get_physical_device_properties(*pd);
                                let name = std::ffi::CStr::from_ptr(props.device_name.as_ptr())
                                    .to_string_lossy().to_string();
                                let heap_count = props.memory_properties.memory_heap_count as usize;
                                let vram = if heap_count > 0 {
                                    props.memory_properties.memory_heaps[0].size / 1_048_576
                                } else { 0 };
                                let dtype = match props.device_type {
                                    ash::vk::PhysicalDeviceType::DISCRETE_GPU => "dGPU",
                                    ash::vk::PhysicalDeviceType::INTEGRATED_GPU => "iGPU",
                                    ash::vk::PhysicalDeviceType::VIRTUAL_GPU => "vGPU",
                                    ash::vk::PhysicalDeviceType::CPU => "CPU",
                                    _ => "Other",
                                };
                                devices.push(VulkanDevice {
                                    index: i, name,
                                    vram_mb: vram,
                                    api_version: props.api_version,
                                    device_type: dtype.to_string(),
                                });
                            }
                            let _ = instance;
                            log::info!("Vulkan: {} device(s)", devices.len());
                            Some(VulkanEngine { device_count: devices.len(), devices })
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            }
        }
    }
    #[cfg(not(feature = "vulkan"))] { None }
}
