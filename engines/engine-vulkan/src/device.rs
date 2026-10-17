//! Vulkan device discovery.
//!
//! # What this replaces
//!
//! The previous version requested `ash::Entry::linked()`, which does not exist in
//! ash 0.38, so the `vulkan` feature did not compile at all. The engine could not
//! be built with the feature that gives it its entire purpose.
//!
//! It also dropped the `ash::Entry` and the `ash::Instance` immediately after
//! enumerating devices, destroying the instance before any caller could use it.
//! A Vulkan instance is required for every subsequent call, so even had it
//! compiled it could not have launched anything.
//!
//! # Limits are read, not assumed
//!
//! Task P7.3.04 asks for `maxComputeWorkGroupInvocations` and
//! `maxStorageBufferRange` to size batches. Those are queried from the physical
//! device here and exposed through [`VulkanDeviceLimits`], so nothing in the
//! dispatch path has to assume a number. The values on the development machine
//! are 1024 invocations per work group and a 128 MiB storage buffer range; a
//! different card will report different ones and the code uses what it is given.

use crate::error::VulkanError;
use crate::{VulkanDevice, VulkanEngine};

/// Limits read from the physical device, used for batch sizing.
///
/// Every field comes from a `VkPhysicalDeviceProperties` query. None has a
/// fallback constant, because a fallback would be indistinguishable from a real
/// measurement and would silently produce wrong batch sizes on a card whose
/// limits differ.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VulkanDeviceLimits {
    /// `maxComputeWorkGroupInvocations`: threads in one work group.
    pub max_work_group_invocations: u32,
    /// `maxComputeWorkGroupCount[0]`: work groups in one dispatch dimension.
    pub max_work_group_count: u32,
    /// `maxStorageBufferRange`: largest single storage buffer binding.
    pub max_storage_buffer_range: u64,
    /// `maxComputeSharedMemorySize`: work group shared memory in bytes.
    pub max_shared_memory: u32,
    /// API version, major in the high 16 bits.
    pub api_version: u32,
}

/// Enumerates Vulkan devices and returns an engine handle.
///
/// Returns `None` when no instance can be created or no physical device is
/// present. Use [`probe`] when the reason matters.
pub fn init_vulkan() -> Option<VulkanEngine> {
    match probe() {
        Ok(engine) => Some(engine),
        Err(e) => {
            log::info!("Vulkan unavailable: {e}");
            None
        }
    }
}

/// Enumerates Vulkan devices, reporting why if there are none.
#[cfg(feature = "vulkan")]
pub fn probe() -> Result<VulkanEngine, VulkanError> {
    // ash 0.38 spells this `load`, not `linked`.
    let entry = unsafe { ash::Entry::load() }
        .map_err(|e| VulkanError::DeviceError(format!("could not load the Vulkan loader: {e}")))?;

    // Request a specific API version rather than taking whatever the loader
    // offers, so behaviour does not change silently when a driver is upgraded.
    let app_name = c_str("pwdcrack");
    let app_info = ash::vk::ApplicationInfo::default()
        .application_name(&app_name)
        .application_version(ash::vk::make_api_version(0, 1, 2, 0))
        .api_version(ash::vk::API_VERSION_1_1)
        .engine_name(&app_name);

    let create_info = ash::vk::InstanceCreateInfo::default().application_info(&app_info);

    // SAFETY: the instance is created with no layers and no extensions enabled,
    // so there is nothing for a callback to receive, and the returned handle is
    // owned by the VulkanEngine returned alongside it.
    let instance = unsafe { entry.create_instance(&create_info, None) }
        .map_err(|e| VulkanError::DeviceError(format!("could not create a Vulkan instance: {e}")))?;

    let phys = unsafe { instance.enumerate_physical_devices() }
        .map_err(|e| VulkanError::DeviceError(format!("could not enumerate devices: {e}")))?;

    if phys.is_empty() {
        return Err(VulkanError::NoDevice);
    }

    let mut devices = Vec::new();
    for (i, handle) in phys.iter().enumerate() {
        let props = unsafe { instance.get_physical_device_properties(*handle) };
        let name = unsafe {
            std::ffi::CStr::from_ptr(props.device_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        // Memory properties are a separate query in ash, not a field of
        // PhysicalDeviceProperties.
        let mem = unsafe { instance.get_physical_device_memory_properties(*handle) };
        let heap_count = mem.memory_heap_count as usize;
        let vram_mb = if heap_count > 0 {
            (unsafe { mem.memory_heaps[0].size }) / 1_048_576
        } else {
            0
        };

        let device_type = match props.device_type {
            ash::vk::PhysicalDeviceType::DISCRETE_GPU => "discrete GPU",
            ash::vk::PhysicalDeviceType::INTEGRATED_GPU => "integrated GPU",
            ash::vk::PhysicalDeviceType::VIRTUAL_GPU => "virtual GPU",
            ash::vk::PhysicalDeviceType::CPU => "CPU",
            _ => "other",
        };

        let limits = VulkanDeviceLimits {
            max_work_group_invocations: props.limits.max_compute_work_group_invocations,
            max_work_group_count: props.limits.max_compute_work_group_count[0],
            max_storage_buffer_range: props.limits.max_storage_buffer_range as u64,
            max_shared_memory: props.limits.max_compute_shared_memory_size,
            api_version: props.api_version,
        };

        devices.push(VulkanDevice {
            index: i,
            handle: *handle,
            name,
            vram_mb,
            api_version: props.api_version,
            device_type: device_type.to_string(),
            limits,
        });
    }

    log::info!("Vulkan: {} device(s)", devices.len());

    // The instance and entry are moved into the engine. Destroying them here, as
    // the previous version did, leaves every later call without a handle.
    Ok(VulkanEngine {
        device_count: devices.len(),
        devices,
        entry,
        instance,
    })
}

/// No Vulkan support in this build.
#[cfg(not(feature = "vulkan"))]
pub fn probe() -> Result<VulkanEngine, VulkanError> {
    Err(VulkanError::FeatureDisabled)
}

#[cfg(feature = "vulkan")]
fn c_str(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("literal has no interior nul")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the host looks like, discovery must not panic and must not
    /// invent a device.
    #[test]
    fn discovery_never_invents_a_device() {
        match probe() {
            Ok(engine) => {
                assert!(engine.device_count > 0);
                for d in &engine.devices {
                    assert!(!d.name.is_empty(), "device with no name");
                }
            }
            Err(e) => {
                // The error must name a cause a user can act on.
                assert!(
                    matches!(e, VulkanError::NoDevice | VulkanError::FeatureDisabled
                                  | VulkanError::DeviceError(_)),
                    "unexpected error variant: {e:?}"
                );
            }
        }
    }

    /// Limits come from the device, so a device that reports them must report
    /// plausible values rather than zeros standing in for "unknown".
    #[cfg(feature = "vulkan")]
    #[test]
    fn limits_are_read_from_the_device() {
        if let Ok(engine) = probe() {
            for d in &engine.devices {
                assert!(
                    d.limits.max_work_group_invocations > 0,
                    "{} reported zero max_compute_work_group_invocations",
                    d.name
                );
                assert!(
                    d.limits.max_storage_buffer_range > 0,
                    "{} reported zero max_storage_buffer_range",
                    d.name
                );
                println!(
                    "{}: {} invocations/workgroup, {} workgroups, {} MiB storage range",
                    d.name,
                    d.limits.max_work_group_invocations,
                    d.limits.max_work_group_count,
                    d.limits.max_storage_buffer_range / 1_048_576
                );
            }
        }
    }
}