//! Metal device discovery.
//!
//! # Status: honest stub
//!
//! Metal is an Apple platform API. There is no implementation of it on Linux or
//! Windows, so this module does not attempt to discover devices anywhere else.
//!
//! # What the previous version did, and why it was wrong
//!
//! It constructed two devices by hand behind `#[cfg(target_os = "macos")]`:
//!
//! ```text
//! name: "Apple GPU", vendor: "Apple", compute_units: 64, gpu_family: "Apple9"
//! name: "Intel GPU", vendor: "Intel", compute_units: 48, max_threads_per_group: 512
//! ```
//!
//! Those numbers were invented. No query was made, so they could not reflect any
//! real machine: a MacBook Air and a Mac Pro would have reported the same 64
//! compute units and the same "Apple9" family. Reporting invented hardware as if
//! it had been detected is worse than reporting nothing, because it looks like a
//! detection result and would feed made-up numbers into whatever consumes them.
//!
//! On non-macOS it read `/tmp/metal_devices.txt`. Nothing in this repository ever
//! writes that file, so the path was always empty and always reported no
//! devices. A file in `/tmp` that no component produces is a placeholder that
//! looks like a configuration point.
//!
//! Both are removed. `detect_all` now returns an empty vector off macOS and
//! requires a real query behind `#[cfg(target_os = "macos")]`, which is where
//! `MTLCreateSystemDefaultDevice()` belongs.
//!
//! # What is needed to make this real
//!
//! On macOS, depend on `metal-rs` and call
//! `metal::Device::system_default()`, then read the limits from the device:
//! `recommended_max_working_set_size()` and `max_threads_per_threadgroup()`.
//! That is P7.2.01 and P7.2.04. Nothing has been written here because it cannot
//! be compiled or tested on this machine, and a Metal path that was never run
//! would be exactly the kind of unverified claim this crate refuses to make.

use std::collections::HashMap;

/// A Metal device as this crate would model it.
///
/// The fields are real Metal device properties. They are never populated with
/// constants; a value here comes from a query or it does not appear.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetalDevice {
    pub name: String,
    pub vendor: String,
    pub compute_units: u32,
    pub max_threads_per_group: u32,
    pub has_unified_memory: bool,
    pub gpu_family: String,
}

impl MetalDevice {
    /// A device with no properties filled in.
    ///
    /// Not a usable device. Present so that `Option` handling downstream has a
    /// neutral value; every field is empty rather than a plausible default,
    /// because a zero that looks like a real measurement is the failure being
    /// removed here.
    pub fn new() -> Self {
        Self::default()
    }

    /// Detects Metal devices.
    ///
    /// Returns an empty vector on every platform where Metal does not exist,
    /// which is every platform this was tested on.
    #[cfg(target_os = "macos")]
    pub fn detect_all() -> Vec<Self> {
        // P7.2.01: query MTLCreateSystemDefaultDevice through metal-rs here and
        // read the real limits. Until that is written this returns empty rather
        // than a hardcoded device, because an invented device is a false report
        // and an empty list is a true one.
        let _ = HashMap::<u32, u32>::new();
        Vec::new()
    }

    /// Detects Metal devices. Always empty off macOS.
    #[cfg(not(target_os = "macos"))]
    pub fn detect_all() -> Vec<Self> {
        Vec::new()
    }
}

/// Detected Metal device summary, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetalDeviceInfo {
    pub name: String,
    pub vendor: String,
    pub compute_units: u32,
    pub gpu_family: String,
}

impl std::fmt::Display for MetalDeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) units={} family={}",
            self.name, self.vendor, self.compute_units, self.gpu_family
        )
    }
}

/// Probes the host for a Metal capable device.
///
/// Returns `None` on every non-macOS host. That is a real answer, not a failure
/// to look: Metal does not exist there.
pub fn probe() -> Option<MetalDeviceInfo> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    MetalDevice::detect_all()
        .into_iter()
        .find(|d| !d.name.is_empty())
        .map(|d| MetalDeviceInfo {
            name: d.name,
            vendor: d.vendor,
            compute_units: d.compute_units,
            gpu_family: d.gpu_family,
        })
}

/// Whether this build can possibly use Metal.
///
/// True only on macOS. Kept as a function rather than a constant so that a
/// cross-compiled binary answers for the machine it runs on.
pub fn supported() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core invariant: this crate never invents a GPU.
    ///
    /// The previous implementation passed this test on macOS by hardcoding two
    /// devices, which is exactly the behaviour being removed.
    #[test]
    fn no_device_is_invented_on_this_host() {
        for d in MetalDevice::detect_all() {
            // A device that came from a real query carries a name and a vendor.
            // A fabricated one in the old code also did, so name alone is not
            // enough: the specific values the old code used are asserted absent.
            assert!(
                !(d.name == "Apple GPU" && d.compute_units == 64 && d.gpu_family == "Apple9"),
                "detect_all returned the hardcoded device from the previous implementation"
            );
            assert!(
                !(d.name == "Intel GPU" && d.compute_units == 48),
                "detect_all returned the hardcoded Intel device from the previous implementation"
            );
        }
    }

    #[test]
    fn probe_agrees_with_the_platform() {
        if supported() {
            // On macOS a device may or may not be present; the contract is only
            // that whatever is returned has a name.
            if let Some(info) = probe() {
                assert!(!info.name.is_empty());
            }
        } else {
            assert!(probe().is_none(), "probe reported a Metal device off macOS");
            assert!(detect_all_is_empty());
        }
    }

    fn detect_all_is_empty() -> bool {
        MetalDevice::detect_all().is_empty()
    }

    #[test]
    fn new_device_has_no_invented_properties() {
        let d = MetalDevice::new();
        assert_eq!(d.name, "");
        assert_eq!(d.compute_units, 0);
        assert_eq!(d.gpu_family, "");
        assert!(!d.has_unified_memory);
    }

    /// Nothing may read a device list from a file that no component writes.
    ///
    /// Comments are stripped before the check, because this file explains why
    /// that path was removed and naming it is the only way to do that clearly.
    #[test]
    fn no_file_is_read_for_discovery() {
        let src = include_str!("device.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("/**")
                        && !l.trim_start().starts_with("//"))
            // Strip the string literal of this test itself, which necessarily
            // names the thing it is checking for.
            .map(|l| l.split("!code.contains").next().unwrap_or(l).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("metal_devices.txt"),
            "device discovery still references a placeholder file"
        );
        assert!(
            !code.contains("/tmp/"),
            "device discovery still reads from /tmp"
        );
    }
}