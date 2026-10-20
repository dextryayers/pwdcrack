//! Real hardware facts read from the operating system.
//!
//! # Why this module exists
//!
//! [`crate::AdapterInfo::vram_mb`] used to return a literal chosen by device
//! type: 8192 for a discrete GPU, 512 for an integrated one, 128 for anything
//! else. None of those numbers was read from anywhere. A user with a 4 GiB
//! discrete card was told 8192 MB, and an Intel iGPU with a small aperture was
//! told 512 MB. The value is now read from the kernel, or reported as unknown.
//!
//! The numbers come from the DRM card under `/sys/class/drm` whose PCI vendor and
//! device ids match the adapter wgpu selected. That mapping is the part that can
//! be wrong: a machine can have several cards, and a backend can report ids that
//! no DRM card matches. When no card matches, both values are `None` rather than
//! a guess.

use std::path::Path;

/// Dedicated video memory and shared memory for one adapter, in bytes.
///
/// `vram` is the memory soldered to the card, or on an APU the BIOS carve out.
/// `gtt` is system memory the GPU can address. Either can be `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemorySizes {
    pub vram: Option<u64>,
    pub gtt: Option<u64>,
}

/// Reads the memory sizes for the adapter with these PCI ids.
///
/// Returns all `None` on any platform other than Linux, and on Linux when no
/// DRM card matches the ids.
pub(crate) fn memory_bytes(vendor: u32, device: u32) -> MemorySizes {
    #[cfg(target_os = "linux")]
    {
        memory_bytes_in(Path::new("/sys/class/drm"), vendor, device)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (vendor, device);
        MemorySizes::default()
    }
}

/// Reads the memory sizes from a directory shaped like `/sys/class/drm`.
///
/// Split out from [`memory_bytes`] so the selection and parsing can be tested
/// against a synthetic tree instead of whatever hardware the test host happens to
/// have.
#[cfg(target_os = "linux")]
pub(crate) fn memory_bytes_in(root: &Path, vendor: u32, device: u32) -> MemorySizes {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return MemorySizes::default(),
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Only the base cards, not the connectors: /sys/class/drm also contains
        // card0-DP-1 and similar entries, whose `device` link points at the same
        // card and would be selected a second time.
        let suffix = match name.strip_prefix("card") {
            Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s,
            _ => continue,
        };
        let _ = suffix;

        let device_dir = entry.path().join("device");
        let card_vendor = read_pci_id(&device_dir.join("vendor"));
        let card_device = read_pci_id(&device_dir.join("device"));
        if card_vendor != Some(vendor) || card_device != Some(device) {
            continue;
        }

        return MemorySizes {
            vram: read_u64(&device_dir.join("mem_info_vram_total")),
            gtt: read_u64(&device_dir.join("mem_info_gtt_total")),
        };
    }

    MemorySizes::default()
}

/// Parses a PCI id from sysfs, which is written as `0x1002` with a newline.
///
/// Also accepts the bare hexadecimal form, because the kernel interface is not
/// guaranteed to keep the prefix.
#[cfg(target_os = "linux")]
fn read_pci_id(path: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    parse_pci_id(&text)
}

#[cfg(target_os = "linux")]
fn parse_pci_id(text: &str) -> Option<u32> {
    let text = text.trim();
    let text = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    u32::from_str_radix(text, 16).ok()
}

#[cfg(target_os = "linux")]
fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;

    /// Builds a fake DRM tree with one card per tuple.
    fn fake_tree(name: &str, cards: &[(u32, u32, Option<u64>, Option<u64>)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for (i, (vendor, device, vram, gtt)) in cards.iter().enumerate() {
            let dir = root.join(format!("card{i}")).join("device");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("vendor"), format!("0x{vendor:04x}\n")).unwrap();
            fs::write(dir.join("device"), format!("0x{device:04x}\n")).unwrap();
            if let Some(v) = vram {
                fs::write(dir.join("mem_info_vram_total"), format!("{v}\n")).unwrap();
            }
            if let Some(g) = gtt {
                fs::write(dir.join("mem_info_gtt_total"), format!("{g}\n")).unwrap();
            }
        }
        // A connector entry, which must not be mistaken for a card of its own.
        let conn = root.join("card0-DP-1").join("device");
        fs::create_dir_all(&conn).unwrap();
        fs::write(conn.join("vendor"), "0x1002\n").unwrap();
        fs::write(conn.join("device"), "0x164c\n").unwrap();
        root
    }

    #[test]
    fn picks_the_card_whose_ids_match() {
        let root = fake_tree(
            "pwdcrack_gpu_hw_match",
            &[
                (0x10de, 0x2484, Some(4 * 1024 * 1024 * 1024), Some(0)),
                (0x1002, 0x164c, Some(512 * 1024 * 1024), Some(10_157_957_120)),
            ],
        );

        let got = memory_bytes_in(&root, 0x1002, 0x164c);
        assert_eq!(got.vram, Some(512 * 1024 * 1024));
        assert_eq!(got.gtt, Some(10_157_957_120));

        let nvidia = memory_bytes_in(&root, 0x10de, 0x2484);
        assert_eq!(nvidia.vram, Some(4 * 1024 * 1024 * 1024));
        // A zero in sysfs is a real answer, not an unknown.
        assert_eq!(nvidia.gtt, Some(0));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_adapter_reports_nothing_instead_of_a_guess() {
        let root = fake_tree("pwdcrack_gpu_hw_unknown", &[(0x8086, 0x9a49, Some(1), None)]);
        let got = memory_bytes_in(&root, 0x1002, 0x164c);
        assert_eq!(got, MemorySizes::default());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_memory_file_is_unknown_not_zero() {
        let root = fake_tree("pwdcrack_gpu_hw_partial", &[(0x1002, 0x164c, Some(1024), None)]);
        let got = memory_bytes_in(&root, 0x1002, 0x164c);
        assert_eq!(got.vram, Some(1024));
        assert_eq!(got.gtt, None, "a missing file must not read as 0 bytes");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_tree_is_unknown() {
        let got = memory_bytes_in(Path::new("/nonexistent/pwdcrack/drm"), 0x1002, 0x164c);
        assert_eq!(got, MemorySizes::default());
    }

    #[test]
    fn pci_ids_parse_with_and_without_the_prefix() {
        assert_eq!(parse_pci_id("0x1002\n"), Some(0x1002));
        assert_eq!(parse_pci_id("1002"), Some(0x1002));
        assert_eq!(parse_pci_id("  0X10DE  "), Some(0x10de));
        assert_eq!(parse_pci_id("zz"), None);
        assert_eq!(parse_pci_id(""), None);
    }
}
