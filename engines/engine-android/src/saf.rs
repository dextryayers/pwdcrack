//! Storage Access Framework (SAF) — read files from /sdcard

use std::fs;
use std::path::Path;

/// Copy file from SAF URI (content://) to temp file
/// Workaround: Termux FUSE mounts /sdcard at /storage/emulated/0
pub fn saf_path(saf_uri: &str) -> Option<String> {
    // Termux mounts SAF at /storage/emulated/0
    let real_path = saf_uri
        .replace("content://com.android.externalstorage.documents/document/primary%3A", "/storage/emulated/0/")
        .replace("content://com.android.externalstorage.documents/tree/primary%3A", "/storage/emulated/0/");

    if Path::new(&real_path).exists() {
        Some(real_path)
    } else {
        None
    }
}

/// Check if a file is accessible
pub fn file_accessible(path: &str) -> bool {
    Path::new(path).exists() && fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
