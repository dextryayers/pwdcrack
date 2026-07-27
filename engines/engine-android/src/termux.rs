//! Termux environment detection and utilities

/// Check if running inside Termux
pub fn is_termux() -> bool {
    std::env::var("TERMUX_VERSION").is_ok()
}

/// Get Termux prefix path
pub fn termux_prefix() -> String {
    std::env::var("PREFIX").unwrap_or_else(|_| "/data/data/com.termux/files/usr".to_string())
}

/// Get Termux home directory
pub fn termux_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/data/data/com.termux/files/home".to_string())
}
