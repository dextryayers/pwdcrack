//! Android notifications — termux-notification API for crack alerts

use std::process::Command;

pub struct AndroidNotification;

impl AndroidNotification {
    fn termux_notification(title: &str, content: &str, alert_once: bool) -> Option<()> {
        let mut cmd = Command::new("termux-notification");
        cmd.arg("--title").arg(title);
        cmd.arg("--content").arg(content);
        if alert_once {
            cmd.arg("--alert-once");
        }
        cmd.output().ok()?;
        Some(())
    }

    pub fn notify_cracked(password: &str, hash: &str, hash_type: &str) {
        let title = format!("🔥 Cracked: {}", password);
        let content = format!("[{}] {} → {}", hash_type, hash, password);
        log::info!("Notification: {}", title);

        if std::env::var("TERMUX_VERSION").is_ok() {
            let _ = Self::termux_notification(&title, &content, true);
        }
    }

    pub fn notify_progress(pct: f64, hashes_per_sec: f64, elapsed: &str) {
        if std::env::var("TERMUX_VERSION").is_ok() {
            if std::env::var("TERMUX_NOTIFICATION_PROGRESS").is_ok() {
                let title = "pwdcrack running";
                let content = format!("{:.1}% | {:.0} H/s | {}", pct, hashes_per_sec, elapsed);
                let _ = Self::termux_notification(title, &content, false);
            }
        }
    }

    pub fn notify_paused(reason: &str) {
        let title = "⏸ pwdcrack paused";
        if std::env::var("TERMUX_VERSION").is_ok() {
            let _ = Self::termux_notification(title, reason, true);
        }
    }

    pub fn notify_resumed() {
        let title = "▶ pwdcrack resumed";
        if std::env::var("TERMUX_VERSION").is_ok() {
            let _ = Self::termux_notification(title, "Cracking continues", true);
        }
    }

    pub fn notify_complete(total_cracked: usize, elapsed: &str) {
        let title = format!("✅ pwdcrack complete — {} cracked", total_cracked);
        let content = format!("Elapsed: {}", elapsed);
        if std::env::var("TERMUX_VERSION").is_ok() {
            let _ = Self::termux_notification(&title, &content, true);
        }
    }
}
