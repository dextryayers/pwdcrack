//! Session save/restore — persist cracking progress for resume on battery death

use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CrackingSession {
    pub version: u32,
    pub hash_file: String,
    pub hashes_remaining: Vec<String>,
    pub hashes_cracked: Vec<(String, String)>,
    pub attack_type: String,
    pub attack_params: HashMap<String, String>,
    pub progress: u64,
    pub total: u64,
    pub timestamp: u64,
}

impl CrackingSession {
    pub fn new() -> Self {
        CrackingSession {
            version: 1,
            hash_file: String::new(),
            hashes_remaining: Vec::new(),
            hashes_cracked: Vec::new(),
            attack_type: String::new(),
            attack_params: HashMap::new(),
            progress: 0,
            total: 0,
            timestamp: 0,
        }
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        log::info!("Session saved to {}", path);
        Ok(())
    }

    pub fn load(path: &str) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn auto_save_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.pwdcrack_session.json", home)
    }

    pub fn save_auto(&self) {
        let path = Self::auto_save_path();
        let _ = self.save(&path);
    }

    pub fn load_auto() -> Option<Self> {
        let path = Self::auto_save_path();
        Self::load(&path)
    }

    pub fn clear_auto() {
        let path = Self::auto_save_path();
        let _ = fs::remove_file(&path);
    }
}

pub struct SessionManager {
    session: CrackingSession,
    dirty: bool,
    save_interval_secs: u64,
    path: String,
}

impl SessionManager {
    pub fn new(path: Option<String>, save_interval_secs: u64) -> Self {
        SessionManager {
            session: CrackingSession::new(),
            dirty: false,
            save_interval_secs,
            path: path.unwrap_or_else(CrackingSession::auto_save_path),
        }
    }

    pub fn load_or_create(&mut self) {
        if let Some(s) = CrackingSession::load(&self.path) {
            self.session = s;
            log::info!("Session restored from {}", self.path);
        }
    }

    pub fn save(&self) {
        let _ = self.session.save(&self.path);
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn auto_save(&mut self) {
        if self.dirty {
            self.save();
            self.dirty = false;
        }
    }

    pub fn session(&self) -> &CrackingSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut CrackingSession {
        self.dirty = true;
        &mut self.session
    }
}
