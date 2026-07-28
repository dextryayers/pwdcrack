use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Tracks cracked hashes and persists them to a potfile on disk.
pub struct Potfile {
    path: String,
    cracked: Mutex<HashSet<String>>,
}

impl Potfile {
    /// Opens or creates a potfile at the given path, loading any existing entries.
    pub fn new(path: &str) -> Self {
        let cracked = if Path::new(path).exists() {
            fs::read_to_string(path)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| {
                    let trimmed = l.trim();
                    if let Some(idx) = trimmed.find(':') {
                        Some(trimmed[..idx].to_string())
                    } else {
                        Some(trimmed.to_string())
                    }
                })
                .collect()
        } else {
            HashSet::new()
        };

        Potfile {
            path: path.to_string(),
            cracked: Mutex::new(cracked),
        }
    }

    /// Returns `true` if the given hash has already been cracked.
    pub fn is_cracked(&self, hash: &str) -> bool {
        self.cracked.lock().unwrap().contains(hash)
    }

    /// Records a cracked hash and appends `hash:password` to the potfile.
    pub fn save(&self, hash: &str, password: &str) {
        {
            let mut cracked = self.cracked.lock().unwrap();
            if cracked.contains(hash) {
                return;
            }
            cracked.insert(hash.to_string());
        }

        let line = format!("{}:{}\n", hash, password);
        let mut file = match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] Failed to write potfile: {}", e);
                return;
            }
        };

        if let Err(e) = file.write_all(line.as_bytes()) {
            eprintln!("[!] Failed to write potfile entry: {}", e);
            return;
        }
        let _ = file.flush();
        #[cfg(any(unix, windows))]
        { let _ = file.sync_all(); }
    }

    /// Returns all `(hash, password)` pairs currently stored in the potfile.
    pub fn entries(&self) -> Vec<(String, String)> {
        let content = fs::read_to_string(&self.path).unwrap_or_default();
        content.lines()
            .filter_map(|l| {
                let trimmed = l.trim();
                let idx = trimmed.find(':')?;
                Some((trimmed[..idx].to_string(), trimmed[idx+1..].to_string()))
            })
            .collect()
    }

    /// Returns the number of unique hashes recorded as cracked.
    pub fn count(&self) -> usize {
        self.cracked.lock().unwrap().len()
    }
}
