use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub struct Potfile {
    path: String,
    cracked: Mutex<HashSet<String>>,
}

impl Potfile {
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

    pub fn is_cracked(&self, hash: &str) -> bool {
        self.cracked.lock().unwrap().contains(hash)
    }

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

    pub fn save_batch(&self, entries: &[(String, String)]) {
        let mut batch = String::new();
        {
            let mut cracked = self.cracked.lock().unwrap();
            for (hash, password) in entries {
                if cracked.contains(hash) {
                    continue;
                }
                cracked.insert(hash.clone());
                batch.push_str(&format!("{}:{}\n", hash, password));
            }
        }

        if batch.is_empty() {
            return;
        }

        let mut file = match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[!] Failed to open potfile: {}", e);
                return;
            }
        };

        if let Err(e) = file.write_all(batch.as_bytes()) {
            eprintln!("[!] Failed to write potfile batch: {}", e);
        }
        let _ = file.flush();
        #[cfg(any(unix, windows))]
        { let _ = file.sync_all(); }
    }

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

    pub fn count(&self) -> usize {
        self.cracked.lock().unwrap().len()
    }
}
