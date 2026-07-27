use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Potfile {
    path: String,
    cracked: HashSet<String>,
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
            cracked,
        }
    }

    pub fn is_cracked(&self, hash: &str) -> bool {
        self.cracked.contains(hash)
    }

    pub fn save(&self, hash: &str, password: &str) {
        if let Err(e) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            eprintln!("[!] Failed to write potfile: {}", e);
            return;
        }
        let line = format!("{}:{}\n", hash, password);
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            use std::io::Write;
            let _ = file.write_all(line.as_bytes());
        }
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
}
