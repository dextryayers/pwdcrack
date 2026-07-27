//! RAM and I/O limits — aggressive streaming for low-RAM devices

#[derive(Debug, Clone)]
pub struct AndroidLimits {
    pub total_ram_mb: u64,
    pub batch_size: u64,
    pub arena_kb: u64,
    pub use_mmap: bool,
    pub max_wordlist_mb: u64,
}

impl AndroidLimits {
    pub fn detect() -> Self {
        let total_ram_mb = Self::read_total_ram_mb();

        // Low-RAM profile: streaming I/O, tiny batches, small arena
        if total_ram_mb < 1024 {
            AndroidLimits {
                total_ram_mb,
                batch_size: 8,
                arena_kb: 16,
                use_mmap: false,
                max_wordlist_mb: 128,
            }
        } else if total_ram_mb < 2048 {
            AndroidLimits {
                total_ram_mb,
                batch_size: 16,
                arena_kb: 64,
                use_mmap: false,
                max_wordlist_mb: 512,
            }
        } else if total_ram_mb < 4096 {
            AndroidLimits {
                total_ram_mb,
                batch_size: 32,
                arena_kb: 128,
                use_mmap: false,
                max_wordlist_mb: 1024,
            }
        } else {
            // 4GB+ — can use mmap cautiously
            AndroidLimits {
                total_ram_mb,
                batch_size: 64,
                arena_kb: 256,
                use_mmap: true,
                max_wordlist_mb: 2048,
            }
        }
    }

    fn read_total_ram_mb() -> u64 {
        let content = std::fs::read_to_string("/proc/meminfo").ok();
        if let Some(s) = content {
            for line in s.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
        // Fallback
        if cfg!(target_pointer_width = "64") {
            2048
        } else {
            512
        }
    }

    pub fn recommended_threads(&self) -> usize {
        if self.total_ram_mb < 512 {
            1
        } else if self.total_ram_mb < 1024 {
            2
        } else if self.total_ram_mb < 2048 {
            4
        } else {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
        }
    }

    pub fn info(&self) -> String {
        format!(
            "{}MB RAM, batch={}, arena={}KB, mmap={}, max_wordlist={}MB",
            self.total_ram_mb, self.batch_size, self.arena_kb, self.use_mmap, self.max_wordlist_mb
        )
    }
}
