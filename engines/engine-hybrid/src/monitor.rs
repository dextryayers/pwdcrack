use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DeviceStats {
    pub device_name: String,
    pub hashes_per_second: f64,
    pub power_watts: f64,
    pub temperature_c: f64,
    pub utilization: f64,
}

#[derive(Debug)]
pub struct SystemMonitor {
    start_time: Instant,
    total_hashes: u64,
    samples: Vec<DeviceStats>,
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_hashes: 0,
            samples: Vec::new(),
        }
    }

    pub fn record_hashes(&mut self, count: u64) {
        self.total_hashes += count;
    }

    pub fn add_sample(&mut self, stats: DeviceStats) {
        self.samples.push(stats);
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn global_hps(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64().max(0.001);
        self.total_hashes as f64 / secs
    }

    pub fn average_power(&self) -> Option<f64> {
        if self.samples.is_empty() { return None; }
        let total: f64 = self.samples.iter().map(|s| s.power_watts).sum();
        Some(total / self.samples.len() as f64)
    }

    pub fn summary(&self) -> String {
        format!("{:.2} H/s, {:.1}s elapsed, {} samples",
            self.global_hps(), self.elapsed().as_secs_f64(), self.samples.len())
    }
}
