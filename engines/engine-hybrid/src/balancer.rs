use crate::scheduler::{DeviceInfo, DeviceKind, HybridScheduler};

#[derive(Debug, Clone)]
pub struct LoadBalancer {
    pub strategy: BalanceStrategy,
    history: Vec<BalanceRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceStrategy {
    RoundRobin,
    LeastLoaded,
    PerformanceWeighted,
    Adaptive,
}

#[derive(Debug, Clone)]
struct BalanceRecord {
    device: DeviceKind,
    items_processed: u64,
    time_taken_ms: u64,
}

impl LoadBalancer {
    pub fn new(strategy: BalanceStrategy) -> Self {
        Self {
            strategy,
            history: Vec::new(),
        }
    }

    pub fn select_device(&self, devices: &[DeviceInfo]) -> Option<DeviceInfo> {
        match self.strategy {
            BalanceStrategy::LeastLoaded => {
                devices.iter()
                    .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap_or(std::cmp::Ordering::Equal))
                    .cloned()
            }
            BalanceStrategy::PerformanceWeighted => {
                devices.iter()
                    .max_by(|a, b| {
                        let score_a = a.performance * (1.0 - a.load);
                        let score_b = b.performance * (1.0 - b.load);
                        score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .cloned()
            }
            BalanceStrategy::RoundRobin => devices.first().cloned(),
            BalanceStrategy::Adaptive => {
                devices.iter()
                    .filter(|d| d.load < 0.85)
                    .max_by(|a, b| a.performance.partial_cmp(&b.performance).unwrap_or(std::cmp::Ordering::Equal))
                    .cloned()
            }
        }
    }

    pub fn record(&mut self, device: DeviceKind, items: u64, time_ms: u64) {
        self.history.push(BalanceRecord {
            device,
            items_processed: items,
            time_taken_ms: time_ms,
        });
    }
}
