use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    Cpu,
    Gpu,
    Fpga,
    Dsp,
    Tpu,
    Metal,
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub kind: DeviceKind,
    pub name: String,
    pub performance: f64,
    pub power_watts: f64,
    pub load: f64,
}

pub struct HybridScheduler {
    devices: Vec<DeviceInfo>,
    work_queue: Vec<WorkItem>,
}

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub id: u64,
    pub hash_type: String,
    pub data: Vec<u8>,
    pub priority: u32,
}

impl HybridScheduler {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            work_queue: Vec::new(),
        }
    }

    pub fn register_device(&mut self, device: DeviceInfo) {
        self.devices.push(device);
    }

    pub fn enqueue(&mut self, item: WorkItem) {
        self.work_queue.push(item);
    }

    pub fn schedule(&mut self) -> Vec<(u64, DeviceKind)> {
        let mut assignments = Vec::new();
        for item in &self.work_queue {
            let best_device = self.devices
                .iter()
                .filter(|d| d.load < 0.9)
                .max_by(|a, b| a.performance.partial_cmp(&b.performance).unwrap_or(std::cmp::Ordering::Equal));
            if let Some(device) = best_device {
                assignments.push((item.id, device.kind));
            }
        }
        assignments
    }

    pub fn device_count(&self) -> usize { self.devices.len() }

    pub fn total_performance(&self) -> f64 {
        self.devices.iter().map(|d| d.performance * (1.0 - d.load)).sum()
    }
}
