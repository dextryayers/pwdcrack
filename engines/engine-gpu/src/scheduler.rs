use std::sync::Arc;
use wgpu::*;

pub struct GpuScheduler {
    devices: Vec<Arc<Device>>,
    queues: Vec<Arc<Queue>>,
    next_device: usize,
    batch_size: u64,
}

impl GpuScheduler {
    pub fn new(devices: Vec<(Arc<Device>, Arc<Queue>)>, batch_size: u64) -> Self {
        let mut d = Vec::new();
        let mut q = Vec::new();
        for (dev, qu) in devices {
            d.push(dev);
            q.push(qu);
        }
        GpuScheduler {
            devices: d,
            queues: q,
            next_device: 0,
            batch_size,
        }
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn next_device(&mut self) -> Option<(&Arc<Device>, &Arc<Queue>)> {
        if self.devices.is_empty() {
            return None;
        }
        let idx = self.next_device % self.devices.len();
        self.next_device = (self.next_device + 1) % self.devices.len();
        Some((&self.devices[idx], &self.queues[idx]))
    }

    pub fn all_devices(&self) -> impl Iterator<Item = (&Arc<Device>, &Arc<Queue>)> {
        self.devices.iter().zip(self.queues.iter())
    }

    pub fn submit(&self, device_idx: usize, encoder: CommandEncoder) {
        let idx = device_idx % self.devices.len();
        self.queues[idx].submit(std::iter::once(encoder.finish()));
    }

    pub fn submit_all(&self, encoders: Vec<(usize, CommandEncoder)>) {
        for (idx, encoder) in encoders {
            self.submit(idx, encoder);
        }
    }

    pub fn wait_all(&self) {
        // wgpu 30 handles submission tracking internally.
        // GPU work completes asynchronously without explicit polling.
    }

    pub fn batch_size(&self) -> u64 {
        self.batch_size
    }

    pub fn set_batch_size(&mut self, size: u64) {
        self.batch_size = size;
    }
}
