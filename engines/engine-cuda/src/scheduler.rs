pub struct CudaScheduler {
    devices: Vec<crate::CudaDevice>,
    next_device: usize,
    batch_size: u64,
}

impl CudaScheduler {
    pub fn new(devices: Vec<crate::CudaDevice>, batch_size: u64) -> Self {
        CudaScheduler { devices, next_device: 0, batch_size }
    }

    pub fn device_count(&self) -> usize { self.devices.len() }

    pub fn next_device(&mut self) -> Option<&crate::CudaDevice> {
        if self.devices.is_empty() { return None; }
        let dev = &self.devices[self.next_device % self.devices.len()];
        self.next_device += 1;
        Some(dev)
    }

    pub fn batch_size(&self) -> u64 { self.batch_size }
    pub fn set_batch_size(&mut self, size: u64) { self.batch_size = size; }
}
