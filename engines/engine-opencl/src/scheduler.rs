pub struct OpenclScheduler {
    devices: Vec<crate::OpenclDevice>,
    next_device: usize,
}

impl OpenclScheduler {
    pub fn new(devices: Vec<crate::OpenclDevice>) -> Self {
        OpenclScheduler { devices, next_device: 0 }
    }
    pub fn device_count(&self) -> usize { self.devices.len() }
    pub fn next_device(&mut self) -> Option<&crate::OpenclDevice> {
        if self.devices.is_empty() { return None; }
        let dev = &self.devices[self.next_device % self.devices.len()];
        self.next_device += 1;
        Some(dev)
    }
}
