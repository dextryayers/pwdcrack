use wgpu::*;
use std::sync::Arc;

pub struct GpuBuffer {
    pub buffer: Buffer,
    pub size: u64,
    pub usage: BufferUsages,
}

pub struct GpuBufferPool {
    device: Arc<Device>,
    upload_pool: Vec<GpuBuffer>,
    storage_pool: Vec<GpuBuffer>,
    readback_pool: Vec<GpuBuffer>,
    max_buffers: usize,
}

impl GpuBufferPool {
    pub fn new(device: Arc<Device>, max_buffers: usize) -> Self {
        GpuBufferPool {
            device,
            upload_pool: Vec::new(),
            storage_pool: Vec::new(),
            readback_pool: Vec::new(),
            max_buffers,
        }
    }

    /// Takes a buffer of at least `size` bytes from `pool`, or allocates one.
    ///
    /// Sizes are rounded up to a power of two so that a batch of 300 candidates
    /// can reuse the buffer a batch of 256 allocated. The previous version popped
    /// whatever was in the pool, even when it was smaller than the request, which
    /// would have bound a short buffer to a kernel that indexes past its end.
    fn take(
        pool: &mut Vec<GpuBuffer>,
        device: &Device,
        size: u64,
        usage: BufferUsages,
        label: &str,
    ) -> GpuBuffer {
        let size = size.max(64).next_power_of_two();
        if let Some(index) = pool.iter().position(|b| b.size >= size) {
            return pool.swap_remove(index);
        }
        GpuBuffer {
            buffer: device.create_buffer(&BufferDescriptor {
                label: Some(label),
                size,
                usage,
                mapped_at_creation: false,
            }),
            size,
            usage,
        }
    }

    pub fn get_upload_buffer(&mut self, size: u64) -> GpuBuffer {
        Self::take(
            &mut self.upload_pool,
            &self.device,
            size,
            BufferUsages::MAP_WRITE | BufferUsages::COPY_SRC,
            "upload buffer",
        )
    }

    pub fn get_storage_buffer(&mut self, size: u64) -> GpuBuffer {
        Self::take(
            &mut self.storage_pool,
            &self.device,
            size,
            BufferUsages::STORAGE | BufferUsages::COPY_DST | BufferUsages::COPY_SRC,
            "storage buffer",
        )
    }

    pub fn get_readback_buffer(&mut self, size: u64) -> GpuBuffer {
        Self::take(
            &mut self.readback_pool,
            &self.device,
            size,
            BufferUsages::MAP_READ | BufferUsages::COPY_DST,
            "readback buffer",
        )
    }

    pub fn return_buffer(&mut self, buf: GpuBuffer, pool_type: PoolType) {
        let pool = match pool_type {
            PoolType::Upload => &mut self.upload_pool,
            PoolType::Storage => &mut self.storage_pool,
            PoolType::Readback => &mut self.readback_pool,
        };
        if pool.len() < self.max_buffers {
            pool.push(buf);
        }
    }

    pub fn clear(&mut self) {
        self.upload_pool.clear();
        self.storage_pool.clear();
        self.readback_pool.clear();
    }

    pub fn total_buffers(&self) -> usize {
        self.upload_pool.len() + self.storage_pool.len() + self.readback_pool.len()
    }
}

pub enum PoolType {
    Upload,
    Storage,
    Readback,
}
