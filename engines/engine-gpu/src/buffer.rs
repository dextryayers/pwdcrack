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

    pub fn get_upload_buffer(&mut self, size: u64) -> GpuBuffer {
        self.upload_pool.pop().unwrap_or_else(|| GpuBuffer {
            buffer: self.device.create_buffer(&BufferDescriptor {
                label: Some("upload buffer"),
                size,
                usage: BufferUsages::MAP_WRITE | BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            }),
            size,
            usage: BufferUsages::MAP_WRITE | BufferUsages::COPY_SRC,
        })
    }

    pub fn get_storage_buffer(&mut self, size: u64) -> GpuBuffer {
        self.storage_pool.pop().unwrap_or_else(|| GpuBuffer {
            buffer: self.device.create_buffer(&BufferDescriptor {
                label: Some("storage buffer"),
                size,
                usage: BufferUsages::STORAGE | BufferUsages::COPY_DST | BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            }),
            size,
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST | BufferUsages::COPY_SRC,
        })
    }

    pub fn get_readback_buffer(&mut self, size: u64) -> GpuBuffer {
        self.readback_pool.pop().unwrap_or_else(|| GpuBuffer {
            buffer: self.device.create_buffer(&BufferDescriptor {
                label: Some("readback buffer"),
                size,
                usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
                mapped_at_creation: false,
            }),
            size,
            usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
        })
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
