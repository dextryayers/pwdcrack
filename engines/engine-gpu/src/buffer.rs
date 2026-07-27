//! GPU buffer management — pinned memory, buffer pool

use wgpu::*;
use std::sync::Arc;

pub struct GpuBufferPool {
    device: Arc<Device>,
    /// Pre-allocated staging buffers for upload
    upload_pool: Vec<Buffer>,
    /// Pre-allocated storage buffers for compute
    storage_pool: Vec<Buffer>,
    max_buffers: usize,
}

impl GpuBufferPool {
    pub fn new(device: Arc<Device>, max_buffers: usize) -> Self {
        GpuBufferPool {
            device,
            upload_pool: Vec::new(),
            storage_pool: Vec::new(),
            max_buffers,
        }
    }

    pub fn get_upload_buffer(&mut self, size: u64) -> Buffer {
        self.upload_pool.pop().unwrap_or_else(|| {
            self.device.create_buffer(&BufferDescriptor {
                label: Some("upload buffer"),
                size,
                usage: BufferUsages::MAP_WRITE | BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            })
        })
    }

    pub fn get_storage_buffer(&mut self, size: u64) -> Buffer {
        self.storage_pool.pop().unwrap_or_else(|| {
            self.device.create_buffer(&BufferDescriptor {
                label: Some("storage buffer"),
                size,
                usage: BufferUsages::STORAGE | BufferUsages::COPY_DST | BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            })
        })
    }

    pub fn return_buffer(&mut self, buf: Buffer, pool_type: PoolType) {
        match pool_type {
            PoolType::Upload if self.upload_pool.len() < self.max_buffers => {
                self.upload_pool.push(buf);
            }
            PoolType::Storage if self.storage_pool.len() < self.max_buffers => {
                self.storage_pool.push(buf);
            }
            _ => {} // Drop buffer if pool is full
        }
    }
}

pub enum PoolType {
    Upload,
    Storage,
}
