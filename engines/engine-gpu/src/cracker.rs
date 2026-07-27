use std::sync::Arc;
use wgpu::*;

use crate::{GpuEngine, pipeline::ComputePipeline, error::GpuError};

const WGSL_MD5: &str = include_str!("shaders/md5.wgsl");
const WGSL_SHA1: &str = include_str!("shaders/sha1.wgsl");
const WGSL_SHA256: &str = include_str!("shaders/sha256.wgsl");
const WGSL_NTLM: &str = include_str!("shaders/ntlm.wgsl");

pub struct GpuCracker {
    engine: Arc<GpuEngine>,
    pipelines: Vec<(String, ComputePipeline)>,
    batch_size: u32,
}

impl GpuCracker {
    pub async fn new(engine: Arc<GpuEngine>) -> Self {
        let mut pipelines = Vec::new();
        if let Ok(p) = Self::build_pipeline(&engine, WGSL_MD5, "md5").await {
            pipelines.push(("md5".to_string(), p));
        }
        if let Ok(p) = Self::build_pipeline(&engine, WGSL_SHA1, "sha1").await {
            pipelines.push(("sha1".to_string(), p));
        }
        if let Ok(p) = Self::build_pipeline(&engine, WGSL_SHA256, "sha256").await {
            pipelines.push(("sha256".to_string(), p));
        }
        if let Ok(p) = Self::build_pipeline(&engine, WGSL_NTLM, "ntlm").await {
            pipelines.push(("ntlm".to_string(), p));
        }
        let count = pipelines.len();
        log::info!("GPU: {} compute pipelines built", count);
        GpuCracker {
            engine,
            pipelines,
            batch_size: 64,
        }
    }

    async fn build_pipeline(
        engine: &GpuEngine,
        source: &str,
        label: &str,
    ) -> Result<ComputePipeline, GpuError> {
        let shader = engine.device.create_shader_module(ShaderModuleDescriptor {
            label: Some(&format!("{label} shader")),
            source: ShaderSource::Wgsl(source.into()),
        });

        // Layout: binding 0 = input candidates, binding 1 = output results
        let bind_group_layout = engine.device.create_bind_group_layout(&BindGroupLayoutDescriptor {
            label: Some(&format!("{label} bind group layout")),
            entries: &[
                BindGroupLayoutEntry {
                    binding: 0,
                    visibility: ShaderStages::COMPUTE,
                    ty: BindingType::Buffer {
                        ty: BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                BindGroupLayoutEntry {
                    binding: 1,
                    visibility: ShaderStages::COMPUTE,
                    ty: BindingType::Buffer {
                        ty: BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = engine.device.create_pipeline_layout(&PipelineLayoutDescriptor {
            label: Some(&format!("{label} pipeline layout")),
            bind_group_layouts: &[Some(&bind_group_layout)],
            immediate_size: 0,
        });

        let pipeline = engine.device.create_compute_pipeline(&ComputePipelineDescriptor {
            label: Some(&format!("{label} pipeline")),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(ComputePipeline {
            pipeline,
            bind_group_layout,
            label: label.to_string(),
        })
    }

    fn find_pipeline(&self, name: &str) -> Option<&ComputePipeline> {
        self.pipelines.iter().find(|(n, _)| n == name).map(|(_, p)| p)
    }

    fn create_bind_group(&self, pipeline: &ComputePipeline, input: &Buffer, output: &Buffer) -> BindGroup {
        self.engine.device.create_bind_group(&BindGroupDescriptor {
            label: Some(&format!("{} bind group", pipeline.label)),
            layout: &pipeline.bind_group_layout,
            entries: &[
                BindGroupEntry { binding: 0, resource: input.as_entire_binding() },
                BindGroupEntry { binding: 1, resource: output.as_entire_binding() },
            ],
        })
    }

    pub fn dispatch_batch(&self, hash_type: &str, candidates: &[u8]) -> Result<Vec<bool>, GpuError> {
        let pipeline = self.find_pipeline(hash_type)
            .ok_or(GpuError::UnsupportedHash)?;

        let input_size = candidates.len() as u64;
        let batch = candidates.len() as u32 / 64; // 64 bytes per password
        let output_size = (batch as u64) * 4; // u32 per result

        let input_buf = self.engine.device.create_buffer(&BufferDescriptor {
            label: Some("gpu input candidates"),
            size: input_size.max(64),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let output_buf = self.engine.device.create_buffer(&BufferDescriptor {
            label: Some("gpu output results"),
            size: output_size.max(64),
            usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let readback_buf = self.engine.device.create_buffer(&BufferDescriptor {
            label: Some("gpu readback buffer"),
            size: output_size.max(64),
            usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Write input
        {
            let mut encoder = self.engine.device.create_command_encoder(&CommandEncoderDescriptor {
                label: Some("gpu write encoder"),
            });
            encoder.write_buffer(&input_buf, 0, candidates);
            let bind_group = self.create_bind_group(pipeline, &input_buf, &output_buf);
            let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor {
                label: Some(&format!("{} compute pass", pipeline.label)),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&pipeline.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(batch, 1, 1);
            drop(cpass);
            encoder.copy_buffer_to_buffer(&output_buf, 0, &readback_buf, 0, output_size);
            self.engine.queue.submit(std::iter::once(encoder.finish()));
        }

        // Read back results (blocking poll for simplicity)
        let readback_slice = readback_buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        readback_slice.map_async(MapMode::Read, move |r| { let _ = tx.send(r); });
        self.engine.device.poll(wgpu::PollType::Wait).unwrap_or_default();

        if rx.recv().is_err() {
            return Err(GpuError::Timeout);
        }

        let data = readback_slice.get_mapped_range();
        let results: Vec<bool> = data.chunks(4)
            .map(|chunk| {
                let val = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                val != 0
            })
            .collect();
        drop(data);
        readback_buf.unmap();

        Ok(results)
    }

    pub fn verify_md5(&self, password: &[u8], target_hex: &str) -> bool {
        // Fallback to CPU verification — GPU path dispatches batch only
        use md5::{Md5, Digest};
        let mut hasher = Md5::new();
        hasher.update(password);
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(target_hex)
    }

    pub fn verify_sha256(&self, password: &[u8], target_hex: &str) -> bool {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password);
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(target_hex)
    }

    pub fn verify_ntlm(&self, password: &[u8], target_hex: &str) -> bool {
        use md4::{Md4, Digest};
        let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut hasher = Md4::new();
        hasher.update(&utf16);
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(target_hex)
    }

    pub fn verify_sha1(&self, password: &[u8], target_hex: &str) -> bool {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();
        hasher.update(password);
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(target_hex)
    }

    pub fn batch_verify(&self, hash_type: &str, passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
        // Pack passwords for GPU dispatch (64 bytes each, padded)
        let batch = passwords.len().min(1024);
        let mut packed = Vec::with_capacity(batch * 64);
        for pw in passwords.iter().take(batch) {
            let mut buf = [0u8; 64];
            let len = pw.len().min(63);
            buf[..len].copy_from_slice(&pw[..len]);
            buf[63] = len as u8;
            packed.extend_from_slice(&buf);
        }

        if let Ok(gpu_results) = self.dispatch_batch(hash_type, &packed) {
            // Extend with CPU fallback for any remaining
            let mut all: Vec<bool> = gpu_results.into_iter().map(|r| r).collect();
            for (pw, target) in passwords.iter().skip(batch).zip(targets.iter().skip(batch)) {
                let ok = match hash_type {
                    "md5" => self.verify_md5(pw, target),
                    "sha256" => self.verify_sha256(pw, target),
                    "sha1" => self.verify_sha1(pw, target),
                    "ntlm" => self.verify_ntlm(pw, target),
                    _ => false,
                };
                all.push(ok);
            }
            all
        } else {
            passwords.iter().zip(targets).map(|(pw, target)| match hash_type {
                "md5" => self.verify_md5(pw, target),
                "sha256" => self.verify_sha256(pw, target),
                "sha1" => self.verify_sha1(pw, target),
                "ntlm" => self.verify_ntlm(pw, target),
                _ => false,
            }).collect()
        }
    }
}
