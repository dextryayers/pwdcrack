//! Hash dispatch onto the GPU.
//!
//! Every supported kernel uses one bind layout, documented in `md5.wgsl`:
//! candidates, a per candidate match flag, the target digest, and the count.
//! NTLM is MD4 over UTF-16LE input, so it shares the MD4 pipeline and differs
//! only in how the host packs each candidate.

use std::sync::Arc;
use wgpu::*;

use crate::{GpuEngine, pipeline::ComputePipeline, error::GpuError, buffer::{GpuBufferPool, PoolType}};

const WGSL_MD5: &str = include_str!("shaders/md5.wgsl");
const WGSL_SHA1: &str = include_str!("shaders/sha1.wgsl");
const WGSL_SHA256: &str = include_str!("shaders/sha256.wgsl");
const WGSL_SHA512: &str = include_str!("shaders/sha512.wgsl");
const WGSL_MD4: &str = include_str!("shaders/md4.wgsl");
const WGSL_RIPEMD160: &str = include_str!("shaders/ripemd160.wgsl");
const WGSL_BLAKE2B: &str = include_str!("shaders/blake2b.wgsl");

/// Bytes per packed candidate: 16 message words and the byte length.
pub const CANDIDATE_BYTES: usize = 68;
/// Longest message the kernels accept.
pub const MAX_MESSAGE: usize = 64;
/// Bytes the target digest buffer is declared with.
const TARGET_BYTES: usize = 64;

/// Hash types that have a working kernel.
pub const HASH_TYPES: [&str; 8] = [
    "md5", "md4", "ntlm", "sha1", "sha256", "sha512", "ripemd160", "blake2b",
];

/// Digest size in bytes for a supported hash type.
pub fn digest_len(hash_type: &str) -> Option<usize> {
    match hash_type {
        "md5" | "md4" | "ntlm" => Some(16),
        "sha1" | "ripemd160" => Some(20),
        "sha256" => Some(32),
        "sha512" | "blake2b" => Some(64),
        _ => None,
    }
}

pub struct GpuCracker {
    engine: Arc<GpuEngine>,
    pipelines: Vec<(String, ComputePipeline)>,
    pool: std::sync::Mutex<GpuBufferPool>,
    batch_size: usize,
}

impl GpuCracker {
    pub async fn new(engine: Arc<GpuEngine>) -> Self {
        let sources: [(&str, &str); 7] = [
            ("md5", WGSL_MD5),
            ("sha1", WGSL_SHA1),
            ("sha256", WGSL_SHA256),
            ("sha512", WGSL_SHA512),
            ("md4", WGSL_MD4),
            ("ripemd160", WGSL_RIPEMD160),
            ("blake2b", WGSL_BLAKE2B),
        ];

        let mut pipelines = Vec::new();
        for (name, source) in sources {
            match Self::build_pipeline(&engine, source, name).await {
                Ok(p) => pipelines.push((name.to_string(), p)),
                // A shader that does not compile must be named. Silently dropping
                // it, as the previous version did, turns a GPU into a CPU engine
                // without saying so.
                Err(e) => log::warn!("GPU: {name} pipeline unavailable: {e}"),
            }
        }
        let count = pipelines.len();

        // P5.3.02: size the batch so the input buffer stays under 80 percent of
        // the adapter's storage binding limit, with a floor of one workgroup and
        // a ceiling that keeps a single dispatch's readback small.
        let limit = engine.device.limits().max_storage_buffer_binding_size as usize;
        let batch_size = ((limit / 10) * 8 / CANDIDATE_BYTES).clamp(64, 1 << 20);

        log::info!(
            "GPU: {count} of {} compute pipelines built, batch {batch_size}",
            sources.len()
        );

        let pool = GpuBufferPool::new(engine.device.clone(), 32);
        GpuCracker {
            engine,
            pipelines,
            pool: std::sync::Mutex::new(pool),
            batch_size,
        }
    }

    /// Names of the hash types whose pipeline was created.
    pub fn available(&self) -> Vec<&str> {
        self.pipelines.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Batch size used by [`Self::verify_many`].
    pub fn batch_size(&self) -> usize {
        self.batch_size
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

        let buffer_entry = |binding: u32, ty: BufferBindingType| BindGroupLayoutEntry {
            binding,
            visibility: ShaderStages::COMPUTE,
            ty: BindingType::Buffer {
                ty,
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        };

        let bind_group_layout = engine.device.create_bind_group_layout(&BindGroupLayoutDescriptor {
            label: Some(&format!("{label} bind group layout")),
            entries: &[
                buffer_entry(0, BufferBindingType::Storage { read_only: true }),
                buffer_entry(1, BufferBindingType::Storage { read_only: false }),
                buffer_entry(2, BufferBindingType::Storage { read_only: true }),
                buffer_entry(3, BufferBindingType::Uniform),
            ],
        });

        let pipeline_layout = engine.device.create_pipeline_layout(&PipelineLayoutDescriptor {
            label: Some(&format!("{label} pipeline layout")),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
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

    fn find_pipeline(&self, hash_type: &str) -> Option<&ComputePipeline> {
        // NTLM is MD4 over UTF-16LE; one kernel serves both.
        let kernel = if hash_type == "ntlm" { "md4" } else { hash_type };
        self.pipelines.iter().find(|(n, _)| n == kernel).map(|(_, p)| p)
    }

    fn create_bind_group(&self, pipeline: &ComputePipeline, input: &Buffer, output: &Buffer, target: &Buffer, count: &Buffer) -> BindGroup {
        self.engine.device.create_bind_group(&BindGroupDescriptor {
            label: Some(&format!("{} bind group", pipeline.label)),
            layout: &pipeline.bind_group_layout,
            entries: &[
                BindGroupEntry { binding: 0, resource: input.as_entire_binding() },
                BindGroupEntry { binding: 1, resource: output.as_entire_binding() },
                BindGroupEntry { binding: 2, resource: target.as_entire_binding() },
                BindGroupEntry { binding: 3, resource: count.as_entire_binding() },
            ],
        })
    }

    /// Decodes a target digest into the 64 byte buffer the kernels bind.
    ///
    /// Every digest byte keeps its position, and each four byte group is read by
    /// the shader as one little endian word. Kernels whose standard output is big
    /// endian byte swap their state before comparing.
    fn target_words(target_hex: &str, digest_len: usize) -> Result<[u32; 16], GpuError> {
        let hex = target_hex.trim();
        let bytes = hex::decode(hex)
            .map_err(|e| GpuError::Other(format!("target is not hex: {e}")))?;
        if bytes.len() != digest_len {
            return Err(GpuError::Other(format!(
                "target is {} bytes, this hash needs {digest_len}",
                bytes.len()
            )));
        }
        let mut words = [0u32; 16];
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let mut four = [0u8; 4];
            four[..chunk.len()].copy_from_slice(chunk);
            words[i] = u32::from_le_bytes(four);
        }
        Ok(words)
    }

    /// Packs one candidate. Returns [`None`] when it cannot be represented: more
    /// than 64 bytes, or NTLM input that is not valid UTF-8.
    fn pack(hash_type: &str, password: &[u8], out: &mut [u8; CANDIDATE_BYTES]) -> Option<()> {
        let mut message = [0u8; MAX_MESSAGE];
        let len = if hash_type == "ntlm" {
            let text = std::str::from_utf8(password).ok()?;
            let mut n = 0;
            for unit in text.encode_utf16() {
                if n + 2 > MAX_MESSAGE {
                    return None;
                }
                message[n..n + 2].copy_from_slice(&unit.to_le_bytes());
                n += 2;
            }
            n
        } else {
            if password.len() > MAX_MESSAGE {
                return None;
            }
            message[..password.len()].copy_from_slice(password);
            password.len()
        };

        for i in 0..16 {
            let word = u32::from_le_bytes([
                message[4 * i],
                message[4 * i + 1],
                message[4 * i + 2],
                message[4 * i + 3],
            ]);
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[64..68].copy_from_slice(&(len as u32).to_le_bytes());
        Some(())
    }

    /// Runs one packed batch and returns one flag per candidate.
    fn dispatch_batch(&self, hash_type: &str, candidates: &[u8], target_hex: &str) -> Result<Vec<bool>, GpuError> {
        let pipeline = self.find_pipeline(hash_type).ok_or(GpuError::UnsupportedHash)?;
        let digest_len = digest_len(hash_type).ok_or(GpuError::UnsupportedHash)?;
        if candidates.len() % CANDIDATE_BYTES != 0 {
            return Err(GpuError::Other(format!(
                "packed input is {} bytes, not a multiple of {CANDIDATE_BYTES}",
                candidates.len()
            )));
        }
        let num_candidates = candidates.len() / CANDIDATE_BYTES;
        if num_candidates == 0 {
            return Ok(Vec::new());
        }
        let target = Self::target_words(target_hex, digest_len)?;

        let input_size = candidates.len() as u64;
        let output_size = (num_candidates as u64) * 4;
        let workgroups = (num_candidates as u32).div_ceil(64);

        let mut pool = self.pool.lock().unwrap();

        let input_buf = pool.get_storage_buffer(input_size.max(4));
        let output_buf = pool.get_storage_buffer(output_size.max(4));
        let readback_buf = pool.get_readback_buffer(output_size.max(4));
        let target_buf = pool.get_storage_buffer(TARGET_BYTES as u64);
        let count_buf = self.engine.device.create_buffer(&BufferDescriptor {
            label: Some("count uniform"),
            size: 4,
            usage: BufferUsages::UNIFORM | BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        self.engine.queue.write_buffer(&input_buf.buffer, 0, candidates);
        self.engine.queue.write_buffer(&target_buf.buffer, 0, bytemuck::cast_slice(&target));
        self.engine.queue.write_buffer(&count_buf, 0, &(num_candidates as u32).to_ne_bytes());

        let mut encoder = self.engine.device.create_command_encoder(&CommandEncoderDescriptor {
            label: Some("gpu compute encoder"),
        });
        let bind_group = self.create_bind_group(pipeline, &input_buf.buffer, &output_buf.buffer, &target_buf.buffer, &count_buf);
        {
            let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor {
                label: Some(&format!("{} compute pass", pipeline.label)),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&pipeline.pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            cpass.dispatch_workgroups(workgroups, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&output_buf.buffer, 0, &readback_buf.buffer, 0, output_size);
        self.engine.queue.submit(std::iter::once(encoder.finish()));

        let results = {
            let readback_slice = readback_buf.buffer.slice(..);
            let (tx, rx) = std::sync::mpsc::channel();
            readback_slice.map_async(MapMode::Read, move |r| { let _ = tx.send(r); });
            self.engine.device.poll(wgpu::PollType::Wait).ok();

            if rx.recv().is_err() {
                pool.return_buffer(input_buf, PoolType::Storage);
                pool.return_buffer(output_buf, PoolType::Storage);
                pool.return_buffer(target_buf, PoolType::Storage);
                return Err(GpuError::Timeout);
            }

            let data = readback_slice.get_mapped_range();
            let r: Vec<bool> = data.chunks_exact(4)
                .map(|chunk| u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) != 0)
                .collect();
            drop(data);
            r
        };
        readback_buf.buffer.unmap();

        pool.return_buffer(input_buf, PoolType::Storage);
        pool.return_buffer(output_buf, PoolType::Storage);
        pool.return_buffer(readback_buf, PoolType::Readback);
        pool.return_buffer(target_buf, PoolType::Storage);

        Ok(results)
    }

    /// Checks many candidates against one target, on the GPU when possible.
    ///
    /// This is the shape an attack uses: one digest, a stream of candidates. It
    /// replaces `batch_verify`, which paired each password with a different
    /// target and then fed every password to one target on the GPU.
    pub fn verify_many(&self, hash_type: &str, passwords: &[&[u8]], target_hex: &str) -> Vec<bool> {
        let mut out: Vec<Option<bool>> = vec![None; passwords.len()];
        let mut packed = Vec::with_capacity(self.batch_size * CANDIDATE_BYTES);
        let mut indices = Vec::with_capacity(self.batch_size);

        let flush = |packed: &mut Vec<u8>, indices: &mut Vec<usize>, out: &mut Vec<Option<bool>>| {
            if indices.is_empty() {
                return;
            }
            match self.dispatch_batch(hash_type, packed, target_hex) {
                Ok(flags) if flags.len() == indices.len() => {
                    for (i, flag) in indices.iter().zip(flags) {
                        out[*i] = Some(flag);
                    }
                }
                Ok(flags) => {
                    log::warn!("GPU: {} flags for {} candidates", flags.len(), indices.len());
                }
                Err(e) => {
                    log::warn!("GPU dispatch failed, using CPU for this batch: {e}");
                }
            }
            packed.clear();
            indices.clear();
        };

        for (i, password) in passwords.iter().enumerate() {
            let mut buf = [0u8; CANDIDATE_BYTES];
            if Self::pack(hash_type, password, &mut buf).is_none() {
                continue;
            }
            packed.extend_from_slice(&buf);
            indices.push(i);
            if indices.len() == self.batch_size {
                flush(&mut packed, &mut indices, &mut out);
            }
        }
        flush(&mut packed, &mut indices, &mut out);

        out.into_iter()
            .zip(passwords)
            .map(|(flag, password)| flag.unwrap_or_else(|| self.verify_on_cpu(hash_type, password, target_hex)))
            .collect()
    }

    fn verify_on_cpu(&self, hash_type: &str, password: &[u8], target_hex: &str) -> bool {
        use sha2::Digest;
        let computed: Option<Vec<u8>> = match hash_type {
            "md5" => {
                let mut h = md5::Md5::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "sha1" => {
                let mut h = sha1::Sha1::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "sha256" => {
                let mut h = sha2::Sha256::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "sha512" => {
                let mut h = sha2::Sha512::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "md4" => {
                let mut h = md4::Md4::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "ntlm" => {
                let mut h = md4::Md4::new();
                let text = std::str::from_utf8(password).ok()?;
                let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                h.update(&utf16);
                Some(h.finalize().to_vec())
            }
            "ripemd160" => {
                let mut h = ripemd::Ripemd160::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            "blake2b" => {
                let mut h = blake2::Blake2b512::new();
                h.update(password);
                Some(h.finalize().to_vec())
            }
            _ => None,
        };
        match computed {
            Some(bytes) => hex::encode(bytes).eq_ignore_ascii_case(target_hex.trim()),
            None => false,
        }
    }
}
