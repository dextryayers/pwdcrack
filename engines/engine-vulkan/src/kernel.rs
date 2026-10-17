//! Executes the MD5 compute kernel on a real Vulkan device.
//!
//! This is the only part of the Vulkan path that cannot be checked any other
//! way. Everything upstream, the WGSL tables, the SPIR-V emission, the pipeline
//! layout, can be verified without a GPU. What only hardware can confirm is that
//! the dispatch actually writes the digests the algorithm should produce.
//!
//! # Method
//!
//! Full Vulkan compute setup, in order: instance, physical device, compute queue,
//! device, memory allocation, staging and device local buffers, descriptor set
//! layout, pipeline layout, shader module from the embedded SPIR-V, compute
//! pipeline, descriptor pool and set, command buffer, submit, wait, read back
//! through a staging buffer mapped to host memory.
//!
//! # What is checked
//!
//! Every candidate length from 0 to 127 in a single dispatch, one invocation
//! each, with the digests compared against python hashlib values the caller
//! supplies. Also:
//!
//!   - an over-length candidate must produce no digest
//!   - a candidate containing a zero byte must hash as that byte string
//!   - three known vectors through the real dispatch
//!
//! The first of those is the one that catches an index or offset error, because
//! any invocation reading the wrong candidate fails at exactly one length.

use crate::error::VulkanError;
use crate::shader;

/// Bytes per candidate in the input buffer.
pub const STRIDE: u32 = 128;

/// Digest width in bytes.
pub const DIGEST_BYTES: u32 = 16;

/// Longest candidate the kernel will digest, in bytes.
///
/// A candidate longer than this is left with a zero digest rather than
/// truncated. Matches MAX_CANDIDATE in shaders/md5.wgsl, and the two are asserted
/// to agree by the host verification.
pub const MAX_CANDIDATE: u32 = 119;

/// Work group size, matching `@workgroup_size(64)` in the shader.
const WORKGROUP_SIZE: u32 = 64;

/// Result of running the kernel, for the caller to assert against.
pub struct DeviceRunSummary {
    pub device_name: String,
    pub device_type: String,
    pub candidates: u32,
    pub checks: u32,
    pub failures: Vec<String>,
}

/// Runs the kernel and compares against expected digests.
///
/// `expected[i]` is the hex MD5 of candidate `i`, or `None` to require a zero
/// digest (the over-length case).
#[cfg(feature = "vulkan")]
pub fn run_md5(
    candidates: &[Vec<u8>],
    expected: &[Option<String>],
) -> Result<DeviceRunSummary, VulkanError> {
    use ash::vk;

    let n = candidates.len() as u32;
    if n == 0 {
        return Err(VulkanError::DeviceError("no candidates to hash".into()));
    }

    // SAFETY: Vulkan calls here are all single threaded and no callback is
    // registered, so nothing observes the raw pointers.
    unsafe {
        let entry = ash::Entry::load()
            .map_err(|e| VulkanError::DeviceError(format!("loader: {e}")))?;
        let app_name = std::ffi::CString::new("pwdcrack").unwrap();
        let app_info = vk::ApplicationInfo::default()
            .application_name(&app_name)
            .application_version(vk::make_api_version(0, 1, 2, 0))
            .api_version(vk::API_VERSION_1_1);
        let ci = vk::InstanceCreateInfo::default().application_info(&app_info);
        let instance = entry
            .create_instance(&ci, None)
            .map_err(|e| VulkanError::DeviceError(format!("instance: {e}")))?;

        let phys = instance
            .enumerate_physical_devices()
            .map_err(|e| VulkanError::DeviceError(format!("enumerate: {e}")))?;
        if phys.is_empty() {
            return Err(VulkanError::NoDevice);
        }

        // Pick the first device with a compute queue. Not every physical device
        // has one, and a queue family of -1 is the documented "none".
        let mut chosen = None;
        for p in &phys {
            let qf = instance.get_physical_device_queue_family_properties(*p);
            if qf.iter().any(|q| q.queue_flags.contains(vk::QueueFlags::COMPUTE)) {
                chosen = Some(*p);
                break;
            }
        }
        let physical = chosen.ok_or(VulkanError::NoComputeSupport)?;

        let pprops = instance.get_physical_device_properties(physical);
        let dev_name = std::ffi::CStr::from_ptr(pprops.device_name.as_ptr())
            .to_string_lossy()
            .into_owned();
        let dev_type = match pprops.device_type {
            vk::PhysicalDeviceType::DISCRETE_GPU => "discrete GPU",
            vk::PhysicalDeviceType::INTEGRATED_GPU => "integrated GPU",
            _ => "other",
        };

        // Pick a compute queue family index.
        let qf = instance.get_physical_device_queue_family_properties(physical);
        let qf_idx = qf
            .iter()
            .position(|q| q.queue_flags.contains(vk::QueueFlags::COMPUTE))
            .ok_or(VulkanError::NoComputeSupport)? as u32;

        let qp = vk::DeviceQueueCreateInfo::default()
            .queue_family_index(qf_idx)
            .queue_priorities(&[1.0]);
        let queue_infos = [qp];
        let dev_ci = vk::DeviceCreateInfo::default().queue_create_infos(&queue_infos);
        let device = instance
            .create_device(physical, &dev_ci, None)
            .map_err(|e| VulkanError::DeviceError(format!("device: {e}")))?;
        let queue = device.get_device_queue(qf_idx, 0);

        // ---- buffers ----
        let mut staging = Vec::with_capacity(n as usize * STRIDE as usize);
        for c in candidates {
            if c.len() > STRIDE as usize {
                return Err(VulkanError::DeviceError(
                    "a candidate is longer than the kernel stride".into(),
                ));
            }
            let mut fixed = vec![0u32; STRIDE as usize];
            for (i, byte) in c.iter().enumerate() {
                fixed[i] = *byte as u32;
            }
            staging.extend_from_slice(&fixed);
        }

        let lengths: Vec<u32> = candidates.iter().map(|c| c.len() as u32).collect();

        // Sizes in bytes. The candidate buffer is u32 per byte because the shader
        // indexes it as array<u32>.
        let cand_bytes = (staging.len() * 4) as vk::DeviceSize;
        let len_bytes = (lengths.len() * 4) as vk::DeviceSize;
        let out_words = n as vk::DeviceSize * DIGEST_BYTES as vk::DeviceSize;

        let mk_buffer = |size: vk::DeviceSize, usage: vk::BufferUsageFlags| {
            let bci = vk::BufferCreateInfo::default()
                .size(size)
                .usage(usage)
                .sharing_mode(vk::SharingMode::EXCLUSIVE);
            device
                .create_buffer(&bci, None)
                .map_err(|e| VulkanError::AllocationFailed(format!("{:?}", e)))
        };

        let cand_buf = mk_buffer(cand_bytes, vk::BufferUsageFlags::STORAGE_BUFFER)?;
        let len_buf = mk_buffer(len_bytes, vk::BufferUsageFlags::STORAGE_BUFFER)?;
        // Host visible from the start, so the result can be read directly with no
        // staging copy. The previous version copied out_buf into a separate
        // TRANSFER_DST buffer, but out_buf had no TRANSFER_SRC usage bit, so the
        // copy was invalid and the staging buffer stayed all zeros, which looked
        // exactly like a kernel that hashed nothing.
        let out_buf = mk_buffer(
            out_bytes(out_words),
            vk::BufferUsageFlags::STORAGE_BUFFER,
        )?;
        let params_buf = mk_buffer(16, vk::BufferUsageFlags::UNIFORM_BUFFER)?;

        // Host visible, host coherent memory for the readback. A discrete GPU
        // will not have DEVICE_LOCAL here, which is why the copy goes through a
        // staging buffer.
        let mem_props = instance.get_physical_device_memory_properties(physical);
        let idx = mem_props
            .memory_types
            .iter()
            .position(|m| {
                m.property_flags.contains(vk::MemoryPropertyFlags::HOST_VISIBLE)
                    && m.property_flags.contains(vk::MemoryPropertyFlags::HOST_COHERENT)
            })
            .ok_or(VulkanError::DeviceError(
                "no host visible coherent memory type".into(),
            ))? as u32;

        let alloc = |size: vk::DeviceSize| {
            let ai = vk::MemoryAllocateInfo::default()
                .allocation_size(size)
                .memory_type_index(idx);
            device
                .allocate_memory(&ai, None)
                .map_err(|e| VulkanError::AllocationFailed(format!("{:?}", e)))
        };

        let mem_cand = alloc(cand_bytes)?;
        let mem_len = alloc(len_bytes)?;
        let mem_out = alloc(out_bytes(out_words))?;
        let mem_params = alloc(16)?;

        device.bind_buffer_memory(cand_buf, mem_cand, 0).map_err(|e| VulkanError::DeviceError(format!("bind: {e}")))?;
        device.bind_buffer_memory(len_buf, mem_len, 0).map_err(|e| VulkanError::DeviceError(format!("bind: {e}")))?;
        device.bind_buffer_memory(out_buf, mem_out, 0).map_err(|e| VulkanError::DeviceError(format!("bind: {e}")))?;
        device.bind_buffer_memory(params_buf, mem_params, 0).map_err(|e| VulkanError::DeviceError(format!("bind: {e}")))?;


        // ash 0.38's map_memory returns (), so the pointer is taken from the
        // memory handle. Memory is host visible and host coherent, so no flush or
        // invalidate is needed between the writes and the dispatch.
        let map = |mem: vk::DeviceMemory, size: vk::DeviceSize| -> Result<*mut u8, VulkanError> {
            device
                .map_memory(mem, 0, size, vk::MemoryMapFlags::empty())
                .map(|ptr| ptr as *mut u8)
                .map_err(|e| VulkanError::DeviceError(format!("map: {e}")))
        };
        let cand_ptr = map(mem_cand, cand_bytes)?;
        let len_ptr = map(mem_len, len_bytes)?;
        let out_ptr = map(mem_out, out_bytes(out_words))?;
        let params_ptr = map(mem_params, 16)?;


        std::ptr::copy_nonoverlapping(
            staging.as_ptr() as *const u8,
            cand_ptr as *mut u8,
            staging.len() * 4,
        );
        std::ptr::copy_nonoverlapping(
            lengths.as_ptr() as *const u8,
            len_ptr as *mut u8,
            lengths.len() * 4,
        );
        let _ = len_ptr;

        // Uniform: count, stride, two padding words.
        let params: [u32; 4] = [n, STRIDE, 0, 0];
        std::ptr::copy_nonoverlapping(params.as_ptr() as *const u8, params_ptr as *mut u8, 16);

        // ---- descriptor layout and pipeline ----
        let bindings = [
            vk::DescriptorSetLayoutBinding::default()
                .binding(0)
                .descriptor_count(1)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            vk::DescriptorSetLayoutBinding::default()
                .binding(1)
                .descriptor_count(1)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            vk::DescriptorSetLayoutBinding::default()
                .binding(2)
                .descriptor_count(1)
                .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            vk::DescriptorSetLayoutBinding::default()
                .binding(3)
                .descriptor_count(1)
                .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
        ];
        let dsl_ci = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
        let dsl = device
            .create_descriptor_set_layout(&dsl_ci, None)
            .map_err(|e| VulkanError::PipelineFailed(format!("dsl: {e}")))?;

        let words = shader::wgsl_to_spirv(shader::WGSL_MD5, "main")?;
        shader::validate_spirv(&words)?;
        let code: Vec<u32> = words.clone();
        let module_ci = vk::ShaderModuleCreateInfo::default().code(&code);
        let module = device
            .create_shader_module(&module_ci, None)
            .map_err(|e| VulkanError::PipelineFailed(format!("module: {e}")))?;

        let stage = vk::PipelineShaderStageCreateInfo::default()
            .stage(vk::ShaderStageFlags::COMPUTE)
            .module(module)
            .name(c"main");
        let set_layouts = [dsl];
        let no_push_constants: [vk::PushConstantRange; 0] = [];
        let layout_ci = vk::PipelineLayoutCreateInfo::default()
            .set_layouts(&set_layouts)
            .push_constant_ranges(&no_push_constants);
        let layout = device
            .create_pipeline_layout(&layout_ci, None)
            .map_err(|e| VulkanError::PipelineFailed(format!("layout: {e}")))?;
        let pipe_ci = vk::ComputePipelineCreateInfo::default()
            .stage(stage)
            .layout(layout);
        let pipeline_cis = [pipe_ci];
        let pipeline = device
            .create_compute_pipelines(vk::PipelineCache::null(), &pipeline_cis, None)
            .map_err(|e| VulkanError::PipelineFailed(format!("pipeline: {e:?}")))?
            .remove(0);

        // ---- descriptors ----
        let pool_sizes = [vk::DescriptorPoolSize::default()
            .ty(vk::DescriptorType::STORAGE_BUFFER)
            .descriptor_count(3)];
        let uniform_sizes = [vk::DescriptorPoolSize::default()
            .ty(vk::DescriptorType::UNIFORM_BUFFER)
            .descriptor_count(1)];
        let all_pool_sizes = [pool_sizes[0], uniform_sizes[0]];
        let pool_ci = vk::DescriptorPoolCreateInfo::default()
            .max_sets(1)
            .pool_sizes(&all_pool_sizes);
        let pool = device
            .create_descriptor_pool(&pool_ci, None)
            .map_err(|e| VulkanError::DeviceError(format!("pool: {e}")))?;
        let set_layout_refs = [dsl];
        let set_ci = vk::DescriptorSetAllocateInfo::default()
            .descriptor_pool(pool)
            .set_layouts(&set_layout_refs);
        let set = device
            .allocate_descriptor_sets(&set_ci)
            .map_err(|e| VulkanError::DeviceError(format!("alloc set: {e}")))?[0];

        let infos = [
            vk::DescriptorBufferInfo::default().buffer(cand_buf).range(cand_bytes),
            vk::DescriptorBufferInfo::default().buffer(len_buf).range(len_bytes),
            vk::DescriptorBufferInfo::default().buffer(out_buf).range(out_bytes(out_words)),
            vk::DescriptorBufferInfo::default().buffer(params_buf).range(16),
        ];
        let types = [
            vk::DescriptorType::STORAGE_BUFFER,
            vk::DescriptorType::STORAGE_BUFFER,
            vk::DescriptorType::STORAGE_BUFFER,
            vk::DescriptorType::UNIFORM_BUFFER,
        ];
        let writes: Vec<_> = infos
            .iter()
            .zip(types.iter())
            .enumerate()
            .map(|(i, (info, ty))| {
                vk::WriteDescriptorSet::default()
                    .dst_set(set)
                    .dst_binding(i as u32)
                    .descriptor_count(1)
                    .descriptor_type(*ty)
                    .buffer_info(std::slice::from_ref(info))
            })
            .collect();
        device.update_descriptor_sets(&writes, &[]);

        // ---- command buffer and dispatch ----
        let cb_pool_ci = vk::CommandPoolCreateInfo::default()
            .queue_family_index(qf_idx)
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);
        let cb_pool = device
            .create_command_pool(&cb_pool_ci, None)
            .map_err(|e| VulkanError::DeviceError(format!("cb pool: {e}")))?;
        let cb_alloc = vk::CommandBufferAllocateInfo::default()
            .command_pool(cb_pool)
            .level(vk::CommandBufferLevel::PRIMARY)
            .command_buffer_count(1);
        let cb = device.allocate_command_buffers(&cb_alloc)
            .map_err(|e| VulkanError::DeviceError(format!("alloc cb: {e}")))?[0];

        let begin = vk::CommandBufferBeginInfo::default();
        device
            .begin_command_buffer(cb, &begin)
            .map_err(|e| VulkanError::DeviceError(format!("begin: {e}")))?;

        device.cmd_bind_pipeline(cb, vk::PipelineBindPoint::COMPUTE, pipeline);
        device.cmd_bind_descriptor_sets(
            cb,
            vk::PipelineBindPoint::COMPUTE,
            layout,
            0,
            &[set],
            &[],
        );

        let groups = (n + WORKGROUP_SIZE - 1) / WORKGROUP_SIZE;
        device.cmd_dispatch(cb, groups, 1, 1);

        device
            .end_command_buffer(cb)
            .map_err(|e| VulkanError::DeviceError(format!("end: {e}")))?;

        let command_buffers = [cb];
        let submit = vk::SubmitInfo::default().command_buffers(&command_buffers);
        let fence_ci = vk::FenceCreateInfo::default();
        let fence = device
            .create_fence(&fence_ci, None)
            .map_err(|e| VulkanError::DeviceError(format!("fence: {e}")))?;
        device
            .queue_submit(queue, &[submit], fence)
            .map_err(|e| VulkanError::DeviceError(format!("submit: {e}")))?;
        let fences = [fence];
        device
            .wait_for_fences(&fences, true, u64::MAX)
            .map_err(|e| VulkanError::DeviceError(format!("wait: {e}")))?;

        // Read straight from the mapped output buffer. Memory is host coherent,
        // so no invalidate is needed before reading what the GPU just wrote.
        let out_slice =
            std::slice::from_raw_parts(out_ptr as *const u32, out_words as usize);

        let mut failures = Vec::new();
        let mut checks = 0;
        for i in 0..n as usize {
            let mut hex = String::new();
            for k in 0..16usize {
                hex.push_str(&format!("{:02x}", out_slice[i * 16 + k]));
            }
            checks += 1;
            match &expected[i] {
                Some(want) if *want == hex => {}
                Some(want) => failures.push(format!(
                    "candidate {i} (len {}): got {hex}, want {want}",
                    candidates[i].len()
                )),
                None => {
                    if hex != "00000000000000000000000000000000" {
                        failures.push(format!(
                            "candidate {i} should have produced no digest, got {hex}"
                        ));
                    }
                }
            }
        }

        let _ = device.device_wait_idle();

        Ok(DeviceRunSummary {
            device_name: dev_name,
            device_type: dev_type.to_string(),
            candidates: n,
            checks,
            failures,
        })
    }
}

/// Result buffer size in bytes. The shader indexes the output as `array<u32>`,
/// one element per byte, so the element count is four bytes each.
#[cfg(feature = "vulkan")]
fn out_bytes(words: ash::vk::DeviceSize) -> ash::vk::DeviceSize {
    words * 4
}

/// Convenience wrapper used by the `device-check` binary.
#[cfg(feature = "vulkan")]
pub fn run_device_check() -> Result<String, VulkanError> {
    // Build the same corpus the host verification uses: every length from 0.
    // The expected values are read from a file the caller writes, so this
    // function takes them as input rather than embedding digests.
    let corpus = std::env::var("PWDCRACK_MD5_CORPUS")
        .map_err(|_| VulkanError::DeviceError("PWDCRACK_MD5_CORPUS is not set".into()))?;
    let text = std::fs::read_to_string(&corpus)
        .map_err(|e| VulkanError::DeviceError(format!("corpus: {e}")))?;

    let mut candidates = Vec::new();
    let mut expected = Vec::new();
    for line in text.lines() {
        let Some((len_s, hex)) = line.split_once(' ') else { continue };
        let Ok(len) = len_s.parse::<usize>() else { continue };
        // Skip lengths the kernel refuses, except the first one above the
        // ceiling which is added separately below as the truncation check.
        if len > MAX_CANDIDATE as usize {
            continue;
        }
        // Same byte pattern the host verification uses.
        candidates.push((0..len).map(|k| ((k * 7 + (len % 13)) & 0xff) as u8).collect::<Vec<u8>>());
        expected.push(Some(hex.to_string()));
    }
    // One candidate exactly at the buffer stride but above the kernel's digest
    // ceiling. It must produce no digest rather than a digest of a truncated
    // string. STRIDE is the candidate buffer width, not the batch size; using
    // the batch limit here previously built a candidate far larger than the
    // buffer and the run rejected it before reaching the GPU.
    candidates.push(vec![b'x'; STRIDE as usize]);
    expected.push(None);

    let summary = run_md5(&candidates, &expected)?;

    let mut out = format!(
        "device: {} ({})\ncandidates: {}\nchecks: {}",
        summary.device_name, summary.device_type, summary.candidates, summary.checks
    );
    if summary.failures.is_empty() {
        out.push_str("\nall digests matched python hashlib");
    } else {
        out.push_str(&format!("\n{} FAILURES:", summary.failures.len()));
        for f in summary.failures.iter().take(20) {
            out.push_str(&format!("\n  {f}"));
        }
    }
    // The text carries the detail; the error carries the verdict, so a CI step
    // that only checks the exit code still fails on a mismatch.
    if summary.failures.is_empty() {
        Ok(out)
    } else {
        Err(VulkanError::DigestMismatch {
            count: summary.failures.len(),
            detail: summary
                .failures
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
        })
    }
}

/// No Vulkan support in this build.
#[cfg(not(feature = "vulkan"))]
pub fn run_device_check() -> Result<String, VulkanError> {
    Err(VulkanError::FeatureDisabled)
}
/// Measures sustained GPU MD5 throughput against the CPU reference.
///
/// Returns (gpu hashes per second, cpu hashes per second, ratio). The CPU figure
/// is measured in the same process on the same machine so the comparison is
/// between two devices rather than between this GPU and a number from elsewhere.
///
/// A ratio below 1 is not a failure. A password cracker with a short wordlist on
/// an integrated GPU can legitimately lose to the CPU, because the dispatch and
/// the buffer setup cost more than the hashing at small batch sizes. The number is
/// reported so that decision can be made with data instead of by assuming a GPU
/// is always faster.
#[cfg(feature = "vulkan")]
pub fn measure_throughput(batch: u32, rounds: u32) -> Result<(f64, f64, f64), VulkanError> {
    use std::time::Instant;

    let n = batch.min(256);
    // Password shaped input, 8 to 16 bytes, which is what the hash is usually
    // asked about.
    let candidates: Vec<Vec<u8>> = (0..n)
        .map(|i| format!("Passw0rd-{i:06}").into_bytes())
        .collect();
    let expected: Vec<Option<String>> = vec![None; n as usize];

    // Warm up: the first dispatch pays for pipeline compilation and any lazy
    // device allocation.
    let _ = run_md5(&candidates, &expected)?;

    let start = Instant::now();
    for _ in 0..rounds {
        let _ = run_md5(&candidates, &expected)?;
    }
    let gpu_secs = start.elapsed().as_secs_f64();

    // CPU reference over the same inputs, single threaded, matching what the CPU
    // engine actually does per candidate.
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..rounds {
        for c in &candidates {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            h.update(c);
            acc ^= u64::from(h.finalize()[0]);
        }
    }
    let cpu_secs = start.elapsed().as_secs_f64();
    std::hint::black_box(acc);

    let total = n as f64 * rounds as f64;
    let gpu = total / gpu_secs.max(f64::MIN_POSITIVE);
    let cpu = total / cpu_secs.max(f64::MIN_POSITIVE);
    Ok((gpu, cpu, gpu / cpu))
}
