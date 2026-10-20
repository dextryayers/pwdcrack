// Temporary diagnostic: dispatch the real MD5 shader with its final line swapped
// for four state writes, then print the digest for "abc".

use engine_gpu::cracker::{CANDIDATE_BYTES, GpuCracker};
use wgpu::*;

#[test]
fn dump_md5_state() {
    let engine = pollster::block_on(engine_gpu::GpuEngine::init()).expect("gpu");
    let device = &engine.device;
    let queue = &engine.queue;

    let source = include_str!("../src/shaders/md5.wgsl").replace("i < 64u", "i < 16u").replace(
        "results[idx] = select(0u, 1u, compare(st));",
        "results[4u*idx] = st[0]; results[4u*idx+1u]=st[1]; results[4u*idx+2u]=st[2]; results[4u*idx+3u]=st[3];",
    );

    let module = device.create_shader_module(ShaderModuleDescriptor {
        label: Some("dump"),
        source: ShaderSource::Wgsl(source.into()),
    });
    let entry = |binding, ty| BindGroupLayoutEntry {
        binding,
        visibility: ShaderStages::COMPUTE,
        ty: BindingType::Buffer { ty, has_dynamic_offset: false, min_binding_size: None },
        count: None,
    };
    let layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            entry(0, BufferBindingType::Storage { read_only: true }),
            entry(1, BufferBindingType::Storage { read_only: false }),
            entry(2, BufferBindingType::Storage { read_only: true }),
            entry(3, BufferBindingType::Uniform),
        ],
    });
    let pl = device.create_pipeline_layout(&PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
        label: None,
        layout: Some(&pl),
        module: &module,
        entry_point: Some("main"),
        compilation_options: Default::default(),
        cache: None,
    });

    let packed = GpuCracker::pack_candidate("md5", b"abc").unwrap();
    let input = device.create_buffer(&BufferDescriptor {
        label: None, size: 68, usage: BufferUsages::STORAGE | BufferUsages::COPY_DST, mapped_at_creation: false,
    });
    let output = device.create_buffer(&BufferDescriptor {
        label: None, size: 32, usage: BufferUsages::STORAGE | BufferUsages::COPY_SRC, mapped_at_creation: false,
    });
    let readback = device.create_buffer(&BufferDescriptor {
        label: None, size: 32, usage: BufferUsages::MAP_READ | BufferUsages::COPY_DST, mapped_at_creation: false,
    });
    let first = u32::from_str_radix("90015098", 16).unwrap();
    let target: [u32; 16] = [first, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let target_buf = device.create_buffer(&BufferDescriptor {
        label: None, size: 64, usage: BufferUsages::STORAGE | BufferUsages::COPY_DST, mapped_at_creation: false,
    });
    let count = device.create_buffer(&BufferDescriptor {
        label: None, size: 4, usage: BufferUsages::UNIFORM | BufferUsages::COPY_DST, mapped_at_creation: false,
    });
    queue.write_buffer(&input, 0, &packed);
    queue.write_buffer(&target_buf, 0, bytemuck::cast_slice(&target));
    queue.write_buffer(&count, 0, &1u32.to_ne_bytes());

    let bind = device.create_bind_group(&BindGroupDescriptor {
        label: None,
        layout: &layout,
        entries: &[
            BindGroupEntry { binding: 0, resource: input.as_entire_binding() },
            BindGroupEntry { binding: 1, resource: output.as_entire_binding() },
            BindGroupEntry { binding: 2, resource: target_buf.as_entire_binding() },
            BindGroupEntry { binding: 3, resource: count.as_entire_binding() },
        ],
    });
    let mut enc = device.create_command_encoder(&CommandEncoderDescriptor { label: None });
    {
        let mut pass = enc.begin_compute_pass(&ComputePassDescriptor { label: None, timestamp_writes: None });
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bind, &[]);
        pass.dispatch_workgroups(1, 1, 1);
    }
    enc.copy_buffer_to_buffer(&output, 0, &readback, 0, 32);
    queue.submit(std::iter::once(enc.finish()));
    let slice = readback.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(MapMode::Read, move |r| { let _ = tx.send(r); });
    device.poll(PollType::Wait).unwrap();
    rx.recv().unwrap().unwrap();
    let data = slice.get_mapped_range();
    let words: Vec<u32> = data.chunks_exact(4).map(|c| u32::from_ne_bytes([c[0], c[1], c[2], c[3]])).collect();
    eprintln!(
        "md5(abc) state words: {}",
        words.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(" ")
    );
    eprintln!("byte order in memory: {}", hex::encode(&data[..16]));
    assert_eq!(CANDIDATE_BYTES, 68);
}
