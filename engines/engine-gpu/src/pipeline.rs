//! Compute pipeline builder — compiles WGSL shaders, creates pipelines

use wgpu::*;
use crate::error::GpuError;

pub struct ComputePipeline {
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: BindGroupLayout,
}

impl ComputePipeline {
    pub async fn new(
        device: &Device,
        shader_source: &str,
        label: &str,
        buffers: &[BufferBindingType],
    ) -> Result<Self, GpuError> {
        let shader = device.create_shader_module(ShaderModuleDescriptor {
            label: Some(&format!("{label} shader")),
            source: ShaderSource::Wgsl(shader_source.into()),
        });

        let mut layout_entries = Vec::new();
        for (i, buf_type) in buffers.iter().enumerate() {
            layout_entries.push(BindGroupLayoutEntry {
                binding: i as u32,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    ty: *buf_type,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            });
        }

        let bind_group_layout = device.create_bind_group_layout(&BindGroupLayoutDescriptor {
            label: Some(&format!("{label} bind group layout")),
            entries: &layout_entries,
        });

        let pipeline_layout = device.create_pipeline_layout(&PipelineLayoutDescriptor {
            label: Some(&format!("{label} pipeline layout")),
            bind_group_layouts: &[Some(&bind_group_layout)],
            immediate_size: 0,
        });

        let pipeline = device.create_compute_pipeline(&ComputePipelineDescriptor {
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
        })
    }

    pub fn create_bind_group(
        &self,
        device: &Device,
        buffers: &[&Buffer],
    ) -> BindGroup {
        let mut entries = Vec::new();
        for (i, buf) in buffers.iter().enumerate() {
            entries.push(BindGroupEntry {
                binding: i as u32,
                resource: buf.as_entire_binding(),
            });
        }

        device.create_bind_group(&BindGroupDescriptor {
            label: Some("compute bind group"),
            layout: &self.bind_group_layout,
            entries: &entries,
        })
    }

    pub fn dispatch(&self, encoder: &mut CommandEncoder, bind_group: &BindGroup, x: u32, y: u32, z: u32) {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor {
            label: Some("crack compute pass"),
            timestamp_writes: None,
        });
        cpass.set_pipeline(&self.pipeline);
        cpass.set_bind_group(0, bind_group, &[]);
        cpass.dispatch_workgroups(x, y, z);
    }
}
