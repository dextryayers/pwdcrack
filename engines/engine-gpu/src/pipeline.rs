use wgpu::*;
use crate::error::GpuError;
use std::collections::HashMap;

pub struct ComputePipeline {
    pub pipeline: wgpu::ComputePipeline,
    pub bind_group_layout: BindGroupLayout,
    pub label: String,
}

impl ComputePipeline {
    pub async fn new(
        device: &Device,
        shader_source: &str,
        label: &str,
        buffers: &[(u32, BufferBindingType)],
    ) -> Result<Self, GpuError> {
        let shader = device.create_shader_module(ShaderModuleDescriptor {
            label: Some(&format!("{label} shader")),
            source: ShaderSource::Wgsl(shader_source.into()),
        });

        let mut layout_entries = Vec::new();
        for &(binding, buf_type) in buffers {
            layout_entries.push(BindGroupLayoutEntry {
                binding,
                visibility: ShaderStages::COMPUTE,
                ty: BindingType::Buffer {
                    ty: buf_type,
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
            label: label.to_string(),
        })
    }

    pub fn create_bind_group(&self, device: &Device, buffers: &[&Buffer]) -> BindGroup {
        let mut entries = Vec::new();
        for (i, buf) in buffers.iter().enumerate() {
            entries.push(BindGroupEntry {
                binding: i as u32,
                resource: buf.as_entire_binding(),
            });
        }

        device.create_bind_group(&BindGroupDescriptor {
            label: Some(&format!("{} bind group", self.label)),
            layout: &self.bind_group_layout,
            entries: &entries,
        })
    }

    pub fn dispatch(&self, encoder: &mut CommandEncoder, bind_group: &BindGroup, x: u32, y: u32, z: u32) {
        let mut cpass = encoder.begin_compute_pass(&ComputePassDescriptor {
            label: Some(&format!("{} compute pass", self.label)),
            timestamp_writes: None,
        });
        cpass.set_pipeline(&self.pipeline);
        cpass.set_bind_group(0, bind_group, &[]);
        cpass.dispatch_workgroups(x, y, z);
    }
}

pub struct PipelineCache {
    pipelines: HashMap<String, ComputePipeline>,
}

impl PipelineCache {
    pub fn new() -> Self {
        PipelineCache {
            pipelines: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&ComputePipeline> {
        self.pipelines.get(key)
    }

    pub async fn get_or_insert<F>(
        &mut self,
        key: &str,
        device: &Device,
        builder: F,
    ) -> Result<&ComputePipeline, GpuError>
    where
        F: std::future::Future<Output = Result<ComputePipeline, GpuError>>,
    {
        if !self.pipelines.contains_key(key) {
            let pipeline = builder.await?;
            self.pipelines.insert(key.to_string(), pipeline);
        }
        Ok(self.pipelines.get(key).unwrap())
    }

    pub fn remove(&mut self, key: &str) {
        self.pipelines.remove(key);
    }

    pub fn clear(&mut self) {
        self.pipelines.clear();
    }
}
