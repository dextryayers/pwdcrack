pub struct TpuModel {
    pub name: String,
    pub version: String,
    pub input_size: usize,
    pub output_size: usize,
    graph: Vec<u8>,
}

impl TpuModel {
    pub fn new(name: &str, version: &str, input_size: usize, output_size: usize) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            input_size,
            output_size,
            graph: Vec::new(),
        }
    }

    pub fn hash_classifier() -> Self {
        Self::new("hash_classifier", "1.0", 256, 160)
    }

    pub fn pattern_detector() -> Self {
        Self::new("pattern_detector", "1.0", 128, 64)
    }

    pub fn load_tflite(&mut self, data: &[u8]) {
        self.graph = data.to_vec();
    }

    pub fn predict(&self, input: &[f32]) -> Vec<f32> {
        let _ = input;
        vec![0.0; self.output_size]
    }

    pub fn is_loaded(&self) -> bool {
        !self.graph.is_empty()
    }
}
