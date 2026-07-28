use crate::tensor::Tensor;
use crate::graph::{ComputeGraph, GraphNode};
use crate::error::Result;

pub struct TensorCracker {
    graph: ComputeGraph,
    model_loaded: bool,
}

impl TensorCracker {
    pub fn new() -> Self {
        Self {
            graph: ComputeGraph::new(),
            model_loaded: false,
        }
    }

    pub fn is_available(&self) -> bool { true }

    pub fn load_default_model(&mut self) {
        self.graph.add_node(GraphNode::Input {
            name: "input".into(),
            shape: vec![1, 256],
        });
        self.graph.add_node(GraphNode::MatMul {
            name: "hidden".into(),
            a: "input".into(),
            b: "weights".into(),
        });
        self.graph.add_node(GraphNode::Relu {
            name: "activated".into(),
            input: "hidden".into(),
        });
        self.graph.add_node(GraphNode::Output {
            name: "output".into(),
            input: "activated".into(),
        });
        self.graph.set_tensor("weights", Tensor::zeros(vec![256, 160]));
        self.model_loaded = true;
    }

    pub fn crack_dictionary(&self, hash: &[u8], wordlist: &[String]) -> Result<Option<String>> {
        for word in wordlist {
            let digest = md5::compute(word.as_bytes());
            if digest.as_slice() == hash {
                return Ok(Some(word.clone()));
            }
        }
        Ok(None)
    }

    pub fn benchmark(&self) -> Result<u64> {
        let start = std::time::Instant::now();
        let mut count = 0u64;
        while start.elapsed().as_secs() < 1 {
            let _ = md5::compute(b"tensorbench");
            count += 1;
        }
        Ok(count)
    }
}
