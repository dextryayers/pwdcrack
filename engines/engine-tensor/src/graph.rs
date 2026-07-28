use crate::tensor::Tensor;

#[derive(Debug, Clone)]
pub enum GraphNode {
    Input { name: String, shape: Vec<usize> },
    MatMul { name: String, a: String, b: String },
    Add { name: String, a: String, b: String },
    Relu { name: String, input: String },
    Sigmoid { name: String, input: String },
    Output { name: String, input: String },
}

#[derive(Debug)]
pub struct ComputeGraph {
    nodes: Vec<GraphNode>,
    tensors: std::collections::HashMap<String, Tensor>,
}

impl ComputeGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            tensors: std::collections::HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.push(node);
    }

    pub fn set_tensor(&mut self, name: &str, tensor: Tensor) {
        self.tensors.insert(name.to_string(), tensor);
    }

    pub fn get_tensor(&self, name: &str) -> Option<&Tensor> {
        self.tensors.get(name)
    }

    pub fn execute(&mut self) -> Result<(), String> {
        for node in &self.nodes.clone() {
            match node {
                GraphNode::MatMul { name, a, b } => {
                    let ta = self.tensors.get(a).ok_or_else(|| format!("Missing tensor: {}", a))?;
                    let tb = self.tensors.get(b).ok_or_else(|| format!("Missing tensor: {}", b))?;
                    let result = ta.matmul(tb)?;
                    self.tensors.insert(name.clone(), result);
                }
                GraphNode::Add { name, a, b } => {
                    let ta = self.tensors.get(a).ok_or_else(|| format!("Missing tensor: {}", a))?;
                    let tb = self.tensors.get(b).ok_or_else(|| format!("Missing tensor: {}", b))?;
                    let result = ta.add(tb)?;
                    self.tensors.insert(name.clone(), result);
                }
                GraphNode::Relu { name, input } => {
                    let t = self.tensors.get(input).ok_or_else(|| format!("Missing tensor: {}", input))?;
                    let data: Vec<f32> = t.data.iter().map(|&x| if x > 0.0 { x } else { 0.0 }).collect();
                    self.tensors.insert(name.clone(), Tensor::new(data, t.shape.clone()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}
