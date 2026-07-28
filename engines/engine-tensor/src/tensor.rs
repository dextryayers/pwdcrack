#[derive(Debug, Clone)]
pub struct Tensor {
    pub data: Vec<f32>,
    pub shape: Vec<usize>,
}

impl Tensor {
    pub fn new(data: Vec<f32>, shape: Vec<usize>) -> Self {
        Self { data, shape }
    }

    pub fn zeros(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product();
        Self { data: vec![0.0; size], shape }
    }

    pub fn ones(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product();
        Self { data: vec![1.0; size], shape }
    }

    pub fn reshape(&mut self, new_shape: Vec<usize>) -> Result<(), String> {
        let new_size: usize = new_shape.iter().product();
        if new_size != self.data.len() {
            return Err(format!("Shape mismatch: {} vs {}", new_size, self.data.len()));
        }
        self.shape = new_shape;
        Ok(())
    }

    pub fn matmul(&self, other: &Tensor) -> Result<Tensor, String> {
        if self.shape.len() != 2 || other.shape.len() != 2 {
            return Err("matmul requires 2D tensors".into());
        }
        if self.shape[1] != other.shape[0] {
            return Err(format!("Matrix dim mismatch: {} vs {}", self.shape[1], other.shape[0]));
        }
        let m = self.shape[0];
        let k = self.shape[1];
        let n = other.shape[1];
        let mut result = vec![0.0f32; m * n];
        for i in 0..m {
            for j in 0..n {
                let mut sum = 0.0f32;
                for t in 0..k {
                    sum += self.data[i * k + t] * other.data[t * n + j];
                }
                result[i * n + j] = sum;
            }
        }
        Ok(Tensor::new(result, vec![m, n]))
    }

    pub fn add(&self, other: &Tensor) -> Result<Tensor, String> {
        if self.shape != other.shape {
            return Err("Shape mismatch for addition".into());
        }
        let data: Vec<f32> = self.data.iter().zip(other.data.iter()).map(|(a, b)| a + b).collect();
        Ok(Tensor::new(data, self.shape.clone()))
    }
}
