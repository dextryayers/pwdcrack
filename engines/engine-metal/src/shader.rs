pub struct MetalShader {
    pub name: String,
    pub source: String,
    pub function: String,
}

impl MetalShader {
    pub fn new(name: &str, source: &str, function: &str) -> Self {
        Self {
            name: name.to_string(),
            source: source.to_string(),
            function: function.to_string(),
        }
    }

    pub fn md5_kernel() -> Self {
        Self::new(
            "md5_kernel",
            include_str!("../shaders/md5.metal"),
            "md5_compute",
        )
    }

    pub fn sha1_kernel() -> Self {
        Self::new(
            "sha1_kernel",
            include_str!("../shaders/sha1.metal"),
            "sha1_compute",
        )
    }

    pub fn sha256_kernel() -> Self {
        Self::new(
            "sha256_kernel",
            include_str!("../shaders/sha256.metal"),
            "sha256_compute",
        )
    }

    pub fn compile(&self) -> Result<Vec<u32>, String> {
        let spirv = self.source.as_bytes().to_vec();
        let words: Vec<u32> = spirv.chunks(4).map(|c| {
            let mut buf = [0u8; 4];
            for (i, &b) in c.iter().enumerate() {
                buf[i] = b;
            }
            u32::from_le_bytes(buf)
        }).collect();
        Ok(words)
    }
}
