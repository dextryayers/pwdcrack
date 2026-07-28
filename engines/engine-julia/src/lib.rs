pub mod runtime;
pub mod bridge;
pub mod error;

use log;

pub struct JuliaEngine {
    pub version: String,
    pub initialized: bool,
    pub image_path: Option<String>,
}

impl JuliaEngine {
    pub fn init(image_path: Option<&str>) -> Option<Self> {
        runtime::init_julia(image_path)
    }
    pub fn info(&self) -> String {
        format!("Julia {} (image: {})",
            self.version,
            self.image_path.as_deref().unwrap_or("none"),
        )
    }
}
