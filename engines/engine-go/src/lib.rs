pub mod bridge;
pub mod cracker;
pub mod error;

use log;

pub struct GoEngine {
    pub loaded: bool,
    pub path: Option<String>,
    pub functions: Vec<String>,
}

impl GoEngine {
    pub fn load(path: &str) -> Option<Self> {
        bridge::load_go_engine(path)
    }
    pub fn info(&self) -> String {
        format!("Go engine: {} ({})",
            if self.loaded { "loaded" } else { "unloaded" },
            self.path.as_deref().unwrap_or("none"),
        )
    }
}
