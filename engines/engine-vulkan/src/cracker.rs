use crate::VulkanEngine;

pub struct VulkanCracker {
    engine: VulkanEngine,
}

impl VulkanCracker {
    pub fn new(engine: VulkanEngine) -> Self {
        VulkanCracker { engine }
    }
    pub fn engine(&self) -> &VulkanEngine { &self.engine }
}
