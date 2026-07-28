use crate::JuliaEngine;

pub fn init_julia(_image_path: Option<&str>) -> Option<JuliaEngine> {
    #[cfg(feature = "julia")] {
        match jlrs::Julia::init() {
            Ok(julia) => {
                let version = julia.version().to_string();
                log::info!("Julia: {} initialized", version);
                Some(JuliaEngine {
                    version,
                    initialized: true,
                    image_path: _image_path.map(|s| s.to_string()),
                })
            }
            Err(e) => {
                log::warn!("Julia: init failed: {:?}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "julia"))] {
        let _ = _image_path;
        log::info!("Julia: engine requires julia feature (not enabled)");
        None
    }
}
