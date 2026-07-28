use crate::{GoEngine, error::GoError};

pub fn load_go_engine(path: &str) -> Option<GoEngine> {
    #[cfg(feature = "go")] {
        match unsafe { libloading::Library::new(path) } {
            Ok(_lib) => {
                log::info!("Go: loaded shared library from {}", path);
                Some(GoEngine {
                    loaded: true,
                    path: Some(path.to_string()),
                    functions: vec!["verify_md5".into(), "verify_sha256".into()],
                })
            }
            Err(e) => {
                log::warn!("Go: failed to load {}: {}", path, e);
                None
            }
        }
    }
    #[cfg(not(feature = "go"))] {
        let _ = path;
        None
    }
}
