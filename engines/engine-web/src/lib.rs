//! engine-web: control plane for pwdcrack.
//!
//! # What this crate is for
//!
//! A dashboard that shows what the engine is doing and lets an operator start,
//! pause, resume and stop an attack. Two properties matter more than features:
//!
//! * it does nothing the CLI does not do. The attack path is the same code, so
//!   the dashboard cannot claim a capability the binary lacks.
//! * it is not reachable unless the operator said so. See `auth`.
//!
//! # What it was
//!
//! `WebConfig::default()` returned `host: "0.0.0.0"` with `auth_token: None`,
//! and `start_attack` set a status enum to `Running` and returned success without
//! hashing anything. That is B-30: a control plane exposed by default, over a
//! port with no authentication, reporting work that was not happening.
//! `auth::WebBindPolicy` and `attack::spawn` are the replacements.
//!
//! # Wiring
//!
//! This crate cannot call the engine. `pwdcrack` depends on it, so the reverse
//! edge is a dependency cycle. The seam is `attack::AttackExecutor`, implemented
//! by the binary. With no implementation the dashboard refuses to start an
//! attack and says why, rather than reporting one it cannot run.

pub mod attack;
pub mod auth;
pub mod routes;
pub mod server;
pub mod websocket;

use std::path::PathBuf;

pub use attack::{AttackExecutor, AttackHandle, AttackRequest, BatchOutcome, CrackedHit};
pub use auth::{TokenStore, WebBindPolicy};

/// Default listener address. Loopback, deliberately.
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Default listener port.
pub const DEFAULT_PORT: u16 = 8080;

/// Where the token is kept when the operator does not say otherwise.
///
/// Under the user's runtime directory rather than `/etc`, because the dashboard
/// is an optional feature and asking for root to run it would make it unused.
pub fn default_token_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("pwdcrack").join("web.token");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home)
                .join(".config")
                .join("pwdcrack")
                .join("web.token");
        }
    }
    std::env::temp_dir().join("pwdcrack-web.token")
}

/// How the dashboard should be set up.
#[derive(Debug, Clone)]
pub struct WebConfig {
    /// Listener address. Defaults to loopback and is checked by
    /// [`WebBindPolicy`] before anything binds.
    pub host: String,
    pub port: u16,
    /// Where the bearer token lives. Created with mode 0600 if absent.
    pub token_path: PathBuf,
    /// Set only by an explicit operator flag. Without it a routable address is
    /// refused, and without a token it is refused even with it.
    pub allow_exposed_bind: bool,
    /// Mutating requests allowed per second per source address.
    pub rate_per_second: u32,
    /// How many mutating requests may arrive at once before the rate applies.
    pub rate_burst: u32,
}

impl Default for WebConfig {
    /// Loopback. This is the fix for B-30 and it is the whole default.
    fn default() -> Self {
        WebConfig {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            token_path: default_token_path(),
            allow_exposed_bind: false,
            rate_per_second: 10,
            rate_burst: 20,
        }
    }
}

impl WebConfig {
    /// Builds a policy for this configuration, given whether a token exists.
    pub fn bind_policy(&self, has_token: bool) -> WebBindPolicy {
        WebBindPolicy {
            host: self.host.clone(),
            port: self.port,
            allow_exposed: self.allow_exposed_bind,
            has_token,
        }
    }

    pub fn store(&self) -> TokenStore {
        TokenStore::new(self.token_path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-30, as a test: the default must not be routable.
    #[test]
    fn the_default_configuration_binds_to_loopback() {
        let c = WebConfig::default();
        assert_eq!(c.host, "127.0.0.1");
        assert!(!c.allow_exposed_bind);
        let p = c.bind_policy(false);
        assert!(!p.is_exposed());
        assert!(p.check().is_ok());
    }

    #[test]
    fn the_default_token_path_is_under_a_per_user_directory() {
        let p = default_token_path();
        let text = p.to_string_lossy();
        assert!(
            !text.starts_with("/etc") && !text.starts_with("/usr"),
            "an optional feature must not ask for root: {text}"
        );
        assert!(p.ends_with("web.token"), "{text}");
    }

    #[test]
    fn the_store_follows_the_configured_path() {
        let mut c = WebConfig::default();
        c.token_path = PathBuf::from("/tmp/pwdcrack-test.token");
        assert_eq!(c.store().path(), c.token_path.as_path());
    }

    #[test]
    fn the_policy_reports_whether_a_token_was_supplied() {
        let mut c = WebConfig::default();
        c.host = "0.0.0.0".into();
        c.allow_exposed_bind = true;
        assert!(c.bind_policy(false).check().is_err(), "no token is refused");
        assert!(c.bind_policy(true).check().is_ok(), "a token is accepted");
    }
}