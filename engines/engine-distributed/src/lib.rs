pub mod admission;
pub mod discovery;
pub mod master;
pub mod netpolicy;
pub mod protocol;
pub mod verify;
pub mod wordlist;
pub mod worker;

use std::net::SocketAddr;

use netpolicy::{BindPolicy, ClusterAuth};

/// Default checkpoint location.
///
/// Under `/tmp`, which means another user on the same machine can read it and it
/// disappears on reboot. Both are noted rather than fixed: changing the location
/// changes where existing deployments expect to find their state, and that is a
/// decision for the user rather than for this code.
const DEFAULT_CHECKPOINT: &str = "/tmp/pwdcrack_checkpoint.json";

/// Port the cluster uses when none is given.
const DEFAULT_PORT: u16 = 5555;

#[derive(Debug, Clone)]
pub struct DistributedConfig {
    /// Address the master listens on.
    ///
    /// Defaults to `127.0.0.1`. It used to default to `0.0.0.0`, which listened on
    /// every interface with no credential on the port, so any host that could
    /// route to the machine could join the cluster and be handed work units
    /// naming wordlist paths. See `netpolicy` for the policy and its tests.
    pub listen_addr: SocketAddr,
    pub master_addr: Option<SocketAddr>,
    pub node_name: String,
    pub heartbeat_secs: u64,
    pub checkpoint_interval: u64,
    pub checkpoint_path: String,
    /// Shared secret. `None` leaves the cluster unauthenticated, which
    /// `netpolicy` will not permit on a routable address.
    pub token: Option<String>,
    /// Set once the user has explicitly asked for a non loopback address.
    pub allow_exposed_bind: bool,
    /// Directories this worker will read wordlists from. Empty means the worker
    /// refuses every dictionary unit, which is the safe default: the alternative
    /// is opening whatever path the master names.
    pub wordlist_dirs: Vec<String>,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        DistributedConfig {
            listen_addr: format!("127.0.0.1:{DEFAULT_PORT}").parse().unwrap(),
            master_addr: None,
            node_name: hostname(),
            heartbeat_secs: 5,
            checkpoint_interval: 60,
            checkpoint_path: DEFAULT_CHECKPOINT.to_string(),
            token: None,
            allow_exposed_bind: false,
            wordlist_dirs: Vec::new(),
        }
    }
}

impl DistributedConfig {
    pub fn is_master(&self) -> bool {
        self.master_addr.is_none()
    }

    /// The authentication state this configuration implies.
    pub fn auth(&self) -> ClusterAuth {
        ClusterAuth::from_optional(self.token.as_deref())
    }

    /// Checks the listen address against the policy before anything binds.
    ///
    /// Called by `run` and by the command line entry point, so the check happens
    /// before a socket exists rather than after traffic has arrived.
    pub fn resolve_bind(&self) -> Result<netpolicy::BindDecision, netpolicy::BindError> {
        BindPolicy::new()
            .allow_exposed(self.allow_exposed_bind)
            .with_auth(self.auth().is_configured())
            .resolve(self.listen_addr)
    }

    pub async fn run(&self) -> Result<(), String> {
        let decision = self.resolve_bind().map_err(|e| e.to_string())?;
        // The warning is logged, not printed. `src/main.rs` already prints it
        // during startup validation, and printing it in both places showed the
        // user the same three lines twice. Logging keeps it recorded when `run`
        // is driven from somewhere other than the CLI.
        if let Some(warning) = &decision.warning {
            log::warn!("{warning}");
        }
        // The resolved address, not the configured one. They are the same today,
        // but binding what the policy actually approved is what keeps the two
        // from drifting apart.
        let listen_addr = decision.addr;

        if self.is_master() {
            let master = master::MasterNode::new(
                &listen_addr.to_string(),
                &self.checkpoint_path,
                self.auth(),
            );
            master.run().await
        } else {
            // The wordlist grant is part of the worker's own configuration. The
            // master picks which file inside it is opened; it cannot widen it.
            let mut worker =
                worker::WorkerNode::new(&self.master_addr.unwrap().to_string());
            if let Some(token) = &self.token {
                worker = worker.with_token(token.clone());
            }
            if !self.wordlist_dirs.is_empty() {
                worker = worker
                    .with_wordlist_dirs(&self.wordlist_dirs)
                    .map_err(|e| format!("wordlist grant: {e}"))?;
                log::info!(
                    "Distributed: worker will read wordlists from {:?}",
                    worker.roots()
                );
            } else {
                log::warn!(
                    "Distributed: no --wordlist-dir given, so every dictionary work \
                     unit will be refused. A worker does not open paths named by \
                     the master; see docs/PHASE9_STATUS.md for P9.1.05."
                );
            }
            worker.run_worker_loop().await
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_listen_address_is_loopback() {
        let c = DistributedConfig::default();
        assert!(
            c.listen_addr.ip().is_loopback(),
            "default was {}, which is reachable from the network",
            c.listen_addr
        );
    }

    #[test]
    fn a_default_configuration_resolves_without_complaint() {
        let c = DistributedConfig::default();
        let d = c.resolve_bind().expect("the default must be usable");
        assert!(d.warning.is_none());
    }

    /// A configuration that binds every interface with no token must be refused,
    /// even when the address was asked for explicitly.
    #[test]
    fn a_wildcard_bind_without_a_token_is_refused() {
        let c = DistributedConfig {
            listen_addr: "0.0.0.0:5555".parse().unwrap(),
            allow_exposed_bind: true,
            ..DistributedConfig::default()
        };
        assert!(c.resolve_bind().is_err());
    }

    #[test]
    fn a_wildcard_bind_without_an_explicit_request_is_refused() {
        let c = DistributedConfig {
            listen_addr: "0.0.0.0:5555".parse().unwrap(),
            ..DistributedConfig::default()
        };
        assert!(c.resolve_bind().is_err());
    }

    #[test]
    fn a_wildcard_bind_with_a_token_is_allowed_and_warns() {
        let c = DistributedConfig {
            listen_addr: "0.0.0.0:5555".parse().unwrap(),
            allow_exposed_bind: true,
            token: Some("shared".to_string()),
            ..DistributedConfig::default()
        };
        let d = c.resolve_bind().expect("explicit plus a token");
        assert!(d.warning.is_some(), "an exposed bind must warn");
    }

    #[test]
    fn an_empty_token_does_not_count_as_configured() {
        let c = DistributedConfig {
            token: Some("  ".to_string()),
            ..DistributedConfig::default()
        };
        assert!(!c.auth().is_configured());
    }
}