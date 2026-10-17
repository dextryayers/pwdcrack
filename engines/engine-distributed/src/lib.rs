pub mod admission;
pub mod checkpoint;
pub mod codec;
pub mod discovery;
pub mod liveness;
pub mod mask;
pub mod master;
pub mod netpolicy;
pub mod protocol;
pub mod ratelimit;
pub mod scheduler;
pub mod tls;
pub mod verify;
pub mod wordlist;
pub mod worker;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::time;

use checkpoint::CheckpointStore;
use netpolicy::{BindPolicy, ClusterAuth};
use protocol::{AttackType, TargetHash};
use scheduler::ChunkPolicy;
use tls::{ClusterTls, TlsPaths};
use wordlist::WordlistManifest;

/// Port the cluster uses when none is given.
const DEFAULT_PORT: u16 = 5555;

/// How the cluster transport is protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsMode {
    /// Plain TCP. Acceptable only on loopback, which
    /// [`netpolicy::BindPolicy`] enforces for anything else.
    Off,

    /// Encrypted. On a master this generates and persists a certificate
    /// authority and a server leaf on first run.
    Enabled {
        /// On a worker: the master's `ca.pem`. Without it a worker cannot
        /// verify the master and TLS is refused.
        master_ca: Option<PathBuf>,
        /// On a worker: pin the first certificate seen. Refused unless the
        /// master is on loopback.
        trust_on_first_use: bool,
    },
}

impl TlsMode {
    pub fn is_enabled(&self) -> bool {
        !matches!(self, TlsMode::Off)
    }
}

impl Default for TlsMode {
    fn default() -> Self {
        TlsMode::Off
    }
}

/// A job for the cluster master to schedule.
///
/// Built from the command line so `--distributed dictionary hashes.txt words.txt`
/// actually distributes the attack instead of only listening for peers that have
/// nothing to do. A master without one still accepts workers and still serves the
/// protocol; it simply has no work to hand out until something queues a job.
#[derive(Debug, Clone)]
pub struct ClusterJob {
    /// The hashes to try.
    pub targets: Vec<TargetHash>,
    /// How to turn a candidate index into a candidate.
    pub attack: AttackType,
    /// The wordlist to ship to workers, when the attack needs one.
    ///
    /// Sent as contents plus a digest rather than as a path, so a worker needs no
    /// local grant and the master cannot make a worker open a file it chose.
    pub wordlist: Option<(WordlistManifest, Vec<String>)>,
}

impl ClusterJob {
    /// Builds a dictionary job, reading the wordlist to get its line count and
    /// its contents.
    ///
    /// Refuses a wordlist it cannot read. An estimate here, which is what the
    /// old code used with a hardcoded ten million, both invents candidates that do
    /// not exist and leaves the tail of a real wordlist unscheduled.
    pub fn dictionary(
        path: impl AsRef<std::path::Path>,
        rules: Vec<String>,
        targets: Vec<TargetHash>,
    ) -> Result<Self, String> {
        let path = path.as_ref();
        let body = std::fs::read(path)
            .map_err(|e| format!("cannot read the wordlist {}: {e}", path.display()))?;
        let text = String::from_utf8_lossy(&body);
        let words: Vec<String> = text
            .lines()
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        if words.is_empty() {
            return Err(format!("{} has no lines", path.display()));
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "wordlist".to_string());
        let manifest = WordlistManifest::from_bytes(name, text.as_bytes());
        let digest = manifest.sha256.clone();
        Ok(ClusterJob {
            targets,
            attack: AttackType::Inline { sha256: digest, rules },
            wordlist: Some((manifest, words)),
        })
    }

    /// Candidates in this job, computed rather than guessed.
    pub fn keyspace(&self) -> Result<u64, String> {
        let lines = self
            .wordlist
            .as_ref()
            .map(|(_, words)| words.len() as u64);
        crate::scheduler::keyspace_for(&self.attack, lines)
    }

    /// Registers the job with a master and returns its id.
    pub async fn submit(&self, shared: &master::Shared) -> Result<u64, String> {
        if let Some((manifest, words)) = &self.wordlist {
            shared
                .register_wordlist(manifest.clone(), words.clone())
                .await?;
        }
        let keyspace = self.keyspace()?;
        shared
            .scheduler
            .lock()
            .await
            .add_job(self.attack.clone(), self.targets.clone(), keyspace)
    }
}

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
    /// Transport protection. See [`TlsMode`].
    pub tls: TlsMode,
    /// Sustained handshake attempts accepted from one source address.
    pub handshake_rate: f64,
    /// Burst allowance per source address.
    pub handshake_burst: f64,
    /// How many seconds of work a chunk should take at the receiving worker's own
    /// rate. The knob behind P9.2.01.
    pub chunk_seconds: f64,
    /// A job for this node's cluster to schedule, when it is the master.
    pub job: Option<ClusterJob>,
    /// Where to send the cluster's answer when the job finishes.
    ///
    /// The CLI needs the results, and it cannot get them by polling: the cluster
    /// lives on a runtime this crate owns and the caller only holds a handle.
    pub results_tx: Option<tokio::sync::mpsc::UnboundedSender<ClusterReport>>,
    /// How long to keep serving after the job finishes, so a worker that was
    /// mid chunk gets a clean answer rather than a reset connection.
    pub shutdown_grace: Duration,
}

/// What the cluster found.
#[derive(Debug, Clone, PartialEq)]
pub struct ClusterReport {
    /// One entry per cracked hash, sorted by hash value.
    pub cracked: Vec<protocol::CrackedEntry>,
    /// Candidates never assigned, which is non-zero only when the job stopped
    /// early because every target was solved.
    pub candidates_unsearched: u64,
    /// Jobs with no work left.
    pub jobs_finished: usize,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        // Falls back to a path under the user's state directory, and only to
        // `/tmp` when there is no HOME at all, which is logged rather than
        // silently accepted.
        let checkpoint_path = CheckpointStore::discover()
            .map(|s| s.path().display().to_string())
            .unwrap_or_else(|_| {
                log::warn!(
                    "no HOME and no {}, so the checkpoint will go to /tmp where another \
                     user can read it. Set PWDCRACK_CHECKPOINT_DIR.",
                    checkpoint::CHECKPOINT_DIR_ENV
                );
                format!("/tmp/pwdcrack-{}/checkpoint.pwck", std::process::id())
            });

        DistributedConfig {
            listen_addr: format!("127.0.0.1:{DEFAULT_PORT}").parse().unwrap(),
            master_addr: None,
            node_name: hostname(),
            heartbeat_secs: 5,
            checkpoint_interval: 15,
            checkpoint_path,
            token: None,
            allow_exposed_bind: false,
            wordlist_dirs: Vec::new(),
            tls: TlsMode::Off,
            handshake_rate: ratelimit::DEFAULT_RATE_PER_SEC,
            handshake_burst: ratelimit::DEFAULT_BURST,
            chunk_seconds: 2.0,
            job: None,
            results_tx: None,
            shutdown_grace: Duration::from_secs(5),
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
            .with_encryption(self.tls.is_enabled())
            .resolve(self.listen_addr)
    }

    /// The cluster tunables this configuration implies.
    pub fn policy(&self) -> master::ClusterPolicy {
        master::ClusterPolicy {
            heartbeat: Duration::from_secs(self.heartbeat_secs.max(1)),
            checkpoint_interval: Duration::from_secs(self.checkpoint_interval.max(1)),
            chunk: ChunkPolicy {
                target_seconds: self.chunk_seconds.max(0.001),
                ..ChunkPolicy::default()
            },
            max_frame: codec::DEFAULT_MAX_FRAME,
            handshake_rate_per_sec: self.handshake_rate,
            handshake_burst: self.handshake_burst,
        }
    }

    /// Builds the transport for this node's role.
    pub fn transport(&self) -> Result<Option<ClusterTls>, String> {
        match &self.tls {
            TlsMode::Off => Ok(None),
            TlsMode::Enabled {
                master_ca,
                trust_on_first_use,
            } => {
                if self.is_master() {
                    let paths = TlsPaths::discover()?;
                    Ok(Some(ClusterTls::for_master(&paths)?))
                } else {
                    let addr = self
                        .master_addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "127.0.0.1:5555".to_string());
                    let name = tls::tls_server_name(&addr)
                        .unwrap_or_else(|| "localhost".to_string());
                    if let Some(ca) = master_ca {
                        Ok(Some(ClusterTls::for_worker_with_ca(ca, &name)?))
                    } else if *trust_on_first_use {
                        let paths = TlsPaths::discover()?;
                        let loopback = self
                            .master_addr
                            .map(|a| a.ip().is_loopback())
                            .unwrap_or(true);
                        Ok(Some(ClusterTls::for_worker_tofu(
                            &paths, &name, loopback,
                        )?))
                    } else {
                        Err(
                            "TLS is on but this worker has nothing to verify the master \
                             against. Pass --master-ca with the master's ca.pem, or \
                             --tls-tofu on loopback."
                                .to_string(),
                        )
                    }
                }
            }
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        let decision = self.resolve_bind().map_err(|e| e.to_string())?;
        // The warning is logged, not printed. `src/main.rs` already prints it
        // during startup validation, and printing it in both places showed the
        // user the same three lines twice.
        if let Some(warning) = &decision.warning {
            log::warn!("{warning}");
        }
        // The resolved address, not the configured one.
        let listen_addr = decision.addr;
        let transport = self.transport()?;

        if self.is_master() {
            let built = master::MasterNode::with_policy(
                &listen_addr.to_string(),
                CheckpointStore::new(&self.checkpoint_path),
                self.policy(),
                self.auth(),
            );
            let master = std::sync::Arc::new(match transport {
                Some(t) => built.with_tls(t),
                None => built,
            });
            match master.resume_from_store().await {
                Ok(true) => log::info!("resumed from the checkpoint at {}", self.checkpoint_path),
                Ok(false) => {}
                Err(e) => log::error!("{e}. Starting a fresh run instead."),
            }

            // The job goes in before the accept loop starts, so a worker that
            // connects in the first instant is not told there is nothing to do.
            if let Some(job) = &self.job {
                let id = job.submit(&master.shared).await?;
                log::info!(
                    "Cluster master: queued job {id}: {} target(s), {} candidates",
                    job.targets.len(),
                    job.keyspace()?
                );
                let local = std::sync::Arc::clone(&master);
                let name = format!("local-{}", std::process::id());
                let results_tx = self.results_tx.clone();
                let grace = self.shutdown_grace;
                let job_count = master.shared.scheduler.lock().await.job_count();
                let accept = tokio::spawn({
                    let running = std::sync::Arc::clone(&master);
                    async move { running.run().await }
                });

                if let Err(e) = local.run_local_worker(&name).await {
                    log::error!("Cluster master local worker '{name}' stopped: {e}");
                }
                let cracked = master.cracked().await;
                let unsearched = master.free_total().await;
                if let Some(tx) = results_tx {
                    let _ = tx.send(ClusterReport {
                        cracked,
                        candidates_unsearched: unsearched,
                        jobs_finished: job_count,
                    });
                }
                // Keep serving briefly so a worker still working on a chunk gets
                // told the job is over rather than seeing the socket close.
                time::sleep(grace).await;
                accept.abort();
                return Ok(());
            }

            master.run().await
        } else {
            // The wordlist grant is part of the worker's own configuration. The
            // master picks which file inside it is opened; it cannot widen it.
            let mut worker =
                worker::WorkerNode::new(&self.master_addr.unwrap().to_string());
            if let Some(token) = &self.token {
                worker = worker.with_token(token.clone());
            }
            if let Some(t) = transport {
                worker = worker.with_tls(t);
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
        assert!(d.warning.as_ref().unwrap().contains("sent in the clear"));
    }

    /// TLS changes what the warning says, because the previous wording told the
    /// operator to use TLS and that would be nonsense once they had.
    #[test]
    fn tls_changes_the_exposure_warning() {
        let c = DistributedConfig {
            listen_addr: "0.0.0.0:5555".parse().unwrap(),
            allow_exposed_bind: true,
            token: Some("shared".to_string()),
            tls: TlsMode::Enabled {
                master_ca: None,
                trust_on_first_use: false,
            },
            ..DistributedConfig::default()
        };
        let d = c.resolve_bind().expect("explicit plus a token plus tls");
        let w = d.warning.expect("an exposed bind must warn");
        assert!(w.contains("encrypted"), "warning did not mention TLS: {w}");
        assert!(!w.contains("sent in the clear"), "stale plaintext warning: {w}");
    }

    #[test]
    fn an_empty_token_does_not_count_as_configured() {
        let c = DistributedConfig {
            token: Some("  ".to_string()),
            ..DistributedConfig::default()
        };
        assert!(!c.auth().is_configured());
    }

    #[test]
    fn the_default_checkpoint_is_not_in_a_shared_directory() {
        let c = DistributedConfig::default();
        assert!(
            !c.checkpoint_path.starts_with("/tmp/"),
            "default checkpoint {} is world readable",
            c.checkpoint_path
        );
    }

    #[test]
    fn the_policy_reflects_the_configured_rates() {
        let c = DistributedConfig {
            heartbeat_secs: 2,
            checkpoint_interval: 7,
            chunk_seconds: 0.5,
            handshake_rate: 11.0,
            handshake_burst: 22.0,
            ..DistributedConfig::default()
        };
        let p = c.policy();
        assert_eq!(p.heartbeat, Duration::from_secs(2));
        assert_eq!(p.checkpoint_interval, Duration::from_secs(7));
        assert_eq!(p.chunk.target_seconds, 0.5);
        assert_eq!(p.handshake_rate_per_sec, 11.0);
        assert_eq!(p.handshake_burst, 22.0);
    }

    /// A zero interval would make the dispatcher spin. Clamped rather than
    /// trusted.
    #[test]
    fn a_zero_interval_is_clamped_to_something_usable() {
        let c = DistributedConfig {
            heartbeat_secs: 0,
            checkpoint_interval: 0,
            chunk_seconds: 0.0,
            ..DistributedConfig::default()
        };
        let p = c.policy();
        assert_eq!(p.heartbeat, Duration::from_secs(1));
        assert_eq!(p.checkpoint_interval, Duration::from_secs(1));
        assert!(p.chunk.target_seconds > 0.0);
    }

    /// A job must carry its real keyspace. The old code used a hardcoded ten
    /// million for every dictionary attack.
    #[test]
    fn a_dictionary_job_measures_its_wordlist() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.txt");
        std::fs::write(&p, b"a\nb\nc\nd\n").unwrap();
        let job = ClusterJob::dictionary(&p, vec![], vec![]).unwrap();
        assert_eq!(job.keyspace().unwrap(), 4);
        assert_eq!(job.wordlist.as_ref().unwrap().1.len(), 4);
        assert!(matches!(job.attack, AttackType::Inline { .. }));
    }

    #[test]
    fn a_missing_wordlist_is_an_error_rather_than_an_estimate() {
        let err = ClusterJob::dictionary("/nonexistent/w.txt", vec![], vec![])
            .unwrap_err();
        assert!(err.contains("cannot read"), "unhelpful error: {err}");
    }

    #[tokio::test]
    async fn a_job_without_targets_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.txt");
        std::fs::write(&p, b"a\nb\n").unwrap();
        let job = ClusterJob::dictionary(&p, vec![], vec![]).unwrap();
        let store = CheckpointStore::new(dir.path().join("cp.pwck"));
        let shared = master::Shared::new(store, master::ClusterPolicy::default(), None);
        let err = job.submit(&shared).await.unwrap_err();
        assert!(err.contains("no target hashes"), "unhelpful error: {err}");
    }

    #[tokio::test]
    async fn a_submitted_job_reaches_the_scheduler_and_the_wordlist_cache() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.txt");
        std::fs::write(&p, b"alpha\nbravo\ncharlie\n").unwrap();
        let job = ClusterJob::dictionary(
            &p,
            vec![],
            vec![TargetHash::new("MD5", "5d41402abc4b2a76b9719d911017c592")],
        )
        .unwrap();
        let store = CheckpointStore::new(dir.path().join("cp.pwck"));
        let shared = master::Shared::new(store, master::ClusterPolicy::default(), None);
        let id = job.submit(&shared).await.unwrap();
        assert_eq!(id, 1);
        assert_eq!(shared.scheduler.lock().await.free_total(), 3);
        assert_eq!(
            shared.wordlists.lock().await.len(),
            1,
            "the wordlist was not made available to workers"
        );
    }

    #[test]
    fn tls_is_off_by_default() {
        assert!(!DistributedConfig::default().tls.is_enabled());
    }

    /// A worker with TLS on and nothing to verify against must be refused at
    /// startup, not allowed to fall back to trusting anyone.
    #[test]
    fn a_tls_worker_with_no_trust_anchor_is_refused() {
        let c = DistributedConfig {
            master_addr: Some("127.0.0.1:5555".parse().unwrap()),
            tls: TlsMode::Enabled {
                master_ca: None,
                trust_on_first_use: false,
            },
            ..DistributedConfig::default()
        };
        let err = c.transport().unwrap_err();
        assert!(err.contains("--master-ca"), "unhelpful error: {err}");
    }
}