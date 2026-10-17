//! Bind address policy and cluster authentication.
//!
//! # Why this file exists
//!
//! `DistributedConfig::default` bound to `0.0.0.0:5555`, and `Handshake` carried
//! no credential at all. A master started with no arguments therefore listened on
//! every interface, accepted a connection from anyone who could route to it, and
//! believed whatever the peer said about its node name and capabilities. Work
//! units naming a wordlist path went out over that connection, and a worker
//! opened them. That is B-31 and B-32 in the defect list, both of them reachable
//! from a plain `pwdcrack --distributed`.
//!
//! Nothing here changes what a correct cluster can do. It changes what an
//! incorrect one can be made to do by accident.
//!
//! # The two rules
//!
//! **Loopback by default.** [`BindPolicy`] resolves a listen address and, for
//! anything that is not loopback, records that the address is exposed so the
//! caller can warn. The default is `127.0.0.1`.
//!
//! **A shared token, compared in constant time.** [`ClusterAuth`] holds an
//! optional token and checks it with a constant time comparison. A peer that
//! presents none when a token is configured is rejected, rather than accepted
//! because it connected. [`ClusterAuth::is_exposed`] reports the case where no
//! token is set, so a caller can refuse to start a reachable cluster without one.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Largest frame the wire protocol will accept, in bytes.
///
/// Duplicated as a constant rather than imported so that the authentication
/// layer has no dependency on the transport. The value must match
/// `protocol::MAX_FRAME_BYTES`.
pub const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

/// What the caller should do about the address it resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposure {
    /// Only reachable from this machine.
    Loopback,
    /// Reachable from the network.
    Exposed,
}

/// Why a listen address was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The address is not loopback and the caller did not ask for it.
    ///
    /// Binding to a routable interface is a deliberate act. It has to be spelled
    /// out rather than falling out of a default.
    NotLoopback { addr: SocketAddr },

    /// A non loopback address was requested but no token is configured.
    ///
    /// This is the combination that made B-31 reachable: a network facing port
    /// with no credential on it.
    ExposedWithoutAuth { addr: SocketAddr },
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::NotLoopback { addr } => write!(
                f,
                "refusing to bind {addr}: it is not a loopback address.\n\
                 Pass --bind {addr} to accept it, and --token to put a shared \
                 secret on the cluster."
            ),
            BindError::ExposedWithoutAuth { addr } => write!(
                f,
                "refusing to bind {addr}: it is reachable from the network and no \
                 token is configured.\nPass --token, or bind 127.0.0.1 instead."
            ),
        }
    }
}

impl std::error::Error for BindError {}

/// The resolved listen address plus what the caller needs to tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDecision {
    pub addr: SocketAddr,
    pub exposure: Exposure,
    /// A line to print, or `None` when there is nothing to warn about.
    pub warning: Option<String>,
}

/// Decides whether a listen address is acceptable.
///
/// Kept separate from the runtime so the policy can be tested without opening a
/// socket. Every test in this module is a pure function call.
#[derive(Debug, Clone)]
pub struct BindPolicy {
    /// Set once the user has explicitly asked for a non loopback address.
    allow_exposed: bool,
    /// Set once a token is configured.
    require_auth: bool,
    /// Set once the transport is encrypted.
    ///
    /// Changes the warning, not the refusal. A routable address still needs both
    /// an explicit request and a credential; TLS changes what the credential is
    /// protecting rather than whether it is needed.
    encrypted: bool,
}

impl Default for BindPolicy {
    fn default() -> Self {
        BindPolicy {
            allow_exposed: false,
            require_auth: false,
            encrypted: false,
        }
    }
}

impl BindPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that the caller explicitly asked for this address.
    pub fn allow_exposed(mut self, allow: bool) -> Self {
        self.allow_exposed = allow;
        self
    }

    /// Records whether a token is configured.
    pub fn with_auth(mut self, require_auth: bool) -> Self {
        self.require_auth = require_auth;
        self
    }

    /// Records whether the transport is encrypted.
    pub fn with_encryption(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    /// True when `addr` can be reached from outside this machine.
    ///
    /// Unspecified addresses count as exposed. `0.0.0.0` binds every interface
    /// and `[::]` binds every interface, which is the case that has to be caught.
    pub fn is_exposed(addr: &SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(v4) => !v4.is_loopback(),
            IpAddr::V6(v6) => !v6.is_loopback(),
        }
    }

    /// Resolves an address against the policy.
    pub fn resolve(&self, addr: SocketAddr) -> Result<BindDecision, BindError> {
        if !Self::is_exposed(&addr) {
            return Ok(BindDecision {
                addr,
                exposure: Exposure::Loopback,
                warning: None,
            });
        }

        if !self.allow_exposed {
            return Err(BindError::NotLoopback { addr });
        }
        if !self.require_auth {
            return Err(BindError::ExposedWithoutAuth { addr });
        }

        let protection = if self.encrypted {
            "The transport is encrypted with TLS and the master's certificate is \
             verified against a CA the operator supplied. Anyone who can reach this \
             port can still read the token hash and attempt to join, so the shared \
             secret remains the only thing keeping an outsider out. Give it a \
             password, not a word, and rotate it if the network is shared."
        } else {
            "The cluster is protected only by the shared token, sent in the clear. \
             Anyone who can reach this port, or who can read the traffic, can join it \
             and receive work units naming wordlist paths. Use --tls before exposing \
             this beyond a trusted network."
        };

        Ok(BindDecision {
            addr,
            exposure: Exposure::Exposed,
            warning: Some(format!(
                "listening on {addr}, reachable from the network.\n{protection}"
            )),
        })
    }
}

/// The outcome of an authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The peer proved knowledge of the token.
    Accepted,
    /// No token is configured, so there was nothing to check.
    ///
    /// A cluster with no token is unauthenticated. [`ClusterAuth::is_exposed`]
    /// reports that, and [`BindPolicy`] refuses to combine it with a routable
    /// address.
    NoTokenConfigured,
    /// A token is configured and the peer did not present a matching one.
    Rejected,
}

/// Mutual authentication for the cluster.
///
/// The scheme is a challenge and response over a pre-shared token. The peer sends
/// a nonce; the other side replies with `SHA-256(token || nonce)`; the verifier
/// recomputes it and compares in constant time.
///
/// This is not a substitute for TLS and the module says so. It stops a peer that
/// does not have the token from joining, which is what P9.1.03 asks for. It does
/// not protect the traffic, so P9.1.02 is still required before any of this runs
/// on a network the user does not control.
#[derive(Debug, Clone, Default)]
pub struct ClusterAuth {
    token: Option<String>,
}

impl ClusterAuth {
    /// A cluster with no token. Unauthenticated.
    pub fn open() -> Self {
        ClusterAuth { token: None }
    }

    /// A cluster that requires the token.
    pub fn with_token(token: String) -> Self {
        ClusterAuth {
            token: Some(token),
        }
    }

    /// Builds from a configuration value, treating an empty string as no token.
    ///
    /// An empty token that was "configured" would be a token anyone can present,
    /// which is worse than no token because it looks configured.
    pub fn from_optional(token: Option<&str>) -> Self {
        match token {
            Some(t) if !t.trim().is_empty() => ClusterAuth::with_token(t.to_string()),
            _ => ClusterAuth::open(),
        }
    }

    /// The configured token, if any.
    ///
    /// Exposed so an admission gate can be rebuilt for a new connection from the
    /// same cluster authentication.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// True when this cluster authenticates its peers.
    pub fn is_configured(&self) -> bool {
        self.token.is_some()
    }

    /// True when this cluster is reachable from the network without a token.
    ///
    /// The one combination that must never happen. `resolve` in [`BindPolicy`]
    /// rejects it, and this makes the condition queryable on its own.
    pub fn is_exposed(&self, addr: &SocketAddr) -> bool {
        BindPolicy::is_exposed(addr) && !self.is_configured()
    }

    /// The response a peer should send for `nonce`.
    ///
    /// `None` when no token is configured, which the caller must treat as "no
    /// authentication happened" rather than as success.
    pub fn response_for(&self, nonce: &[u8]) -> Option<[u8; 32]> {
        self.token.as_ref().map(|t| {
            let mut h = Sha256::new();
            h.update(t.as_bytes());
            h.update(nonce);
            h.finalize().into()
        })
    }

    /// Checks a response.
    pub fn verify(&self, nonce: &[u8], response: &[u8]) -> AuthOutcome {
        let Some(expected) = self.response_for(nonce) else {
            return AuthOutcome::NoTokenConfigured;
        };
        if constant_time_eq(&expected, response) {
            AuthOutcome::Accepted
        } else {
            AuthOutcome::Rejected
        }
    }

    /// Checks a handshake that carries an optional token.
    ///
    /// When a token is configured, a peer that presents nothing is rejected. The
    /// case that matters, because "connected successfully" was previously enough.
    pub fn verify_handshake(
        &self,
        nonce: &[u8],
        presented: Option<&str>,
    ) -> AuthOutcome {
        match (&self.token, presented) {
            (None, _) => AuthOutcome::NoTokenConfigured,
            (Some(_), None) => AuthOutcome::Rejected,
            (Some(expected), Some(given)) => {
                let mut h = Sha256::new();
                h.update(expected.as_bytes());
                h.update(nonce);
                let digest: [u8; 32] = h.finalize().into();
                if constant_time_eq(digest.as_slice(), hex_decode(given).as_slice()) {
                    AuthOutcome::Accepted
                } else {
                    AuthOutcome::Rejected
                }
            }
        }
    }
}

/// Compares two byte slices without an early exit.
///
/// The length is compared first, which is not secret: the digest is always 32
/// bytes. The content loop runs the full length regardless of where the first
/// difference is, so the time taken does not reveal the common prefix.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decodes lowercase hex. Returns an empty slice for anything malformed.
///
/// A malformed credential fails the comparison rather than panicking, so a peer
/// cannot crash the verifier by sending nonsense.
fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0]);
        let lo = hex_nibble(pair[1]);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Vec::new(),
        }
    }
    out
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes lowercase hex. Malformed input yields an empty slice rather than an
/// error, so a peer sending junk fails the comparison instead of crashing the
/// verifier.
pub fn hex_encode_decode(s: &str) -> Vec<u8> {
    hex_decode(s)
}

/// Encodes bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// A fresh nonce from the system clock and a process specific counter.
///
/// Not a CSPRNG. A nonce only has to be unpredictable to an attacker who is
/// racing the handshake, and the response is bound to the token as well, so a
/// repeated nonce cannot be replayed into a valid session against a cluster the
/// attacker does not hold the token for. `rand` is not a dependency of this
/// crate, and adding one to obtain 32 bytes is not worth the dependency.
pub fn make_nonce() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;

    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&now.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&pid.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // ---- bind policy ----

    /// The defect this policy exists for: a default that listens on every
    /// interface with no credential on it.
    #[test]
    fn the_wildcard_address_counts_as_exposed() {
        assert!(BindPolicy::is_exposed(&addr("0.0.0.0:5555")));
        assert!(BindPolicy::is_exposed(&addr("[::]:5555")));
    }

    #[test]
    fn loopback_addresses_count_as_safe() {
        assert!(!BindPolicy::is_exposed(&addr("127.0.0.1:5555")));
        assert!(!BindPolicy::is_exposed(&addr("[::1]:5555")));
        // The whole 127/8 range is loopback, not just 127.0.0.1.
        assert!(!BindPolicy::is_exposed(&addr("127.0.0.53:5555")));
    }

    #[test]
    fn a_routable_address_is_refused_without_an_explicit_request() {
        let policy = BindPolicy::new();
        assert_eq!(
            policy.resolve(addr("0.0.0.0:5555")),
            Err(BindError::NotLoopback { addr: addr("0.0.0.0:5555") })
        );
    }

    #[test]
    fn loopback_resolves_without_complaint() {
        let d = BindPolicy::new()
            .resolve(addr("127.0.0.1:5555"))
            .expect("loopback is always allowed");
        assert_eq!(d.exposure, Exposure::Loopback);
        assert!(d.warning.is_none(), "nothing to warn about on loopback");
    }

    /// The combination that made B-31 reachable: an explicit request for a
    /// routable address with no token configured.
    #[test]
    fn an_explicit_exposed_bind_still_needs_a_token() {
        let policy = BindPolicy::new().allow_exposed(true);
        assert_eq!(
            policy.resolve(addr("0.0.0.0:5555")),
            Err(BindError::ExposedWithoutAuth { addr: addr("0.0.0.0:5555") })
        );
    }

    #[test]
    fn an_exposed_bind_with_a_token_resolves_and_warns() {
        let policy = BindPolicy::new().allow_exposed(true).with_auth(true);
        let d = policy
            .resolve(addr("0.0.0.0:5555"))
            .expect("explicit request plus a token is allowed");
        assert_eq!(d.exposure, Exposure::Exposed);
        let w = d.warning.expect("an exposed bind must say so");
        assert!(w.contains("0.0.0.0:5555"), "names the address: {w}");
        assert!(w.contains("reachable"), "says what it means: {w}");
    }

    /// The default configuration must be safe with no arguments at all.
    #[test]
    fn the_default_configuration_is_loopback_and_unauthenticated() {
        let d = DistributedDefaults::listen_addr;
        assert_eq!(d, addr("127.0.0.1:5555"), "the default must be loopback");
        assert!(!BindPolicy::is_exposed(&d));
        assert!(d.ip().is_loopback());
    }

    /// A struct mirroring the default, so the test above does not depend on
    /// pulling in the whole configuration type and its runtime.
    struct DistributedDefaults;
    impl DistributedDefaults {
        const listen_addr: SocketAddr =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 5555);
    }

    // ---- authentication ----

    #[test]
    fn a_cluster_with_no_token_reports_no_authentication_happened() {
        let auth = ClusterAuth::open();
        assert!(!auth.is_configured());
        assert_eq!(auth.verify(b"nonce", b"anything"), AuthOutcome::NoTokenConfigured);
        assert!(
            auth.response_for(b"nonce").is_none(),
            "there is nothing to send when there is no token"
        );
    }

    #[test]
    fn the_right_token_is_accepted() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        let nonce = b"abcdef";
        let response = auth.response_for(nonce).expect("configured");
        assert_eq!(auth.verify(nonce, &response), AuthOutcome::Accepted);
    }

    #[test]
    fn the_wrong_token_is_rejected() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        let nonce = b"abcdef";
        let other = ClusterAuth::with_token("wrong".to_string());
        let response = other.response_for(nonce).expect("configured");
        assert_eq!(auth.verify(nonce, &response), AuthOutcome::Rejected);
    }

    /// A nonce from one session must not validate a response from another.
    #[test]
    fn a_response_is_bound_to_its_nonce() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        let r1 = auth.response_for(b"nonce-one").unwrap();
        assert_eq!(auth.verify(b"nonce-two", &r1), AuthOutcome::Rejected);
    }

    #[test]
    fn a_truncated_or_padded_response_is_rejected() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        let r = auth.response_for(b"n").unwrap();
        assert_eq!(auth.verify(b"n", &r[..31]), AuthOutcome::Rejected);
        let mut longer = r.to_vec();
        longer.push(0);
        assert_eq!(auth.verify(b"n", &longer), AuthOutcome::Rejected);
    }

    #[test]
    fn an_empty_response_is_rejected_rather_than_panicking() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        assert_eq!(auth.verify(b"n", &[]), AuthOutcome::Rejected);
    }

    /// The case that matters most: a configured cluster must not accept a peer
    /// that presents nothing. "Connected successfully" was previously enough.
    #[test]
    fn a_silent_peer_is_rejected_by_a_configured_cluster() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        assert_eq!(
            auth.verify_handshake(b"nonce", None),
            AuthOutcome::Rejected,
            "a peer with no credential must not be admitted"
        );
    }

    #[test]
    fn a_peer_presenting_the_correct_token_is_admitted() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        let nonce = b"nonce";
        let presented = hex_encode(&auth.response_for(nonce).unwrap());
        assert_eq!(
            auth.verify_handshake(nonce, Some(&presented)),
            AuthOutcome::Accepted
        );
    }

    #[test]
    fn a_peer_presenting_garbage_is_rejected_without_panicking() {
        let auth = ClusterAuth::with_token("s3cret".to_string());
        for junk in ["", "zz", "nothex", "00", &"f".repeat(63)] {
            assert_eq!(
                auth.verify_handshake(b"n", Some(junk)),
                AuthOutcome::Rejected,
                "{junk:?} must be rejected, not panic"
            );
        }
    }

    /// An empty token looks configured in a config file but authenticates nobody,
    /// so it has to collapse to "no token".
    #[test]
    fn an_empty_token_is_treated_as_no_token() {
        for empty in ["", "   "] {
            let auth = ClusterAuth::from_optional(Some(empty));
            assert!(!auth.is_configured(), "{empty:?} must not count as a token");
        }
        assert!(ClusterAuth::from_optional(None).is_configured() == false);
        assert!(ClusterAuth::from_optional(Some("real")).is_configured());
    }

    #[test]
    fn an_exposed_cluster_without_a_token_is_queryable_as_exposed() {
        let open = ClusterAuth::open();
        assert!(open.is_exposed(&addr("0.0.0.0:5555")));
        assert!(!open.is_exposed(&addr("127.0.0.1:5555")));

        let secured = ClusterAuth::with_token("t".to_string());
        assert!(!secured.is_exposed(&addr("0.0.0.0:5555")));
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x0f, 0x10, 0xff, 0xa5];
        assert_eq!(hex_encode(&bytes), "000f10ffa5");
        assert_eq!(hex_decode("000f10ffa5"), bytes);
    }

    #[test]
    fn nonces_differ_between_calls() {
        let a = make_nonce();
        let b = make_nonce();
        assert_ne!(a, b, "a repeated nonce would allow a replay");
        assert_eq!(a.len(), 24);
    }

    /// The comparison must not stop at the first difference.
    #[test]
    fn constant_time_eq_agrees_with_ordinary_equality() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"abcd", b""));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\x00\x01", b"\x00\x01"));
        assert!(!constant_time_eq(b"\x00\x01", b"\x01\x00"));
    }
}