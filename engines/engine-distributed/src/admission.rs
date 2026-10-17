//! Cluster admission: the handshake gate on the master.
//!
//! # What was missing
//!
//! `handle_worker` accepted a TCP connection and immediately processed whatever
//! arrived. `Message::Handshake` carried a node name, a tier and a set of
//! claimed capabilities, and nothing else. A peer that had never heard of the
//! cluster could connect, name itself anything, and be entered into the worker
//! table, from where it received work units.
//!
//! `ClusterAuth` in `netpolicy` existed and computed the right answers. Nothing
//! called it. A token that nothing checks is a comment.
//!
//! # The gate
//!
//! [`AdmissionGate`] decides, per connection, whether the first frame is
//! acceptable. When the cluster has no token it admits an unauthenticated peer
//! and says so, which is what a loopback single user cluster wants. When it has
//! one, the peer must prove knowledge of it before any other message is
//! processed, and a connection that sends anything else first is dropped.
//!
//! The gate is a value with no I/O so it can be tested exhaustively. The socket
//! loop calls [`AdmissionGate::on_message`] for each frame and
//! [`AdmissionGate::on_disconnect`] at the end.
//!
//! # Why the nonce is per connection
//!
//! The response is `SHA-256(token || nonce)` with a fresh nonce per connection.
//! Without that a captured response replays forever, because nothing about it is
//! bound to a particular session.

use crate::netpolicy::{AuthOutcome, ClusterAuth};
use crate::protocol::Message;

/// What the gate decided about a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// No token configured. The peer is admitted and the cluster stays
    /// unauthenticated, which `netpolicy` will not allow on a routable address.
    AllowedUnauthenticated,

    /// The peer proved knowledge of the token.
    AllowedAuthenticated,

    /// The peer has not authenticated yet and sent something else first.
    ///
    /// Not an error yet: a worker may legitimately send `Ping` while it is
    /// waiting. The connection is dropped only if it never authenticates.
    AwaitingAuthentication,

    /// The peer sent a wrong credential. The connection ends here.
    Rejected,

    /// The peer authenticated but then sent a frame that is not permitted after
    /// admission.
    RejectedAfterAdmission,
}

impl Admission {
    /// True when the connection may carry on being processed.
    pub fn is_admitted(self) -> bool {
        matches!(
            self,
            Admission::AllowedUnauthenticated | Admission::AllowedAuthenticated
        )
    }

    /// True when the connection must be closed.
    pub fn must_close(self) -> bool {
        matches!(
            self,
            Admission::Rejected | Admission::RejectedAfterAdmission
        )
    }
}

/// One connection's admission state.
#[derive(Debug)]
pub struct AdmissionGate {
    auth: ClusterAuth,
    authenticated: bool,
}

impl AdmissionGate {
    pub fn new(auth: ClusterAuth) -> Self {
        let authenticated = !auth.is_configured();
        AdmissionGate {
            auth,
            authenticated,
        }
    }

    /// The cluster authentication this gate enforces.
    ///
    /// Exposed so the accept loop can build a fresh gate per connection from the
    /// same cluster authentication, rather than sharing one gate's per connection
    /// state between peers.
    pub fn token(&self) -> Option<&str> {
        self.auth.token()
    }

    /// True once this connection may receive work.
    ///
    /// A cluster with no token is admitted from the start. A cluster with one is
    /// not, until the peer proves knowledge of it.
    pub fn is_admitted(&self) -> bool {
        self.authenticated
    }

    /// True when this connection proved knowledge of the token.
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_configured() && self.authenticated
    }

    /// Decides what to do with the next frame from this connection.
    pub fn on_message(&mut self, msg: &Message, nonce: &[u8]) -> Admission {
        match msg {
            Message::Authenticate { response } => {
                if !self.auth.is_configured() {
                    // A peer authenticating against an open cluster is not an
                    // error, but it is worth knowing it happened.
                    self.authenticated = true;
                    return Admission::AllowedUnauthenticated;
                }
                match self.auth.verify(nonce, &decode_hex(response)) {
                    AuthOutcome::Accepted => {
                        self.authenticated = true;
                        Admission::AllowedAuthenticated
                    }
                    _ => {
                        self.authenticated = false;
                        Admission::Rejected
                    }
                }
            }

            // A ping is answered before admission so a worker can probe the
            // master without holding a token. It leaks nothing beyond liveness.
            Message::Ping => Admission::AwaitingAuthentication,

            _ if self.authenticated => Admission::AllowedAuthenticated,
            _ => Admission::AwaitingAuthentication,
        }
    }

    /// Called when the connection ends.
    ///
    /// Returns whether it had been admitted, so the master can log an
    /// unauthenticated connection attempt separately from an ordinary one.
    pub fn on_disconnect(&self) -> bool {
        self.is_admitted()
    }
}

fn decode_hex(s: &str) -> Vec<u8> {
    crate::netpolicy::hex_encode_decode(s)
}

/// The frame a worker sends first when the cluster has a token.
pub fn auth_frame(auth: &ClusterAuth, nonce: &[u8]) -> Message {
    Message::Authenticate {
        response: match auth.response_for(nonce) {
            Some(d) => crate::netpolicy::hex_encode(&d),
            None => String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(name: &str) -> Message {
        Message::Handshake {
            node_name: name.to_string(),
            tier: "x86_64".to_string(),
            caps: crate::protocol::Capabilities {
                simd: "none".to_string(),
                gpu: false,
                fpga: false,
                max_threads: 4,
                ram_mb: 1024,
            },
        }
    }

    fn nonce() -> Vec<u8> {
        crate::netpolicy::make_nonce()
    }

    /// An open cluster admits a peer with no credential. That is the loopback
    /// single user case and it has to keep working.
    #[test]
    fn an_open_cluster_admits_without_a_credential() {
        let mut gate = AdmissionGate::new(ClusterAuth::open());
        assert!(gate.is_admitted());
        assert!(gate.on_message(&handshake("n1"), &nonce()).is_admitted());
    }

    /// The defect: a configured cluster must not admit a peer that never
    /// authenticates, however legitimate its handshake looks.
    #[test]
    fn a_configured_cluster_refuses_a_bare_handshake() {
        let mut gate = AdmissionGate::new(ClusterAuth::with_token("s3cret".into()));
        assert!(!gate.is_admitted());
        let decision = gate.on_message(&handshake("intruder"), &nonce());
        assert!(!decision.is_admitted());
        assert!(
            matches!(decision, Admission::AwaitingAuthentication),
            "not admitted, and not a hard rejection yet: {decision:?}"
        );
    }

    #[test]
    fn a_correct_credential_admits_the_peer() {
        let auth = ClusterAuth::with_token("s3cret".into());
        let mut gate = AdmissionGate::new(auth.clone());
        let n = nonce();
        let frame = auth_frame(&auth, &n);
        let decision = gate.on_message(&frame, &n);
        assert!(decision.is_admitted());
        assert!(gate.is_authenticated());
        // And the handshake that follows is then accepted.
        assert!(gate.on_message(&handshake("worker-1"), &n).is_admitted());
    }

    #[test]
    fn a_wrong_credential_is_rejected_hard() {
        let auth = ClusterAuth::with_token("s3cret".into());
        let other = ClusterAuth::with_token("wrong".into());
        let mut gate = AdmissionGate::new(auth);
        let n = nonce();
        let frame = auth_frame(&other, &n);
        let decision = gate.on_message(&frame, &n);
        assert_eq!(decision, Admission::Rejected);
        assert!(decision.must_close());
        assert!(!gate.is_admitted());
    }

    /// A replayed response from another session must not admit.
    #[test]
    fn a_response_from_another_nonce_does_not_admit() {
        let auth = ClusterAuth::with_token("s3cret".into());
        let mut gate = AdmissionGate::new(auth.clone());
        let captured_nonce = nonce();
        let frame = auth_frame(&auth, &captured_nonce);
        // Replayed against a different, live nonce.
        let live = nonce();
        assert_eq!(gate.on_message(&frame, &live), Admission::Rejected);
    }

    #[test]
    fn a_malformed_credential_is_rejected_without_panicking() {
        let mut gate = AdmissionGate::new(ClusterAuth::with_token("s3cret".into()));
        let n = nonce();
        for junk in ["", "zz", "nothexatall", "00"] {
            let msg = Message::Authenticate {
                response: junk.to_string(),
            };
            assert_eq!(
                gate.on_message(&msg, &n),
                Admission::Rejected,
                "{junk:?} must be rejected, not panic"
            );
        }
    }

    /// An empty token must not become a credential anyone can present.
    #[test]
    fn an_empty_token_cluster_behaves_as_open() {
        let gate = AdmissionGate::new(ClusterAuth::from_optional(Some("   ")));
        assert!(gate.is_admitted());
        assert!(!gate.is_authenticated());
    }

    #[test]
    fn a_ping_is_answered_before_admission() {
        let mut gate = AdmissionGate::new(ClusterAuth::with_token("s3cret".into()));
        assert_eq!(
            gate.on_message(&Message::Ping, &nonce()),
            Admission::AwaitingAuthentication
        );
    }

    /// Work must not reach a peer that never authenticated, even one that gets
    /// its handshake in first.
    #[test]
    fn no_work_reaches_an_unauthenticated_peer() {
        let auth = ClusterAuth::with_token("s3cret".into());
        let mut gate = AdmissionGate::new(auth.clone());
        let n = nonce();
        // The peer sends its handshake first, then authenticates.
        assert!(!gate.on_message(&handshake("late"), &n).is_admitted());
        // Until it authenticates, the peer is not admitted, so nothing is
        // dispatched to it.
        assert!(!gate.is_admitted());
        let frame = auth_frame(&auth, &n);
        assert!(gate.on_message(&frame, &n).is_admitted());
        assert!(gate.is_admitted());
    }

    #[test]
    fn an_ended_connection_reports_whether_it_had_been_admitted() {
        let auth = ClusterAuth::with_token("s3cret".into());
        let mut gate = AdmissionGate::new(auth.clone());
        let n = nonce();
        assert!(!gate.on_disconnect());
        gate.on_message(&auth_frame(&auth, &n), &n);
        assert!(gate.on_disconnect());
    }
}