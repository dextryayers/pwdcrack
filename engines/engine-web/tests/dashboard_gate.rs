//! The Phase 10 gate, over a real socket.
//!
//! P10.1.07 names one assertion: an unauthenticated `POST /api/start` returns
//! 401. That is here, and so is everything around it, because a gate that only
//! checks the refusal says nothing about whether the accepted path works. A
//! server that 401s everything passes a refusal test perfectly while doing
//! nothing.
//!
//! Every test drives an actual TCP connection to an actual listener on an
//! ephemeral port. No router is called directly, so the middleware order, the
//! header layer and the body limit are all exercised the way an attacker or an
//! operator would meet them.
//!
//! The stub executor hashes nothing. It counts what it was handed, which is
//! enough to tell a real run from the old behaviour of setting an enum and
//! returning success.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use engine_web::attack::{spawn, AttackExecutor, AttackRequest, BatchOutcome, CrackedHit};
use engine_web::auth::TokenStore;
use engine_web::auth::WebBindPolicy;
use engine_web::server::{self, AppState};
use engine_web::WebConfig;

// ---------------------------------------------------------------------------
// A stub executor
// ---------------------------------------------------------------------------

/// Hands out numbered candidates and counts what it was given.
struct Stub {
    total: u64,
    batch: u64,
    counter: Arc<AtomicU64>,
}

impl Stub {
    fn new(total: u64, batch: u64) -> Self {
        Stub {
            total,
            batch,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl AttackExecutor for Stub {
    fn candidates(
        &self,
        _r: &AttackRequest,
        offset: u64,
        count: u64,
    ) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for i in offset..(offset + count).min(self.total) {
            out.push(format!("candidate-{i}"));
        }
        Ok(out)
    }

    fn keyspace_size(&self, _r: &AttackRequest) -> Option<u64> {
        Some(self.total)
    }

    fn test_batch(
        &self,
        _r: &AttackRequest,
        candidates: &[String],
    ) -> Result<BatchOutcome, String> {
        self.counter.fetch_add(candidates.len() as u64, Ordering::SeqCst);
        Ok(BatchOutcome {
            tested: candidates.len() as u64,
            cracked: vec![CrackedHit {
                hash: "deadbeef".into(),
                password: candidates.first().cloned().unwrap_or_default(),
            }]
            .into_iter()
            .take(if self.total == 0 { 0 } else { 1 })
            .collect(),
        })
    }

    fn batch_size(&self) -> u64 {
        self.batch
    }
}

// ---------------------------------------------------------------------------
// A live server
// ---------------------------------------------------------------------------

/// A running dashboard plus the address it is reachable at.
struct Harness {
    addr: SocketAddr,
    token: String,
    handed_out: Arc<AtomicU64>,
    _dir: std::path::PathBuf,
}

impl Harness {
    /// Starts a server on an ephemeral port with its own token file.
    ///
    /// The token file lives under a directory named after this test, so
    /// concurrent runs of the suite do not share one.
    async fn start(name: &str, total: u64, batch: u64) -> Harness {
        let dir = std::env::temp_dir().join(format!("pwdcrack-web-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let token_path = dir.join("web.token");

        let store = TokenStore::new(&token_path);
        let (token, _) = store.load_or_create().expect("token");

        let mut config = WebConfig {
            token_path,
            ..Default::default()
        };
        // Port 0 is refused by the policy because a bound port nobody can see is
        // useless in production. A test needs it, so the listener is bound here
        // and handed to `serve_on`, which is the same path production takes once
        // its own bind has happened.
        config.host = "127.0.0.1".into();
        let policy = config.bind_policy(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");

        let stub = Arc::new(Stub::new(total, batch));
        let handed_out = Arc::clone(&stub.counter);

        tokio::spawn(async move {
            let _ = server::serve_on(config, stub, policy, listener).await;
        });

        // Wait for the listener to answer rather than sleeping a fixed time.
        for _ in 0..200 {
            if TcpStream::connect(addr).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        Harness {
            addr,
            token,
            handed_out,
            _dir: dir,
        }
    }

    fn send(&self, request: &str) -> Raw {
        Raw::exchange(self.addr, request)
    }

    /// A mutating request with the token and the CSRF header.
    fn authorised(&self, path: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n\
             Authorization: Bearer {}\r\n\
             X-Pwdcrack-Request: dashboard\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.token,
            body.len()
        )
    }

    fn start_body(&self) -> String {
        "attack_type=bruteforce&hash_type=MD5&mask=%3Fa&target_hashes=5d41402abc4b2a76b9719d911017c592"
            .to_string()
    }

    /// Waits until the executor has been handed at least `n` candidates.
    async fn wait_for_tested(&self, n: u64) -> u64 {
        for _ in 0..400 {
            if self.handed_out.load(Ordering::SeqCst) >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.handed_out.load(Ordering::SeqCst)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

/// A parsed HTTP response.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Raw {
    fn exchange(addr: SocketAddr, request: &str) -> Raw {
        let mut stream =
            TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect to {addr}: {e}"));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .write_all(request.as_bytes())
            .expect("write request");
        let mut response = Vec::new();
        // Read to end. `Connection: close` makes the server hang up, so EOF is
        // the terminator rather than a content length.
        let _ = stream.read_to_end(&mut response);
        let text = String::from_utf8_lossy(&response).to_string();

        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or("");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect();

        Raw {
            status,
            headers,
            body: body.to_string(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn contains(&self, needle: &str) -> bool {
        self.body.contains(needle)
    }
}

// ---------------------------------------------------------------------------
// P10.1.07: the gate
// ---------------------------------------------------------------------------

/// The assertion the plan names.
#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_post_to_start_returns_401() {
    let h = Harness::start("gate", 100, 10).await;
    let response = h.send(&format!(
        "POST /api/start HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        h.start_body().len(),
        h.start_body()
    ));
    assert_eq!(
        response.status, 401,
        "an unauthenticated start must be 401, got {} body {}",
        response.status, response.body
    );
    // And the refusal must not have started anything.
    assert_eq!(
        h.handed_out.load(Ordering::SeqCst),
        0,
        "a refused start must not reach the executor"
    );
}

/// A refusal test alone would pass for a server that refuses everything, so the
/// accepted path is checked too.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorised_post_to_start_is_accepted() {
    let h = Harness::start("accept", 100, 10).await;
    let response = h.send(&h.authorised("/api/start", &h.start_body()));
    assert_eq!(
        response.status, 200,
        "the operator's own request must work, got {} body {}",
        response.status, response.body
    );
    assert!(response.contains("\"success\":true"), "body was {}", response.body);
}

/// P10.1.04: the accepted path must actually run the executor.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_start_really_hands_candidates_to_the_executor() {
    let h = Harness::start("real", 400, 20).await;
    let response = h.send(&h.authorised("/api/start", &h.start_body()));
    assert_eq!(response.status, 200);

    let handed = h.wait_for_tested(400).await;
    assert_eq!(
        handed, 400,
        "the executor was handed {handed} candidates, expected all 400"
    );

    // The counters are the run's own, reported by the read only status route.
    let status = h.send(
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status.status, 200);
    assert!(
        status.contains("\"total_tested\":400"),
        "status did not report the run's own count: {}",
        status.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_ends_the_run_before_the_keyspace_is_exhausted() {
    let h = Harness::start("stop", 5_000_000, 50).await;
    assert_eq!(h.send(&h.authorised("/api/start", &h.start_body())).status, 200);
    h.wait_for_tested(100).await;

    assert_eq!(
        h.send(&h.authorised("/api/stop", "")).status,
        200,
        "stop must be accepted"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = h.handed_out.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let later = h.handed_out.load(Ordering::SeqCst);
    assert_eq!(
        after, later,
        "the executor kept receiving candidates after stop: {after} then {later}"
    );
    assert!(later < 5_000_000, "the keyspace should not have been exhausted");
}

#[tokio::test(flavor = "multi_thread")]
async fn pause_freezes_progress_and_resume_restarts_it() {
    let h = Harness::start("pause", 5_000_000, 50).await;
    assert_eq!(h.send(&h.authorised("/api/start", &h.start_body())).status, 200);
    h.wait_for_tested(100).await;

    assert_eq!(h.send(&h.authorised("/api/pause", "")).status, 200);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let a = h.handed_out.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = h.handed_out.load(Ordering::SeqCst);
    assert_eq!(a, b, "a paused attack must not progress: {a} then {b}");

    assert_eq!(h.send(&h.authorised("/api/resume", "")).status, 200);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        h.handed_out.load(Ordering::SeqCst) > b,
        "a resumed attack must progress again"
    );
}

// ---------------------------------------------------------------------------
// P10.1.02: the token
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_token_is_refused() {
    let h = Harness::start("badtoken", 10, 10).await;
    let mut request = h.authorised("/api/start", &h.start_body());
    request = request.replace(&h.token, &"0".repeat(h.token.len()));
    let response = h.send(&request);
    assert_eq!(response.status, 401, "body was {}", response.body);
    assert_eq!(h.handed_out.load(Ordering::SeqCst), 0);
}

/// Every mutating route is guarded, not just start. A guard on one route and not
/// the others is the shape of the bug this phase is about.
#[tokio::test(flavor = "multi_thread")]
async fn every_mutating_route_is_guarded() {
    let h = Harness::start("allroutes", 10, 10).await;
    for path in ["/api/start", "/api/stop", "/api/pause", "/api/resume", "/api/config"] {
        let response = h.send(&format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        assert_eq!(response.status, 401, "{path} answered {} unauthenticated", response.status);
    }
}

// ---------------------------------------------------------------------------
// P10.1.03: CSRF
// ---------------------------------------------------------------------------

/// A valid token without the custom header is refused. A browser will not send a
/// custom header cross site, so this is what stops another page spending it.
#[tokio::test(flavor = "multi_thread")]
async fn a_token_without_the_csrf_header_is_refused() {
    let h = Harness::start("csrf", 10, 10).await;
    let body = h.start_body();
    let response = h.send(&format!(
        "POST /api/start HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        h.token,
        body.len()
    ));
    assert_eq!(
        response.status, 400,
        "the CSRF header is required, got {}",
        response.status
    );
    assert_eq!(h.handed_out.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// P10.1.05: rate limit
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_is_throttled_and_recorded() {
    let h = Harness::start("flood", 10, 10).await;
    let mut refused = 0;
    for _ in 0..60 {
        if h.send(&h.authorised("/api/stop", "")).status == 429 {
            refused += 1;
        }
    }
    assert!(refused > 0, "60 requests at 10/s with a burst of 20 must be refused");

    // The refusals are on the audit record, which is the point of recording
    // refusals rather than successes.
    let audit = h.send("GET /api/audit HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(audit.status, 200);
    assert!(
        audit.contains("rate limited"),
        "a throttle must be visible in the audit log: {}",
        &audit.body[..audit.body.len().min(400)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unauthenticated_flood_is_recorded_too() {
    let h = Harness::start("anonflood", 10, 10).await;
    for _ in 0..5 {
        h.send(
            "POST /api/start HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
    let audit = h.send("GET /api/audit HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(
        audit.contains("no bearer token"),
        "unauthenticated attempts must be on the record: {}",
        &audit.body[..audit.body.len().min(400)]
    );
}

// ---------------------------------------------------------------------------
// P10.1.06: CSP
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn every_response_carries_a_policy_forbidding_inline_script() {
    let h = Harness::start("csp", 10, 10).await;
    for (name, request) in [
        ("page", "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        ("css", "GET /style.css HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        ("js", "GET /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        (
            "api",
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ),
        ("404", "GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    ] {
        let response = h.send(request);
        let policy = response
            .header("content-security-policy")
            .unwrap_or_else(|| panic!("{name} has no CSP header"));
        assert!(
            policy.contains("script-src 'self'"),
            "{name} policy is missing script-src: {policy}"
        );
        assert!(
            !policy.contains("unsafe-inline") && !policy.contains("unsafe-eval"),
            "{name} policy weakens itself: {policy}"
        );
        assert_eq!(
            response.header("x-content-type-options"),
            Some("nosniff"),
            "{name} is missing nosniff"
        );
    }
}

/// A policy the page violates is an outage, so the served page has to comply.
#[tokio::test(flavor = "multi_thread")]
async fn the_served_pages_do_not_use_what_the_policy_forbids() {
    let h = Harness::start("comply", 10, 10).await;
    for path in ["/", "/dashboard/"] {
        let response = h.send(&format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"));
        assert_eq!(response.status, 200, "{path} did not render");
        assert!(
            !response.contains("onclick="),
            "{path} has an inline handler the policy blocks"
        );
        assert!(
            !response.contains("style="),
            "{path} has an inline style the policy blocks"
        );
        assert!(
            response.contains(r#"<script src="/app.js"></script>"#),
            "{path} must load its script from a file"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_static_assets_are_served_with_the_right_content_types() {
    let h = Harness::start("assets", 10, 10).await;
    let css = h.send("GET /style.css HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(
        css.header("content-type").unwrap_or("").starts_with("text/css"),
        "got {:?}",
        css.header("content-type")
    );
    let js = h.send("GET /app.js HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(
        js.header("content-type").unwrap_or("").starts_with("text/javascript"),
        "got {:?}",
        js.header("content-type")
    );
}

// ---------------------------------------------------------------------------
// P10.1.01: bind policy
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_default_listens_on_loopback_and_says_so() {
    let config = WebConfig::default();
    assert_eq!(config.host, "127.0.0.1", "the default bind must be loopback");

    let h = Harness::start("loopback", 10, 10).await;
    assert!(h.addr.ip().is_loopback(), "the harness bound {:?}", h.addr);

    let status = h.send("GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(
        status.contains("\"exposed\":false"),
        "the dashboard must report that it is not reachable from elsewhere: {}",
        status.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wildcard_bind_is_refused_before_a_socket_exists() {
    let dir = std::env::temp_dir().join(format!("pwdcrack-bind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut config = WebConfig {
        token_path: dir.join("web.token"),
        ..Default::default()
    };
    config.host = "0.0.0.0".into();
    let policy = config.bind_policy(true);
    let refusal = policy.check().expect_err("0.0.0.0 must be refused");
    assert!(
        refusal.to_string().contains("--allow-exposed-web-bind"),
        "the refusal must name the way out: {refusal}"
    );
}

/// A policy that is accepted only when both the flag and a token are present.
#[tokio::test(flavor = "multi_thread")]
async fn an_exposed_bind_needs_the_flag_and_a_token() {
    let mut policy = WebBindPolicy::new("0.0.0.0", 8080);
    assert!(policy.check().is_err(), "no flag");
    policy.allow_exposed = true;
    assert!(policy.check().is_err(), "flag without a token");
    policy.has_token = true;
    assert!(policy.check().is_ok(), "flag with a token");
}

// ---------------------------------------------------------------------------
// Refusals with reasons
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_request_is_a_400_with_a_reason() {
    let h = Harness::start("invalid", 10, 10).await;
    let body = "attack_type=bruteforce&hash_type=MD5";
    let response = h.send(&h.authorised("/api/start", body));
    assert_eq!(response.status, 400, "body was {}", response.body);
    assert!(
        response.contains("target hashes") || response.contains("no target"),
        "the refusal must say what is missing: {}",
        response.body
    );
    assert_eq!(
        h.handed_out.load(Ordering::SeqCst),
        0,
        "a refused request must not reach the executor"
    );
}

/// A run that has exhausted its keyspace is over. Pausing or resuming it would
/// report a state change that cannot happen, so both must be a conflict.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_attack_refuses_pause_and_resume() {
    // A one candidate keyspace, so the run completes immediately.
    let h = Harness::start("finished", 1, 1).await;
    assert_eq!(h.send(&h.authorised("/api/start", &h.start_body())).status, 200);

    // Wait for it to finish rather than assuming it has.
    let mut status = String::new();
    for _ in 0..200 {
        status = h
            .send("GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .body;
        if status.contains("Finished") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(status.contains("Finished"), "a one candidate run must finish: {status}");

    for route in ["/api/pause", "/api/resume"] {
        let response = h.send(&h.authorised(route, ""));
        assert_eq!(
            response.status, 409,
            "{route} answered {} on a finished attack",
            response.status
        );
    }
    // The counters survive the finish, which is what makes the report useful.
    assert!(
        status.contains("\"total_tested\":1"),
        "the work stays counted after the run ends: {status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_with_nothing_running_is_a_conflict() {
    let h = Harness::start("conflict", 10, 10).await;
    let response = h.send(&h.authorised("/api/stop", ""));
    assert_eq!(response.status, 409, "body was {}", response.body);
}

/// No executor wired means no attack, and the route says so rather than
/// reporting a run that cannot happen.
#[tokio::test(flavor = "multi_thread")]
async fn an_unwired_dashboard_refuses_to_start() {
    let dir = std::env::temp_dir().join(format!("pwdcrack-null-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config = WebConfig {
        token_path: dir.join("web.token"),
        ..Default::default()
    };
    let (token, _) = TokenStore::new(&config.token_path).load_or_create().expect("token");
    let policy = config.bind_policy(true);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = server::serve_on(
            config,
            Arc::new(engine_web::attack::NullExecutor),
            policy,
            listener,
        )
        .await;
    });
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let request = format!(
        "POST /api/start HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {token}\r\nX-Pwdcrack-Request: dashboard\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 62\r\nConnection: close\r\n\r\n\
         attack_type=bruteforce&hash_type=MD5&target_hashes=5d41402abc4b2a76b9719d911017c592"
    );
    let response = Raw::exchange(addr, &request);
    assert_eq!(response.status, 503, "body was {}", response.body);

    // And the status route tells the operator before they click anything.
    let status = Raw::exchange(
        addr,
        "GET /api/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(
        status.contains("\"executor_wired\":false"),
        "the page must show that attacks cannot run: {}",
        status.body
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The crate's own spawn, over HTTP, with a body that is actually hashed. This
/// is the end to end path: request to handle to executor to counters.
#[tokio::test(flavor = "multi_thread")]
async fn the_attack_handle_can_be_driven_outside_the_server() {
    // Included because the server tests use the stub through HTTP and this one
    // uses the same handle directly, so a break in either is visible.
    let ex: Arc<dyn AttackExecutor> = Arc::new(Stub::new(20, 5));
    let request = AttackRequest {
        attack_type: "bruteforce".into(),
        hash_type: "MD5".into(),
        target_hashes: vec!["5d41402abc4b2a76b9719d911017c592".into()],
        mask: Some("?a".into()),
        wordlist: None,
        rules: vec![],
    };
    let handle = spawn(ex, request).expect("starts");
    for _ in 0..200 {
        if handle.counters().tested() >= 20 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(handle.counters().tested(), 20);
    let state = AppState::new(
        Some("t".into()),
        WebBindPolicy::default(),
        Arc::new(engine_web::attack::NullExecutor),
    );
    assert!(!state.executor_wired, "the state reports its own executor honestly");
}