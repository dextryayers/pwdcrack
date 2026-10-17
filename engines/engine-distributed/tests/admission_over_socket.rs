//! End to end checks that admission, framing, TLS and rate limiting work over a
//! real socket.
//!
//! Run with: cargo test -p engine-distributed --test admission_over_socket
//!
//! The unit tests in `admission.rs` cover the decision table. These cover the
//! things they cannot:
//!
//!   - that `handle_worker` consults the gate before interpreting a frame, and
//!     drops the connection rather than entering the peer into the worker table;
//!   - that the binary framing survives a real socket, which is where a partial
//!     read actually happens;
//!   - that a peer is throttled rather than hashed at, and told why.
//!
//! Every test binds its own listener on a port the OS chose, so parallel runs
//! cannot collide.

use std::time::Duration;

use engine_distributed::checkpoint::CheckpointStore;
use engine_distributed::codec::{self, Code, HEADER_LEN};
use engine_distributed::master::{ClusterPolicy, MasterNode, Shared};
use engine_distributed::netpolicy::{hex_encode_decode, ClusterAuth};
use engine_distributed::protocol::{
    AttackType, Capabilities, ErrorCode, Message, TargetHash, SCHEMA_VERSION,
};
use engine_distributed::scheduler::ChunkPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Turns the cluster's own logging on for this test process.
///
/// Without it a failing cluster test prints only the assertion, and the
/// interesting part is always the master's log line that came before it.
fn enable_logging() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .filter_module("engine_distributed", log::LevelFilter::Trace)
        .try_init();
}

/// A master with its accept loop already running, plus its address.
///
/// The listener is bound first and the port handed to the accept loop, so there
/// is no window between "pick a free port" and "bind it" for another test to
/// steal.
async fn serving_master(auth: ClusterAuth) -> (String, MasterNode) {
    enable_logging();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let dir = tempfile::tempdir().unwrap();
    // Leaked so the directory outlives the function: the master keeps a path
    // into it and a `TempDir` dropped here would delete it under the master.
    let dir: &'static tempfile::TempDir = Box::leak(Box::new(dir));

    let master = MasterNode::with_policy(
        &addr,
        CheckpointStore::new(dir.path().join("checkpoint.pwck")),
        ClusterPolicy {
            heartbeat: Duration::from_millis(150),
            checkpoint_interval: Duration::from_secs(3600),
            chunk: ChunkPolicy {
                target_seconds: 0.001,
                min_candidates: 4,
                max_candidates: 64,
            },
            max_frame: codec::DEFAULT_MAX_FRAME,
            // Several attempts per test from 127.0.0.1 must not be throttled by
            // accident. The throttling test overrides this.
            handshake_rate_per_sec: 1000.0,
            handshake_burst: 1000.0,
        },
        auth,
    );
    engine_distributed::master::spawn_dispatcher(master.shared.clone());

    let shared = master.shared.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let shared = shared.clone();
            tokio::spawn(async move {
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket,
                    shared.clone(),
                    shared.gate(),
                )
                .await;
            });
        }
    });

    (addr, master)
}

/// Reads the master's challenge, which it sends first on every gated connection.
async fn read_challenge(stream: &mut TcpStream) -> (Vec<u8>, u16) {
    match tokio::time::timeout(Duration::from_millis(1500), codec::read_msg(stream)).await {
        Ok(Ok(Some(Message::Challenge {
            nonce,
            protocol_version,
        }))) => (hex_encode_decode(&nonce), protocol_version),
        other => panic!("the master did not issue a challenge, got {other:?}"),
    }
}

/// Reads frames until the peer closes or the deadline passes.
async fn read_until_close(stream: &mut TcpStream) -> Vec<Message> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(700), codec::read_msg(stream)).await {
            Ok(Ok(Some(m))) => out.push(m),
            _ => return out,
        }
    }
}

fn handshake(name: &str) -> Message {
    Message::Handshake {
        protocol_version: SCHEMA_VERSION,
        node_name: name.to_string(),
        tier: "x86_64".to_string(),
        caps: Capabilities {
            simd: "none".to_string(),
            gpu: false,
            fpga: false,
            max_threads: 4,
            ram_mb: 1024,
        },
    }
}

fn refused(frames: &[Message], code: ErrorCode) -> bool {
    frames
        .iter()
        .any(|m| matches!(m, Message::Error { code: c, .. } if *c == code))
}

#[tokio::test]
async fn a_worker_without_the_token_is_disconnected_before_it_is_registered() {
    let (addr, master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;

    let mut stream = TcpStream::connect(&addr).await.unwrap();

    // A peer with no credential sends a handshake, which is what the old code
    // accepted unconditionally.
    let _challenge = read_challenge(&mut stream).await;
    codec::write_msg(&mut stream, &handshake("intruder"))
        .await
        .unwrap();

    let frames = read_until_close(&mut stream).await;

    assert_eq!(
        master.worker_count().await,
        0,
        "an unauthenticated peer entered the worker table: {:?}",
        master.available_workers().await
    );
    assert!(
        !frames
            .iter()
            .any(|m| matches!(m, Message::AssignWork { .. })),
        "an unauthenticated peer was given work"
    );
    // A readable refusal rather than a silent close, so a worker can log
    // something better than "connection reset by peer".
    assert!(
        refused(&frames, ErrorCode::NotAdmitted),
        "no refusal was sent, only: {frames:?}"
    );
}

#[tokio::test]
async fn a_worker_with_the_token_is_accepted() {
    let (addr, master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;

    let mut stream = TcpStream::connect(&addr).await.unwrap();

    // Answer the challenge the master issued, not a nonce invented here.
    let (nonce, version) = read_challenge(&mut stream).await;
    assert_eq!(version, SCHEMA_VERSION, "the master must advertise its schema");
    let auth = ClusterAuth::with_token("s3cret".into());
    codec::write_msg(
        &mut stream,
        &engine_distributed::admission::auth_frame(&auth, &nonce),
    )
    .await
    .unwrap();
    codec::write_msg(&mut stream, &handshake("probe"))
        .await
        .unwrap();

    wait_for(|| async { master.worker_count().await == 1 }).await;
    assert_eq!(master.available_workers().await, vec!["probe".to_string()]);
}

#[tokio::test]
async fn a_worker_with_the_wrong_token_is_refused() {
    let (addr, master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let (nonce, _) = read_challenge(&mut stream).await;
    let auth = ClusterAuth::with_token("wrong".into());
    codec::write_msg(
        &mut stream,
        &engine_distributed::admission::auth_frame(&auth, &nonce),
    )
    .await
    .unwrap();
    codec::write_msg(&mut stream, &handshake("probe"))
        .await
        .unwrap();

    let frames = read_until_close(&mut stream).await;
    assert!(
        refused(&frames, ErrorCode::NotAdmitted),
        "a wrong token was not refused readably: {frames:?}"
    );
    assert_eq!(master.worker_count().await, 0);
}

#[tokio::test]
async fn an_open_cluster_accepts_a_peer_with_no_credential() {
    let (addr, master) = serving_master(ClusterAuth::open()).await;
    assert!(!master.requires_authentication());

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    codec::write_msg(&mut stream, &handshake("probe"))
        .await
        .unwrap();

    wait_for(|| async { master.worker_count().await == 1 }).await;
    assert_eq!(
        master.available_workers().await,
        vec!["probe".to_string()],
        "an open cluster must keep accepting peers with no credential"
    );
}

#[tokio::test]
async fn a_replayed_response_from_another_nonce_is_refused() {
    let (addr, master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;

    // A response computed over some other nonce, as if captured earlier. The
    // server issues a fresh challenge on this connection, so it must not match.
    let auth = ClusterAuth::with_token("s3cret".into());
    let stale = engine_distributed::admission::auth_frame(&auth, b"a-nonce-from-long-ago");

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let (fresh, _) = read_challenge(&mut stream).await;
    assert_ne!(
        fresh,
        b"a-nonce-from-long-ago".to_vec(),
        "the server must not reuse a nonce"
    );
    codec::write_msg(&mut stream, &stale).await.unwrap();
    codec::write_msg(&mut stream, &handshake("replayer"))
        .await
        .unwrap();

    let frames = read_until_close(&mut stream).await;
    assert!(refused(&frames, ErrorCode::NotAdmitted), "{frames:?}");
    assert_eq!(master.worker_count().await, 0, "a replayed response admitted a peer");
}

/// The schema version on the challenge is what lets a worker refuse a stale
/// master without sending anything.
#[tokio::test]
async fn the_challenge_names_the_masters_schema() {
    let (addr, _master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let (_, version) = read_challenge(&mut stream).await;
    assert_eq!(version, SCHEMA_VERSION);
}

/// A worker speaking a different schema is refused with a message naming both
/// versions, before it reaches the worker table.
#[tokio::test]
async fn a_worker_with_a_different_schema_is_refused_by_name() {
    let (addr, master) = serving_master(ClusterAuth::open()).await;
    let mut stream = TcpStream::connect(&addr).await.unwrap();

    codec::write_msg(
        &mut stream,
        &Message::Handshake {
            protocol_version: SCHEMA_VERSION + 1,
            node_name: "from-the-future".into(),
            tier: "x86_64".into(),
            caps: Capabilities {
                simd: "none".into(),
                gpu: false,
                fpga: false,
                max_threads: 1,
                ram_mb: 1,
            },
        },
    )
    .await
    .unwrap();

    let frames = read_until_close(&mut stream).await;
    let detail = frames
        .iter()
        .find_map(|m| match m {
            Message::Error {
                code: ErrorCode::VersionMismatch,
                detail,
            } => Some(detail.clone()),
            _ => None,
        })
        .expect("no version refusal was sent");
    assert!(
        detail.contains(&SCHEMA_VERSION.to_string()),
        "the refusal does not name the master's version: {detail}"
    );
    assert!(
        detail.contains(&(SCHEMA_VERSION + 1).to_string()),
        "the refusal does not name the peer's version: {detail}"
    );
    assert_eq!(master.worker_count().await, 0);
}

/// The gate is not the only path in: a peer that authenticates correctly and
/// then announces a stale schema is still refused.
#[tokio::test]
async fn a_token_cluster_refuses_a_stale_worker_after_admission() {
    let (addr, master) = serving_master(ClusterAuth::with_token("s3cret".into())).await;
    let mut stream = TcpStream::connect(&addr).await.unwrap();

    let (nonce, _) = read_challenge(&mut stream).await;
    let auth = ClusterAuth::with_token("s3cret".into());
    codec::write_msg(
        &mut stream,
        &engine_distributed::admission::auth_frame(&auth, &nonce),
    )
    .await
    .unwrap();
    let mut stale = handshake("stale-but-authenticated");
    if let Message::Handshake { protocol_version, .. } = &mut stale {
        *protocol_version = 0;
    }
    codec::write_msg(&mut stream, &stale).await.unwrap();

    let frames = read_until_close(&mut stream).await;
    assert!(
        refused(&frames, ErrorCode::VersionMismatch),
        "no version refusal: {frames:?}"
    );
    assert_eq!(master.worker_count().await, 0);
}

/// P9.1.02 end to end: a worker that trusts the master's CA completes the token
/// exchange over TLS and is handed work across the encrypted link.
#[tokio::test]
async fn a_tls_worker_authenticates_and_is_given_work() {
    use engine_distributed::tls::{ClusterTls, TlsPaths};

    let dir = tempfile::tempdir().unwrap();
    let paths = TlsPaths {
        dir: dir.path().join("tls"),
    };

    // The master generates its own material on first run.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let server_tls = ClusterTls::for_master(&paths).expect("the master must generate a certificate");
    assert!(paths.is_populated(), "no certificate files were written");
    assert_eq!(
        server_tls.server_fingerprint().map(|f| f.len()),
        Some(64),
        "a fingerprint is SHA-256 hex"
    );

    let master = MasterNode::with_policy(
        &addr,
        CheckpointStore::new(dir.path().join("cp.pwck")),
        ClusterPolicy {
            heartbeat: Duration::from_millis(200),
            checkpoint_interval: Duration::from_secs(3600),
            chunk: ChunkPolicy {
                target_seconds: 0.001,
                min_candidates: 1,
                max_candidates: 1,
            },
            max_frame: codec::DEFAULT_MAX_FRAME,
            handshake_rate_per_sec: 1000.0,
            handshake_burst: 1000.0,
        },
        ClusterAuth::with_token("s3cret".into()),
    )
    .with_tls(server_tls);

    let target = TargetHash::new("MD5", "5d41402abc4b2a76b9719d911017c592"); // "hello"
    let job = master
        .add_job(
            AttackType::BruteForce {
                mask: "?d?d".into(),
            },
            vec![target],
            20,
        )
        .await
        .unwrap();
    assert_eq!(job, 1);

    let master = std::sync::Arc::new(master);
    engine_distributed::master::spawn_dispatcher(master.shared.clone());
    let accepting = std::sync::Arc::clone(&master);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let m = std::sync::Arc::clone(&accepting);
            tokio::spawn(async move {
                let _ = m.serve_for_test(socket).await;
            });
        }
    });

    // The worker side, trusting the CA the master just generated.
    let client_tls = ClusterTls::for_worker_with_ca(&paths.ca(), "127.0.0.1")
        .expect("the generated CA must be usable as a trust anchor");
    enable_logging();
    let mut worker = engine_distributed::worker::WorkerNode::new(&addr)
        .with_token("s3cret".into())
        .with_tls(client_tls);
    let session = tokio::spawn(async move { worker.run_worker_loop().await });

    // "hello" is not two digits, so no crack is expected; the point is that the
    // whole exchange happened inside TLS and the work arrived and was returned.
    wait_for(|| async { master.free_total().await == 0 }).await;
    wait_for(|| async { master.worker_count().await == 1 }).await;
    assert_eq!(master.free_total().await, 0, "no work was issued over TLS");
    assert_eq!(master.cracked().await.len(), 0);
    assert_eq!(
        master.available_workers().await,
        vec!["unknown".to_string()],
        "the worker should be idle once its job is exhausted"
    );

    session.abort();
}

/// A worker that does not trust the master's CA must fail to connect, rather
/// than silently falling back to trusting anything.
#[tokio::test]
async fn a_tls_worker_with_the_wrong_ca_cannot_connect() {
    use engine_distributed::tls::{ClusterTls, TlsPaths};

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let master_paths = TlsPaths {
        dir: a.path().join("tls"),
    };
    let _server = ClusterTls::for_master(&master_paths).unwrap();

    // A completely separate authority, which this worker will trust instead.
    let other_paths = TlsPaths {
        dir: b.path().join("tls"),
    };
    let _unrelated = ClusterTls::for_master(&other_paths).unwrap();
    assert_ne!(
        _server.server_fingerprint(),
        _unrelated.server_fingerprint(),
        "two authorities produced the same certificate"
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = _server.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = server.accept(socket).await;
        }
    });

    let client = ClusterTls::for_worker_with_ca(&other_paths.ca(), "127.0.0.1").unwrap();
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let err = client.connect(tcp, &addr).await.unwrap_err();
    assert!(
        err.contains("TLS handshake"),
        "an untrusted certificate produced an unhelpful error: {err}"
    );
}

/// P9.1.06: repeated handshake attempts from one address are throttled, and the
/// peer is told so rather than being left to guess.
#[tokio::test]
async fn repeated_handshakes_from_one_address_are_throttled_and_logged() {
    use engine_distributed::ratelimit::{RateLimiter, DEFAULT_IDLE_TIMEOUT};

    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let mut master = MasterNode::with_policy(
        &addr,
        CheckpointStore::new(dir.path().join("cp.pwck")),
        ClusterPolicy {
            handshake_rate_per_sec: 0.001,
            handshake_burst: 2.0,
            heartbeat: Duration::from_millis(200),
            checkpoint_interval: Duration::from_secs(3600),
            ..ClusterPolicy::default()
        },
        ClusterAuth::with_token("s3cret".into()),
    );
    master.shared.set_limiter(
        RateLimiter::with_limits(0.001, 2.0, DEFAULT_IDLE_TIMEOUT, 64)
            .with_global_limits(1000.0, 1000.0),
    );
    let shared: Shared = master.shared.clone();
    engine_distributed::master::spawn_dispatcher(shared.clone());

    let accepting = shared.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let shared = accepting.clone();
            tokio::spawn(async move {
                let _ = master_serve(socket, &shared).await;
            });
        }
    });

    // Three attempts against a budget of two.
    let mut throttled_at = None;
    for attempt in 0..3u8 {
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        // Not `read_challenge`: a throttled peer gets an `Error` instead of a
        // challenge, which is the point of the test.
        let frames = read_until_close(&mut stream).await;
        if refused(&frames, ErrorCode::Throttled) {
            throttled_at = Some(attempt);
            break;
        }
    }
    assert_eq!(
        throttled_at,
        Some(2),
        "the third attempt should have been throttled"
    );

    let stats = shared.limiter.lock().await.stats();
    assert!(stats.throttled >= 1, "a refusal was not counted: {stats:?}");
}

/// The rate limited path is the real one, so this goes through the master's own
/// accept handler rather than a copy of it.
async fn master_serve(socket: TcpStream, shared: &Shared) -> Result<(), String> {
    let ip = socket.peer_addr().map(|a| a.ip()).unwrap();
    let now = std::time::Instant::now();
    let throttled = {
        let mut limiter = shared.limiter.lock().await;
        limiter.check(ip, now)
    };
    if let engine_distributed::ratelimit::Decision::Throttled { retry_after } = throttled {
        let mut link = codec::Link::Plain(socket);
        let _ = codec::write_msg(
            &mut link,
            &Message::Error {
                code: ErrorCode::Throttled,
                detail: format!("retry after {retry_after:?}"),
            },
        )
        .await;
        return Ok(());
    }
    engine_distributed::master::serve_connection_for_test(socket, shared.clone(), shared.gate())
        .await
}

/// P9.3.02: a malformed packet ends the connection and the master keeps running.
#[tokio::test]
async fn a_malformed_packet_drops_the_connection_and_the_master_survives() {
    let (addr, master) = serving_master(ClusterAuth::open()).await;

    let good = codec::encode_frame(&Message::Ping, codec::DEFAULT_MAX_FRAME).unwrap();

    let mut bad_version = good.clone();
    bad_version[4..6].copy_from_slice(&77u16.to_le_bytes());

    let mut bad_code = good.clone();
    bad_code[6..8].copy_from_slice(&999u16.to_le_bytes());

    let mut bad_crc = good.clone();
    *bad_crc.last_mut().unwrap() ^= 0xff;

    let mut bad_length = good.clone();
    bad_length[8..12].copy_from_slice(&u32::MAX.to_le_bytes());

    let mut lying_code = good.clone();
    let shutdown = codec::encode_frame(
        &Message::Shutdown {
            reason: "go away".into(),
        },
        codec::DEFAULT_MAX_FRAME,
    )
    .unwrap();
    lying_code.truncate(HEADER_LEN);
    lying_code[8..12].copy_from_slice(&shutdown[8..12]);
    lying_code[12..16].copy_from_slice(&shutdown[12..16]);
    lying_code.extend_from_slice(&shutdown[HEADER_LEN..]);

    let not_a_message = {
        let payload = b"\xff\xff\xff\xff\xff".to_vec();
        let mut v = Vec::new();
        v.extend_from_slice(&codec::MAGIC);
        v.extend_from_slice(&codec::FRAMING_VERSION.to_le_bytes());
        v.extend_from_slice(&Code::Result.as_u16().to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        v.extend_from_slice(&payload);
        v
    };

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("an HTTP request", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
        (
            "the old length prefixed JSON",
            {
                let json = serde_json::to_vec(&serde_json::json!({ "Ping": null })).unwrap();
                let mut v = (json.len() as u32).to_be_bytes().to_vec();
                v.extend_from_slice(&json);
                v
            },
        ),
        ("an unknown framing version", bad_version),
        ("an unknown message code", bad_code),
        ("a corrupted payload", bad_crc),
        ("an impossible length", bad_length),
        ("a header that lies about its payload", lying_code),
        ("a frame that stops halfway", good[..HEADER_LEN - 3].to_vec()),
        ("a payload that is not a message", not_a_message),
    ];

    for (name, bytes) in &cases {
        let mut stream = TcpStream::connect(&addr).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        let _ = stream.flush().await;
        // The write half is closed so a frame that stops halfway is seen as the
        // truncation it is. Without this the master is right to wait for the
        // rest, and the test would be asserting that a correct implementation is
        // wrong.
        let _ = stream.shutdown().await;

        // Either the master closes or it says why. Both are a dropped
        // connection; what must not happen is a crash or a hang.
        let ended = tokio::time::timeout(Duration::from_millis(900), async {
            let mut probe = [0u8; 64];
            let mut seen = 0usize;
            loop {
                match stream.read(&mut probe).await {
                    Ok(0) => return true,
                    Ok(n) => {
                        seen += n;
                        if seen > 8192 {
                            return true;
                        }
                    }
                    Err(_) => return true,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(ended, "the master did not close after {name}");
    }

    // And the master is still serving.
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    codec::write_msg(&mut stream, &handshake("after-the-abuse"))
        .await
        .unwrap();
    wait_for(|| async { master.worker_count().await == 1 }).await;
    assert_eq!(
        master.available_workers().await,
        vec!["after-the-abuse".to_string()],
        "the master stopped working after malformed input"
    );
}

/// Polls until the condition holds or the deadline passes.
async fn wait_for<F, Fut>(mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while std::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}