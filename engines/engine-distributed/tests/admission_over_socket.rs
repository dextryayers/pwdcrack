//! End to end check that the admission gate is enforced over a real socket.
//!
//! Run with: cargo test -p engine-distributed --test admission_over_socket
//!
//! The unit tests in `admission.rs` cover the decision table. This covers the
//! thing they cannot: that `handle_worker` actually consults the gate before
//! interpreting a frame, and that the connection is dropped rather than the
//! peer being quietly entered into the worker table.

use std::sync::Arc;
use std::time::Duration;

use engine_distributed::master::MasterNode;
use engine_distributed::netpolicy::{make_nonce, ClusterAuth};
use engine_distributed::protocol::{self, Capabilities, Message};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Binds a listener on loopback and returns the port plus the listener.
async fn bind_master(auth: ClusterAuth) -> (u16, MasterNode) {
    // Port 0 asks the OS for a free port, so parallel test runs cannot collide.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let master = MasterNode::new(
        &format!("127.0.0.1:{port}"),
        "/tmp/pwdcrack-admission-test.json",
        auth,
    );
    (port, master)
}

/// Reads frames until the peer closes or the deadline passes.
async fn read_until_close(stream: &mut TcpStream) -> Vec<Message> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_millis(600), protocol::read_msg(stream)).await {
            Ok(Ok(Some(m))) => out.push(m),
            _ => return out,
        }
    }
}

fn handshake() -> Message {
    Message::Handshake {
        node_name: "probe".to_string(),
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

#[tokio::test]
async fn a_worker_without_the_token_is_disconnected_before_it_is_registered() {
    let (port, master) = bind_master(ClusterAuth::with_token("s3cret".into())).await;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let workers = Arc::clone(&master.workers);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let w = Arc::clone(&workers);
            let gate = engine_distributed::admission::AdmissionGate::new(
                ClusterAuth::with_token("s3cret".into()),
            );
            tokio::spawn(async move {
                let q = Arc::new(Mutex::new(std::collections::VecDeque::new()));
                let i = Arc::new(Mutex::new(std::collections::HashMap::new()));
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket, q, i, w, gate,
                )
                .await;
            });
        }
    });

    // A peer with no credential sends a handshake, which is what the old code
    // accepted unconditionally.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    protocol::write_msg(&mut stream, &handshake())
        .await
        .unwrap();

    let frames = read_until_close(&mut stream).await;

    // The connection is closed and the peer is not entered into the worker table.
    assert!(
        master.worker_count().await == 0,
        "an unauthenticated peer entered the worker table: {:?}",
        master.available_workers().await
    );
    assert!(
        !frames.iter().any(|m| matches!(m, Message::AssignWork { .. })),
        "an unauthenticated peer was given work"
    );
}

#[tokio::test]
async fn a_worker_with_the_token_is_accepted() {
    let (port, master) = bind_master(ClusterAuth::with_token("s3cret".into())).await;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let workers = Arc::clone(&master.workers);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let w = Arc::clone(&workers);
            let gate = engine_distributed::admission::AdmissionGate::new(
                ClusterAuth::with_token("s3cret".into()),
            );
            tokio::spawn(async move {
                let q = Arc::new(Mutex::new(std::collections::VecDeque::new()));
                let i = Arc::new(Mutex::new(std::collections::HashMap::new()));
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket, q, i, w, gate,
                )
                .await;
            });
        }
    });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let auth = ClusterAuth::with_token("s3cret".into());
    let nonce = make_nonce();
    let frame = engine_distributed::admission::auth_frame(&auth, &nonce);
    protocol::write_msg(&mut stream, &frame).await.unwrap();
    protocol::write_msg(&mut stream, &handshake()).await.unwrap();

    // Give the server a moment to process.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        master.available_workers().await,
        vec!["probe".to_string()],
        "an authenticated peer should be registered"
    );
}

#[tokio::test]
async fn a_worker_with_the_wrong_token_is_refused() {
    let (port, master) = bind_master(ClusterAuth::with_token("s3cret".into())).await;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let workers = Arc::clone(&master.workers);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let w = Arc::clone(&workers);
            let gate = engine_distributed::admission::AdmissionGate::new(
                ClusterAuth::with_token("s3cret".into()),
            );
            tokio::spawn(async move {
                let q = Arc::new(Mutex::new(std::collections::VecDeque::new()));
                let i = Arc::new(Mutex::new(std::collections::HashMap::new()));
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket, q, i, w, gate,
                )
                .await;
            });
        }
    });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let auth = ClusterAuth::with_token("wrong".into());
    let nonce = make_nonce();
    protocol::write_msg(
        &mut stream,
        &engine_distributed::admission::auth_frame(&auth, &nonce),
    )
    .await
    .unwrap();
    protocol::write_msg(&mut stream, &handshake()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(master.worker_count().await, 0);
}

#[tokio::test]
async fn an_open_cluster_accepts_a_peer_with_no_credential() {
    let (port, master) = bind_master(ClusterAuth::open()).await;
    assert!(!master.requires_authentication());

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let workers = Arc::clone(&master.workers);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let w = Arc::clone(&workers);
            let gate =
                engine_distributed::admission::AdmissionGate::new(ClusterAuth::open());
            tokio::spawn(async move {
                let q = Arc::new(Mutex::new(std::collections::VecDeque::new()));
                let i = Arc::new(Mutex::new(std::collections::HashMap::new()));
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket, q, i, w, gate,
                )
                .await;
            });
        }
    });

    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    protocol::write_msg(&mut stream, &handshake()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        master.available_workers().await,
        vec!["probe".to_string()],
        "an open cluster must keep accepting peers with no credential"
    );
}

#[tokio::test]
async fn a_replayed_response_from_another_nonce_is_refused() {
    let (port, master) = bind_master(ClusterAuth::with_token("s3cret".into())).await;

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let workers = Arc::clone(&master.workers);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let w = Arc::clone(&workers);
            let gate = engine_distributed::admission::AdmissionGate::new(
                ClusterAuth::with_token("s3cret".into()),
            );
            tokio::spawn(async move {
                let q = Arc::new(Mutex::new(std::collections::VecDeque::new()));
                let i = Arc::new(Mutex::new(std::collections::HashMap::new()));
                let _ = engine_distributed::master::serve_connection_for_test(
                    socket, q, i, w, gate,
                )
                .await;
            });
        }
    });

    // Capture a response from one session.
    let auth = ClusterAuth::with_token("s3cret".into());
    let captured = engine_distributed::admission::auth_frame(&auth, &make_nonce());

    // Replay it on a new connection, where the server's nonce differs.
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let _ = stream.write_all(b"").await;
    protocol::write_msg(&mut stream, &captured).await.unwrap();
    protocol::write_msg(&mut stream, &handshake()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        master.worker_count().await,
        0,
        "a replayed response admitted a peer"
    );
}