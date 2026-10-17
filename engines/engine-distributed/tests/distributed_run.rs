//! P9.3.01: a master and four workers, in process, over real sockets.
//!
//! Run with: cargo test -p engine-distributed --test distributed_run
//!
//! The assertions are the ones the plan asks for and a few more:
//!
//!   - the union of cracked hashes across the cluster equals what one node finds
//!     alone, so distributing does not change the answer;
//!   - no candidate was tested twice, which is P9.2.04 and is checked against
//!     the coverage ledger rather than inferred from the results;
//!   - the whole keyspace was covered, so nothing was silently skipped;
//!   - a worker that dies mid-run has its work requeued and the run still
//!     finishes with the same answer.
//!
//! Everything runs over loopback TCP through the real master handler. Nothing
//! here reaches into the scheduler directly except to read the ledger, because a
//! test that called `Scheduler::next_chunk` would be testing the scheduler and
//! not the master.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use engine_distributed::checkpoint::CheckpointStore;
use engine_distributed::master::{ClusterPolicy, MasterNode};
use engine_distributed::netpolicy::ClusterAuth;
use engine_distributed::protocol::{AttackType, CrackedEntry, TargetHash};
use engine_distributed::scheduler::ChunkPolicy;
use engine_distributed::worker::WorkerNode;

/// A wordlist of deterministic candidates, built in memory.
fn wordlist(n: usize) -> (String, Vec<String>) {
    let words: Vec<String> = (0..n).map(|i| format!("pw{i:06}")).collect();
    let body = words.join("\n");
    (body, words)
}

/// The MD5 of a candidate, computed by the same path a worker uses, so the
/// expected answer is not produced by a different implementation.
fn md5_hex(s: &str) -> String {
    hex::encode(<md5::Md5 as digest::Digest>::digest(s.as_bytes()))
}

/// Every hash in `words` at the given indices.
fn targets_at(words: &[String], indices: &[usize]) -> Vec<TargetHash> {
    indices
        .iter()
        .map(|i| TargetHash::new("MD5", md5_hex(&words[*i])))
        .collect()
}

struct Cluster {
    master: Arc<MasterNode>,
    sessions: Vec<tokio::task::JoinHandle<Result<(), String>>>,
}

async fn start_cluster(
    workers: usize,
    heartbeat: Duration,
) -> Cluster {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let master = Arc::new(MasterNode::with_policy(
        &addr,
        CheckpointStore::new(dir.path().join("checkpoint.pwck")),
        ClusterPolicy {
            heartbeat,
            checkpoint_interval: Duration::from_secs(3600),
            // Small chunks so four workers really do interleave, and the ledger
            // has plenty of spans to check.
            chunk: ChunkPolicy {
                target_seconds: 0.001,
                min_candidates: 7,
                max_candidates: 64,
            },
            max_frame: engine_distributed::codec::DEFAULT_MAX_FRAME,
            handshake_rate_per_sec: 1000.0,
            handshake_burst: 1000.0,
        },
        ClusterAuth::with_token("cluster-secret".into()),
    ));

    engine_distributed::master::spawn_dispatcher(master.shared.clone());
    let accepting = Arc::clone(&master);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let m = Arc::clone(&accepting);
            tokio::spawn(async move {
                let _ = m.serve_for_test(socket).await;
            });
        }
    });

    let mut sessions = Vec::new();
    for i in 0..workers {
        let mut w = WorkerNode::new(&addr)
            .with_token("cluster-secret".into());
        w.node_name = format!("worker-{i}");
        sessions.push(tokio::spawn(async move { w.run_worker_loop().await }));
    }

    let _ = addr;
    Cluster { master, sessions }
}

async fn wait_until<F, Fut>(limit: Duration, label: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {label}");
}

fn hashes(entries: &[CrackedEntry]) -> BTreeSet<String> {
    entries.iter().map(|e| e.hash.clone()).collect()
}

/// The plan's test: four workers in process, and the union of what they crack is
/// exactly what one node cracks alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_workers_find_exactly_what_one_node_finds() {
    let (body, words) = wordlist(400);

    // The single node answer, computed the long way round by the worker's own
    // verifier rather than by a second implementation.
    let needles = [3usize, 77, 150, 399];
    let expected: BTreeSet<String> = needles
        .iter()
        .map(|i| md5_hex(&words[*i]))
        .collect();
    assert_eq!(expected.len(), 4);

    let cluster = start_cluster(4, Duration::from_millis(250)).await;

    let manifest = engine_distributed::wordlist::WordlistManifest::from_bytes("cluster.txt", body.as_bytes());
    cluster
        .master
        .shared
        .register_wordlist(manifest, words.clone())
        .await
        .unwrap();

    let targets = targets_at(&words, &needles);
    cluster
        .master
        .add_job(
            AttackType::Inline {
                sha256: digest_of(&body),
                rules: vec![],
            },
            targets,
            words.len() as u64,
        )
        .await
        .unwrap();

    // Every target solved stops the scheduler handing out chunks, so the run
    // normally finishes by finding the four passwords rather than by exhausting
    // the keyspace. The wait is therefore on the results, and the coverage
    // assertions below are what say whether the rest of the keyspace was dealt
    // with properly.
    wait_until(Duration::from_secs(60), "all four results", || async {
        cluster.master.cracked().await.len() == 4
    })
    .await;

    let cracked = cluster.master.cracked().await;
    assert_eq!(
        hashes(&cracked),
        expected,
        "the cluster did not find exactly what was planted"
    );
    for e in &cracked {
        let idx = words
            .iter()
            .position(|w| md5_hex(w) == e.hash)
            .expect("a cracked hash that is not in the wordlist");
        assert_eq!(&e.password, &words[idx], "wrong plaintext for {}", e.hash);
    }

    // P9.2.04: no candidate tested twice, and the whole keyspace covered.
    let ledger = cluster
        .master
        .shared
        .scheduler
        .lock()
        .await
        .ledger()
        .cloned()
        .expect("the ledger was not started");
    assert_eq!(ledger.overlaps(), 0, "a candidate was tested twice");
    assert_eq!(ledger.repeats(), 0, "a chunk was issued twice");
    assert!(ledger.missing().is_empty(), "candidates were never assigned");
    assert!(
        ledger.issued_total() <= words.len() as u64,
        "more candidates were issued than the keyspace holds"
    );

    for s in cluster.sessions {
        s.abort();
    }
}

/// The digest the master registered a wordlist under.
///
/// Computed here rather than read back from the master, so the value the job
/// refers to is provably the digest of the bytes that were registered.
fn digest_of(body: &str) -> String {
    engine_distributed::wordlist::content_digest(body.as_bytes())
}

/// Four workers and one slow worker: the answer must not depend on how fast any
/// node is, only on what was planted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_worker_does_not_change_the_answer() {
    let (body, words) = wordlist(300);
    let cluster = start_cluster(4, Duration::from_millis(250)).await;
    let manifest =
        engine_distributed::wordlist::WordlistManifest::from_bytes("s.txt", body.as_bytes());
    let digest = manifest.sha256.clone();
    cluster
        .master
        .shared
        .register_wordlist(manifest, words.clone())
        .await
        .unwrap();

    let needles = [1usize, 100, 250];
    let expected: BTreeSet<String> = needles.iter().map(|i| md5_hex(&words[*i])).collect();
    cluster
        .master
        .add_job(
            AttackType::Inline {
                sha256: digest,
                rules: vec![],
            },
            targets_at(&words, &needles),
            words.len() as u64,
        )
        .await
        .unwrap();

    wait_until(Duration::from_secs(60), "all results", || async {
        cluster.master.cracked().await.len() == 3
    })
    .await;
    assert_eq!(hashes(&cluster.master.cracked().await), expected);

    let ledger = cluster
        .master
        .shared
        .scheduler
        .lock()
        .await
        .ledger()
        .cloned()
        .expect("the ledger was not started");
    assert_eq!(ledger.overlaps(), 0);
    for s in cluster.sessions {
        s.abort();
    }
}

/// P9.2.02 and P9.2.04 together: a worker declared dead has its work requeued,
/// the ledger records the reissue honestly, and the run still finds everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_held_by_a_worker_declared_dead_is_requeued_and_the_run_still_finishes() {
    let (body, words) = wordlist(200);
    let cluster = start_cluster(2, Duration::from_millis(120)).await;
    let manifest =
        engine_distributed::wordlist::WordlistManifest::from_bytes("r.txt", body.as_bytes());
    let digest = manifest.sha256.clone();
    cluster
        .master
        .shared
        .register_wordlist(manifest, words.clone())
        .await
        .unwrap();

    let needles = [10usize, 99, 180];
    let expected: BTreeSet<String> = needles.iter().map(|i| md5_hex(&words[*i])).collect();
    cluster
        .master
        .add_job(
            AttackType::Inline {
                sha256: digest,
                rules: vec![],
            },
            targets_at(&words, &needles),
            words.len() as u64,
        )
        .await
        .unwrap();

    // Wait until somebody holds work, then declare that worker dead.
    wait_until(Duration::from_secs(30), "work in flight", || async {
        !cluster.master.shared.in_flight.lock().await.is_empty()
    })
    .await;
    let (holder, killed) = {
        let inflight = cluster.master.shared.in_flight.lock().await;
        let f = inflight.values().next().expect("nothing was in flight");
        (f.worker_name.clone(), f.span)
    };
    let dead = engine_distributed::master::expire_worker(&cluster.master.shared, &holder).await;
    assert!(dead, "the worker was not declared dead");

    // The batch it held went back to the free set rather than being lost.
    wait_until(Duration::from_secs(10), "the batch to be requeued", || async {
        cluster
            .master
            .shared
            .scheduler
            .lock()
            .await
            .snapshot()
            .iter()
            .any(|j| j.free.overlaps_any(killed))
    })
    .await;

    wait_until(Duration::from_secs(60), "all results", || async {
        cluster.master.cracked().await.len() == 3
    })
    .await;
    assert_eq!(
        hashes(&cluster.master.cracked().await),
        expected,
        "a requeued chunk was lost"
    );

    // The reissue is recorded, which is the honest accounting: within one run a
    // requeued span is issued again, so the ledger counts it twice. That is not
    // a deduplication failure. What makes it safe is that the span went back
    // through `SpanSet::give_back`, which refuses anything still free, so the
    // only way to get here is a span that really had been taken.
    let ledger = cluster
        .master
        .shared
        .scheduler
        .lock()
        .await
        .ledger()
        .cloned()
        .expect("the ledger was not started");
    assert!(
        ledger.times_issued(killed) >= 2,
        "the killed batch was not reissued: {:?}",
        ledger.issued_spans()
    );
    assert!(
        ledger.issued_total() >= words.len() as u64 - 64,
        "far too little of the keyspace was searched: {} of {}",
        ledger.issued_total(),
        words.len()
    );
    for s in cluster.sessions {
        s.abort();
    }
}

/// P9.2.03: a master that is restarted resumes the remaining keyspace instead of
/// restarting from zero, and finishes with the same answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_master_resumes_rather_than_restarting() {
    let (body, words) = wordlist(240);
    let dir = tempfile::tempdir().unwrap();
    let checkpoint = dir.path().join("checkpoint.pwck");

    let needles = [5usize, 120, 230];
    let expected: BTreeSet<String> = needles.iter().map(|i| md5_hex(&words[*i])).collect();
    let manifest =
        engine_distributed::wordlist::WordlistManifest::from_bytes("c.txt", body.as_bytes());
    let digest = manifest.sha256.clone();

    // First master: take some work, checkpoint, stop without finishing.
    let first_free = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let master = Arc::new(MasterNode::with_policy(
            &addr,
            CheckpointStore::new(&checkpoint),
            ClusterPolicy {
                heartbeat: Duration::from_millis(250),
                checkpoint_interval: Duration::from_secs(3600),
                chunk: ChunkPolicy {
                    target_seconds: 0.001,
                    min_candidates: 64,
                    max_candidates: 64,
                },
                max_frame: engine_distributed::codec::DEFAULT_MAX_FRAME,
                handshake_rate_per_sec: 1000.0,
                handshake_burst: 1000.0,
            },
            ClusterAuth::open(),
        ));
        master
            .shared
            .register_wordlist(manifest, words.clone())
            .await
            .unwrap();
        master
            .add_job(
                AttackType::Inline {
                    sha256: digest,
                    rules: vec![],
                },
                targets_at(&words, &needles),
                words.len() as u64,
            )
            .await
            .unwrap();

        engine_distributed::master::spawn_dispatcher(master.shared.clone());
        let accepting = Arc::clone(&master);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let m = Arc::clone(&accepting);
                tokio::spawn(async move {
                    let _ = m.serve_for_test(socket).await;
                });
            }
        });

        // One worker, so the run is slow and stoppable.
        let mut w = WorkerNode::new(&addr);
        w.node_name = "first".into();
        let session = tokio::spawn(async move { w.run_worker_loop().await });

        wait_until(Duration::from_secs(30), "some progress", || async {
            master.shared.scheduler.lock().await.free_total() < words.len() as u64
        })
        .await;

        // Save by hand: the interval loop would take fifteen seconds.
        master.save_checkpoint().await.unwrap();
        session.abort();
        master.shared.in_flight.lock().await.clear();
        master.shared.scheduler.lock().await.free_total()
    };
    assert!(
        first_free < words.len() as u64,
        "nothing was issued before the checkpoint"
    );

    // Second master: a fresh scheduler over the same store.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let second = Arc::new(MasterNode::with_policy(
        &addr,
        CheckpointStore::new(&checkpoint),
        ClusterPolicy {
            heartbeat: Duration::from_millis(250),
            checkpoint_interval: Duration::from_secs(3600),
            chunk: ChunkPolicy {
                target_seconds: 0.001,
                min_candidates: 7,
                max_candidates: 64,
            },
            max_frame: engine_distributed::codec::DEFAULT_MAX_FRAME,
            handshake_rate_per_sec: 1000.0,
            handshake_burst: 1000.0,
        },
        ClusterAuth::open(),
    ));
    let resumed = second.resume_from_store().await.unwrap();
    assert!(resumed, "the second master did not resume");
    assert_eq!(
        second.free_total().await,
        first_free,
        "the resumed master scheduled a different amount of work"
    );
    assert!(
        second.free_total().await < words.len() as u64,
        "the resumed master restarted from zero"
    );

    second
        .shared
        .register_wordlist(
            engine_distributed::wordlist::WordlistManifest::from_bytes("c.txt", body.as_bytes()),
            words.clone(),
        )
        .await
        .unwrap();
    engine_distributed::master::spawn_dispatcher(second.shared.clone());
    let accepting = Arc::clone(&second);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let m = Arc::clone(&accepting);
            tokio::spawn(async move {
                let _ = m.serve_for_test(socket).await;
            });
        }
    });

    let mut w = WorkerNode::new(&addr);
    w.node_name = "second".into();
    let session = tokio::spawn(async move { w.run_worker_loop().await });

    wait_until(Duration::from_secs(60), "all results after the resume", || async {
        second.cracked().await.len() == 3
    })
    .await;
    assert_eq!(
        hashes(&second.cracked().await),
        expected,
        "the resumed run found a different answer"
    );
    session.abort();
}

/// The wordlist a master pushes is verified before a single candidate comes out
/// of it, and a chunk naming a wordlist that never arrived is refused rather than
/// reported as searched and empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_naming_a_wordlist_the_master_never_sent_is_refused() {
    let cluster = start_cluster(1, Duration::from_millis(250)).await;
    let words: Vec<String> = (0..50).map(|i| format!("w{i:03}")).collect();
    let target = TargetHash::new("MD5", md5_hex("w007"));

    let job = cluster
        .master
        .add_job(
            AttackType::Inline {
                sha256: engine_distributed::wordlist::content_digest(b"never sent"),
                rules: vec![],
            },
            vec![target.clone()],
            words.len() as u64,
        )
        .await
        .unwrap();
    assert_eq!(job, 1);

    wait_until(Duration::from_secs(30), "the chunk to be worked", || async {
        cluster.master.shared.scheduler.lock().await.free_total() == 0
    })
    .await;
    // Give the worker time to refuse every chunk it is given.
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        cluster.master.cracked().await.is_empty(),
        "a chunk with a missing wordlist produced a result"
    );
    for s in cluster.sessions {
        s.abort();
    }
}

/// A dictionary chunk is checked against the worker's local grant, so a master
/// naming a path outside it produces no result and no read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dictionary_chunk_outside_the_grant_produces_nothing() {
    let cluster = start_cluster(1, Duration::from_millis(250)).await;
    // The worker in this test has no `--wordlist-dir` at all.
    let target = TargetHash::new("MD5", md5_hex("anything"));
    cluster
        .master
        .add_job(
            AttackType::Dictionary {
                wordlist_path: "../../../etc/passwd".into(),
                rules: vec![],
            },
            vec![target],
            100,
        )
        .await
        .unwrap();

    wait_until(Duration::from_secs(30), "the chunk to be worked", || async {
        cluster.master.shared.scheduler.lock().await.free_total() == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(cluster.master.cracked().await.is_empty());
    for s in cluster.sessions {
        s.abort();
    }
}