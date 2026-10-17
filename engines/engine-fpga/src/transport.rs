//! Transport abstraction and out of order completion handling.
//!
//! # Why a trait
//!
//! The scheduler previously took a concrete device handle, which opened a node
//! node with `OpenOptions`. That has two consequences. It cannot be constructed
//! in a test without hardware, and it cannot be made to return responses out of
//! order, which is exactly the behaviour P8.3.02 asks to be handled. A test that
//! cannot exercise reordering cannot claim reordering works.
//!
//! [`Transport`] is the seam. [`PcieTransport`] is the real one.
//! [`MockTransport`] is in this file and lets a test produce any completion order,
//! any number of duplicates, and any error it likes.
//!
//! # Why completions arrive out of order
//!
//! Several requests are outstanding at once, so the device is free to finish them
//! in whatever order it manages. A device with four cores working on four batches
//! will almost never complete them in submission order. Matching a completion to
//! its request by position rather than by sequence number attributes one batch's
//! result to another, which reports matches against the wrong candidates.
//!
//! [`CompletionQueue`] buffers out of order completions and hands them back in
//! sequence order, so a slow request cannot be overwritten by a fast one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{mpsc, Arc, Mutex};

use crate::error::{FpgaError, FpgaResult};

/// A bidirectional link to a device.
pub trait Transport: Send {
    /// Writes a request. Returns the number of bytes accepted.
    fn submit(&mut self, request: &[u8]) -> FpgaResult<usize>;

    /// Reads the next completion. Returns `None` when the queue is drained.
    ///
    /// Implementations must not block indefinitely; the caller applies a
    /// deadline.
    fn poll_completion(&mut self) -> FpgaResult<Option<Vec<u8>>>;

    /// Human readable name, for logs and for the engine listing.
    fn name(&self) -> &str;
}

/// The real transport, over a memory mapped PCIe BAR.
pub struct PcieTransport {
    file: std::fs::File,
    path: String,
}

impl PcieTransport {
    /// Opens the device node.
    ///
    /// The node must exist and must be readable and writable. Nothing here
    /// verifies that the node is an FPGA rather than any other character device:
    /// there is no reliable way to ask from userspace, so a wrong path produces a
    /// protocol failure later rather than a clear message here. The scheduler
    /// surfaces that as a timeout with the path in the message.
    pub fn open(path: &str) -> FpgaResult<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0)
            .open(path)
            .map_err(|e| FpgaError::DeviceNotFound(format!("{path}: {e}")))?;

        Ok(PcieTransport {
            file,
            path: path.to_string(),
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Transport for PcieTransport {
    fn submit(&mut self, request: &[u8]) -> FpgaResult<usize> {
        use std::os::unix::fs::FileExt;
        let n = self
            .file
            .write_at(request, 0)
            .map_err(|e| FpgaError::DmaError(format!("write to {}: {e}", self.path)))?;
        Ok(n)
    }

    fn poll_completion(&mut self) -> FpgaResult<Option<Vec<u8>>> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; crate::protocol::RESPONSE_LEN];
        let n = self
            .file
            .read_at(&mut buf, 0)
            .map_err(|e| FpgaError::DmaError(format!("read from {}: {e}", self.path)))?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some(buf))
    }

    fn name(&self) -> &str {
        "pcie"
    }
}

/// A transport for tests, driven entirely by the caller.
///
/// No timing, no threads, no device. A test decides exactly which completions
/// come back and in what order, which is the only way to assert that
/// [`CompletionQueue`] really reorders.
pub struct MockTransport {
    /// Completions to hand out, in the order they will be returned.
    ///
    /// A `VecDeque` with `pop_front`, so the order frames are pushed is the
    /// order they arrive. An earlier version used `Vec::pop`, which is LIFO and
    /// silently reversed every ordering test written against it.
    pending: VecDeque<Result<Vec<u8>, FpgaError>>,
    /// Requests the caller submitted, for assertions.
    pub submitted: Vec<Vec<u8>>,
    name: String,
}

impl MockTransport {
    pub fn new() -> Self {
        MockTransport {
            pending: VecDeque::new(),
            submitted: Vec::new(),
            name: "mock".to_string(),
        }
    }

    /// Queues a completion to arrive next.
    pub fn push_completion(&mut self, bytes: Vec<u8>) {
        self.pending.push_back(Ok(bytes));
    }

    /// Queues a transport level failure to arrive next.
    pub fn push_error(&mut self, err: FpgaError) {
        self.pending.push_back(Err(err));
    }

    /// Number of completions not yet returned.
    pub fn remaining(&self) -> usize {
        self.pending.len()
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for MockTransport {
    fn submit(&mut self, request: &[u8]) -> FpgaResult<usize> {
        self.submitted.push(request.to_vec());
        Ok(request.len())
    }

    fn poll_completion(&mut self) -> FpgaResult<Option<Vec<u8>>> {
        self.pending.pop_front().transpose()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// Reorders device completions into request submission order.
///
/// A request is declared with [`CompletionQueue::expect`]. Completions arrive in
/// whatever order the device produced them, through
/// [`CompletionQueue::deliver`], and leave in ascending sequence order through
/// [`CompletionQueue::try_recv`].
///
/// Emission is strictly ordered, not merely mostly ordered. If sequence 3 has
/// arrived but 1 and 2 have not, `try_recv` returns `None` and 3 stays buffered.
/// Emitting 3 early would hand the caller a result while the batches before it
/// are still running, and a caller that assigns results by arrival would credit
/// 3's matches to 1's candidates.
///
/// Two kinds of frame are refused rather than buffered, and both are counted:
///
/// - A completion whose sequence was never declared. There is nothing to
///   attribute it to, and buffering it forever would mask a device bug behind a
///   leak.
/// - A duplicate. The device should not send one, and honouring the second would
///   count the same batch twice.
#[derive(Debug, Default)]
pub struct CompletionQueue {
    /// Sequences declared outstanding and not yet emitted.
    expected: BTreeSet<u32>,
    /// Completed frames waiting to be emitted, keyed by sequence.
    ready: BTreeMap<u32, Vec<u8>>,
    dropped_duplicate: usize,
    dropped_unexpected: usize,
}

impl CompletionQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares sequence `seq` outstanding.
    ///
    /// Declaring does not release anything. The lowest buffered sequence stays
    /// held until every lower outstanding sequence has been delivered, which is
    /// what makes the ordering strict.
    pub fn expect(&mut self, seq: u32) {
        self.expected.insert(seq);
    }

    /// Accepts a completion.
    ///
    /// Returns `true` if it was buffered. `false` means it was dropped: either a
    /// duplicate, or a sequence that was never declared.
    pub fn deliver(&mut self, seq: u32, bytes: Vec<u8>) -> bool {
        if !self.expected.contains(&seq) {
            self.dropped_unexpected += 1;
            return false;
        }
        if self.ready.contains_key(&seq) {
            self.dropped_duplicate += 1;
            return false;
        }
        self.ready.insert(seq, bytes);
        true
    }

    /// Takes the lowest buffered sequence, if no lower outstanding sequence is
    /// still missing, and removes that sequence from the outstanding set.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        let lowest_buffered = *self.ready.keys().next()?;
        let blocked = self
            .expected
            .iter()
            .any(|seq| *seq < lowest_buffered);
        if blocked {
            return None;
        }
        self.expected.remove(&lowest_buffered);
        self.ready.remove(&lowest_buffered)
    }

    /// Sequence numbers buffered but not yet emitted.
    pub fn buffered(&self) -> Vec<u32> {
        self.ready.keys().copied().collect()
    }

    /// Sequences still outstanding.
    pub fn outstanding(&self) -> Vec<u32> {
        self.expected.iter().copied().collect()
    }

    pub fn dropped_duplicate(&self) -> usize {
        self.dropped_duplicate
    }

    pub fn dropped_unexpected(&self) -> usize {
        self.dropped_unexpected
    }

    /// True when every declared sequence has been emitted.
    pub fn is_complete(&self) -> bool {
        self.expected.is_empty() && self.ready.is_empty()
    }
}

/// A reader thread that turns device completions into ordered results.
///
/// This is the P8.3.02 worker model. The thread owns the transport for its
/// lifetime, which is why there is one worker per transport: a single transport
/// cannot be polled from two threads without synchronisation, and that
/// synchronisation would cost more than the device read it protected.
///
/// The queue is shared with the caller through an `Arc<Mutex<_>>`. The caller
/// declares each request with [`CompletionQueue::expect`] before submitting it,
/// and the worker declares nothing, because only the caller knows what it sent.
/// Frames the caller never declared are refused by the queue rather than
/// buffered.
///
/// Ordering is produced by the queue, not by the thread. The thread only drains
/// it: every frame handed to `sink` has passed [`crate::protocol::parse_response`]
/// and every lower outstanding sequence has already been delivered.
pub struct CompletionWorker {
    /// Held so the owner can signal the thread to stop.
    tx: mpsc::Sender<WorkerMessage>,
    handle: Option<std::thread::JoinHandle<()>>,
}

enum WorkerMessage {
    Stop,
}

impl CompletionWorker {
    /// Starts a reader thread over `transport`.
    ///
    /// The thread polls until `stop`, until the transport reports end of queue,
    /// or until the transport errors. Errors end the thread rather than
    /// propagating: the thread has no return path, and a device that has gone
    /// away cannot be recovered from here. Anything already delivered to `sink`
    /// stays valid.
    pub fn start<T, S>(
        mut transport: T,
        queue: Arc<Mutex<CompletionQueue>>,
        mut sink: S,
    ) -> Self
    where
        T: Transport + 'static,
        S: FnMut(u32, Vec<u8>) + Send + 'static,
    {
        let (stop_tx, stop_rx) = mpsc::channel::<WorkerMessage>();
        let handle = std::thread::spawn(move || {
            let worker_queue = queue;
            let mut stopping = false;
            loop {
                if !stopping && matches!(stop_rx.try_recv(), Ok(WorkerMessage::Stop)) {
                    stopping = true;
                }

                match transport.poll_completion() {
                    Ok(Some(bytes)) => {
                        // A corrupt frame must not take the worker down. Killing
                        // the thread here would lose every other in-flight
                        // request with it, and a bit flip is a reason to drop one
                        // frame, not to abandon the batch.
                        if let Ok(resp) = crate::protocol::parse_response(&bytes) {
                            let mut q = worker_queue.lock().unwrap_or_else(|e| e.into_inner());
                            if q.deliver(resp.seq_id, bytes) {
                                drain(&mut q, &mut sink);
                            }
                        }
                    }
                    // The transport has nothing left. This is the only exit other
                    // than a transport error, and it is reached after a stop as
                    // well, so a stop drains what is already in flight rather than
                    // discarding it.
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        CompletionWorker {
            tx: stop_tx,
            handle: Some(handle),
        }
    }

    /// Signals the thread to stop and waits for it.
    pub fn stop(mut self) {
        let _ = self.tx.send(WorkerMessage::Stop);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Emits every frame the queue is currently willing to release, in order.
///
/// A poisoned lock is recovered rather than propagated: the queue contains no
/// invariant that a panic could have left broken, and losing the batch because a
/// sink panicked is worse than the panic.
fn drain<S: FnMut(u32, Vec<u8>)>(queue: &mut CompletionQueue, sink: &mut S) {
    while let Some(bytes) = queue.try_recv() {
        if let Ok(resp) = crate::protocol::parse_response(&bytes) {
            sink(resp.seq_id, bytes);
        }
    }
}

impl Drop for CompletionWorker {
    fn drop(&mut self) {
        let _ = self.tx.send(WorkerMessage::Stop);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{self, Command, HashType};

    fn frame(seq: u32, found: u32) -> Vec<u8> {
        protocol::build_response(Command::Crack, HashType::Md5, seq, found)
    }

    /// The behaviour P8.3.02 exists for: a device that finishes request 3 before
    /// request 2 must not make the caller believe 2 is done.
    #[test]
    fn completions_out_of_order_are_reordered() {
        let mut q = CompletionQueue::new();
        q.expect(1);
        q.expect(2);
        q.expect(3);

        // The device finishes 3, then 1, and 2 is still running.
        assert!(q.deliver(3, frame(3, 3)));
        assert!(q.deliver(1, frame(1, 1)));
        assert_eq!(q.buffered(), vec![1, 3]);

        // 1 is the lowest buffered and nothing lower is outstanding, so it goes.
        let first = q.try_recv().expect("sequence 1 is releasable");
        assert_eq!(protocol::parse_response(&first).unwrap().seq_id, 1);

        // 3 is buffered but 2 is still outstanding, so 3 must stay put.
        assert!(
            q.try_recv().is_none(),
            "sequence 3 must not overtake the outstanding sequence 2"
        );
        assert_eq!(q.buffered(), vec![3]);
        // 3 is outstanding in the sense that matters here: it is declared and
        // not yet emitted, which is why it cannot be released past 2.
        assert_eq!(q.outstanding(), vec![2, 3]);

        // 2 lands, and both drain in order.
        assert!(q.deliver(2, frame(2, 2)));
        let second = q.try_recv().expect("sequence 2");
        assert_eq!(protocol::parse_response(&second).unwrap().seq_id, 2);
        let third = q.try_recv().expect("sequence 3");
        assert_eq!(protocol::parse_response(&third).unwrap().seq_id, 3);

        assert!(q.try_recv().is_none());
        assert!(q.is_complete());
    }

    #[test]
    fn duplicate_completion_is_dropped_not_double_counted() {
        let mut q = CompletionQueue::new();
        q.expect(1);
        assert!(q.deliver(1, frame(1, 5)));
        assert!(!q.deliver(1, frame(1, 5)), "second copy must be dropped");
        assert_eq!(q.dropped_duplicate(), 1);
        assert!(q.try_recv().is_some());
        assert!(q.try_recv().is_none(), "the batch must be counted once");
    }

    /// A completion for a sequence the caller never declared is refused. There is
    /// no request to attribute it to, and buffering it would hide a device bug
    /// behind a growing map.
    #[test]
    fn completion_for_an_undeclared_sequence_is_refused() {
        let mut q = CompletionQueue::new();
        q.expect(1);
        assert!(!q.deliver(9, frame(9, 0)));
        assert_eq!(q.dropped_unexpected(), 1);
        assert!(q.buffered().is_empty());
    }

    /// Reordering must survive an arbitrary arrival permutation, not just the one
    /// hand written case above. Exhaustively checked over every order of four
    /// completions.
    #[test]
    fn every_arrival_permutation_yields_submission_order() {
        fn permutations(items: Vec<u32>) -> Vec<Vec<u32>> {
            if items.is_empty() {
                return vec![Vec::new()];
            }
            let mut out = Vec::new();
            for i in 0..items.len() {
                let mut rest = items.clone();
                let head = rest.remove(i);
                for mut tail in permutations(rest) {
                    tail.insert(0, head);
                    out.push(tail);
                }
            }
            out
        }

        let orders = permutations(vec![1, 2, 3, 4]);
        assert_eq!(orders.len(), 24, "4! permutations");
        for order in &orders {
            let mut q = CompletionQueue::new();
            for seq in 1..=4 {
                q.expect(seq);
            }
            for &seq in order {
                assert!(q.deliver(seq, frame(seq, seq)));
            }
            let mut emitted = Vec::new();
            while let Some(b) = q.try_recv() {
                emitted.push(protocol::parse_response(&b).unwrap().seq_id);
            }
            assert_eq!(emitted, vec![1, 2, 3, 4], "arrival order {order:?}");
        }
    }

    #[test]
    fn corrupted_frame_never_reaches_the_sink() {
        let (sink_tx, sink_rx) = mpsc::channel::<Vec<u8>>();
        let mut mock = MockTransport::new();
        let mut bad = frame(1, 1);
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        mock.push_completion(bad);
        mock.push_completion(frame(1, 1));

        let queue = Arc::new(Mutex::new(CompletionQueue::new()));
        queue.lock().unwrap().expect(1);

        let worker = CompletionWorker::start(mock, queue, move |_seq, bytes| {
            let _ = sink_tx.send(bytes).ok();
        });
        worker.stop();

        let got = sink_rx.try_recv().expect("the good frame should arrive");
        assert!(protocol::parse_response(&got).is_ok());
        assert_eq!(protocol::parse_response(&got).unwrap().found, 1);
    }

    /// The end to end ordering claim: the worker emits in submission order even
    /// though the mock hands the frames over back to front.
    #[test]
    fn worker_emits_in_submission_order_from_a_reversed_device() {
        let (sink_tx, sink_rx) = mpsc::channel::<(u32, Vec<u8>)>();
        let mut mock = MockTransport::new();
        // Pushed in arrival order, so the device appears to finish 3 first.
        mock.push_completion(frame(3, 3));
        mock.push_completion(frame(2, 2));
        mock.push_completion(frame(1, 1));

        let queue = Arc::new(Mutex::new(CompletionQueue::new()));
        for seq in 1..=3 {
            queue.lock().unwrap().expect(seq);
        }

        let worker = CompletionWorker::start(mock, queue, move |seq, bytes| {
            let _ = sink_tx.send((seq, bytes)).ok();
        });
        worker.stop();

        let mut order = Vec::new();
        while let Ok((seq, bytes)) = sink_rx.try_recv() {
            assert_eq!(protocol::parse_response(&bytes).unwrap().seq_id, seq);
            order.push(seq);
        }
        assert_eq!(order, vec![1, 2, 3]);
    }

    #[test]
    fn transport_error_ends_the_worker_without_panicking() {
        let (sink_tx, sink_rx) = mpsc::channel::<Vec<u8>>();
        let mut mock = MockTransport::new();
        mock.push_error(FpgaError::DmaError("simulated link failure".into()));
        mock.push_completion(frame(1, 1));

        let queue = Arc::new(Mutex::new(CompletionQueue::new()));
        queue.lock().unwrap().expect(1);

        let worker = CompletionWorker::start(mock, queue, move |_seq, bytes| {
            let _ = sink_tx.send(bytes).ok();
        });
        worker.stop();
        // The worker stopped at the error, so nothing after it arrived.
        assert!(sink_rx.try_recv().is_err());
    }

    #[test]
    fn mock_transport_records_submissions() {
        let mut mock = MockTransport::new();
        let req = protocol::build_crack_request(1, HashType::Md5, &[0u8; 64]).unwrap();
        let n = mock.submit(&req).unwrap();
        assert_eq!(n, req.len());
        assert_eq!(mock.submitted.len(), 1);
        assert_eq!(mock.submitted[0], req);
    }
}