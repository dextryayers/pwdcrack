//! P8.3.03: the scheduler against a simulated device.
//!
//! The device here is not a stub. It parses the request with the same decoder the
//! host uses, computes a real MD5 over each candidate slot, compares it to a
//! target, and returns the match positions as a bitmask. The scheduler under test
//! knows nothing about the digest; it only splits slots into requests, sends
//! them, and reads the masks back. So a test that passes here shows that result
//! attribution is correct across request boundaries, not merely that the plumbing
//! runs.
//!
//! Every failure mode the protocol is supposed to catch has a case below, driven
//! by a `Misbehaviour` value the simulated device acts on. Without them, a
//! scheduler that ignored the CRC, ignored the sequence number, or accepted any
//! protocol version would still pass.

use engine_fpga::error::FpgaError;
use engine_fpga::protocol::{
    self, Command, HashType, MAX_PAYLOAD_LEN, REQUEST_HEADER_LEN, RESPONSE_LEN, SLOT_LEN,
};
use engine_fpga::scheduler::FpgaScheduler;
use engine_fpga::transport::Transport;
use std::sync::Arc;
use std::sync::Mutex;

/// How the simulated device should misbehave on the next request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Misbehaviour {
    /// Behave correctly.
    None,
    /// Corrupt one bit of the reply's checksum.
    BadCrc,
    /// Echo a sequence number the host never sent.
    WrongSequence,
    /// Speak a protocol revision the host does not.
    WrongVersion,
    /// Report a different iteration count than was requested.
    WrongIterationCount,
    /// Report matches in the wrong bit positions.
    ShiftedMask,
    /// Never reply.
    Silent,
}

/// Requests the device saw, for assertions.
#[derive(Debug, Default)]
struct Log {
    requests: Vec<Vec<u8>>,
}

/// A device that computes MD5 and can be told to misbehave.
struct SimulatedDevice {
    /// The digest every candidate is compared against.
    target: [u8; 16],
    replies: Vec<Vec<u8>>,
    misbehaviour: Misbehaviour,
    log: Arc<Mutex<Log>>,
}

impl SimulatedDevice {
    fn new(target: [u8; 16], log: Arc<Mutex<Log>>) -> Self {
        SimulatedDevice {
            target,
            replies: Vec::new(),
            misbehaviour: Misbehaviour::None,
            log,
        }
    }

    /// Decodes a request the way a device would, and returns the match mask.
    ///
    /// This is an independent read of the wire format rather than a call into
    /// the host's encoder, so an error in the encoder cannot hide behind a
    /// matching error in the decoder.
    fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        let mode = self.misbehaviour;
        if mode == Misbehaviour::Silent {
            return Vec::new();
        }

        assert!(
            request.len() >= REQUEST_HEADER_LEN + 4,
            "request shorter than a header plus checksum"
        );

        let magic = u32::from_le_bytes(request[0..4].try_into().unwrap());
        assert_eq!(magic, protocol::MAGIC_HOST, "request magic");
        let version = u16::from_le_bytes(request[4..6].try_into().unwrap());
        assert_eq!(version, protocol::PROTOCOL_VERSION, "request version");
        let cmd = Command::from_u8(request[6]).expect("known command");
        let hash_type = HashType::from_u8(request[7]).expect("known hash type");
        let seq = u32::from_le_bytes(request[8..12].try_into().unwrap());
        let count = u32::from_le_bytes(request[12..16].try_into().unwrap());

        let stated = u32::from_le_bytes(request[request.len() - 4..].try_into().unwrap());
        let computed = protocol::crc32(&request[..request.len() - 4]);
        assert_eq!(stated, computed, "request checksum");

        match cmd {
            Command::Crack => {
                assert_eq!(hash_type, HashType::Md5, "this device only does MD5");
                let payload = &request[REQUEST_HEADER_LEN..request.len() - 4];
                assert_eq!(payload.len() % SLOT_LEN, 0, "payload is whole slots");
                assert_eq!(
                    count as usize * SLOT_LEN,
                    payload.len(),
                    "count agrees with the payload length"
                );
                assert!(
                    payload.len() <= MAX_PAYLOAD_LEN,
                    "payload within the advertised limit"
                );

                let mut mask = 0u32;
                for i in 0..count as usize {
                    let slot = &payload[i * SLOT_LEN..(i + 1) * SLOT_LEN];
                    if md5::compute(slot).0 == self.target {
                        mask |= 1 << i;
                    }
                }

                // ShiftedMask keeps the count of matches but puts each one in the
                // wrong position, which is what a device with an off by one index
                // bug looks like from the host.
                if mode == Misbehaviour::ShiftedMask && mask != 0 {
                    mask = (mask << 1) | (mask >> 31);
                }

                protocol::build_response(Command::Crack, hash_type, seq, mask)
            }
            Command::Bench => {
                let n = if mode == Misbehaviour::WrongIterationCount {
                    count + 1
                } else {
                    count
                };
                protocol::build_response(Command::Bench, hash_type, seq, n)
            }
            Command::Reset => protocol::build_response(Command::Reset, hash_type, seq, 0),
            other => panic!("the simulated device does not implement {other:?}"),
        }
    }
}

impl Transport for SimulatedDevice {
    fn submit(&mut self, request: &[u8]) -> Result<usize, FpgaError> {
        self.log.lock().unwrap().requests.push(request.to_vec());
        let reply = self.handle(request);
        if !reply.is_empty() {
            self.replies.push(reply);
        }
        Ok(request.len())
    }

    fn poll_completion(&mut self) -> Result<Option<Vec<u8>>, FpgaError> {
        if self.replies.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.replies.remove(0)))
    }

    fn name(&self) -> &str {
        "simulated"
    }
}

/// Applies the post processing the device's own reply would need, so the mode is
/// a property of the transport rather than of each command handler.
fn corrupt(reply: Vec<u8>, mode: Misbehaviour) -> Vec<u8> {
    match mode {
        Misbehaviour::BadCrc => {
            let mut r = reply;
            let last = r.len() - 1;
            r[last] ^= 0x01;
            r
        }
        Misbehaviour::WrongSequence => {
            let mut r = reply;
            // Rewrite the sequence and recompute the checksum, so the frame is
            // well formed and only the sequence is wrong. A test that only
            // corrupted the checksum would pass even with no sequence checking.
            let seq = u32::from_le_bytes(r[8..12].try_into().unwrap()).wrapping_add(1000);
            r[8..12].copy_from_slice(&seq.to_le_bytes());
            let crc = protocol::crc32(&r[..RESPONSE_LEN - 4]);
            r[RESPONSE_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
            r
        }
        Misbehaviour::WrongVersion => {
            let mut r = reply;
            r[4..6].copy_from_slice(&(protocol::PROTOCOL_VERSION + 7).to_le_bytes());
            let crc = protocol::crc32(&r[..RESPONSE_LEN - 4]);
            r[RESPONSE_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
            r
        }
        _ => reply,
    }
}

/// Builds a batch of `n` slots where slot `i` holds `candidate_i`.
fn slots_for(candidates: &[&str]) -> Vec<u8> {
    let mut buf = vec![0u8; candidates.len() * SLOT_LEN];
    for (i, c) in candidates.iter().enumerate() {
        buf[i * SLOT_LEN..i * SLOT_LEN + c.len()].copy_from_slice(c.as_bytes());
    }
    buf
}

#[test]
fn a_match_is_attributed_to_the_slot_that_produced_it() {
    // The same candidate appears at slot 7 and slot 33, straddling the boundary
    // between the first 32 slot request and the second. Both must be reported.
    //
    // A single target cannot cover both, because only one digest is being looked
    // for. Repeating the candidate is what makes two independent positions match,
    // which is what tests that the second request's results land on the second
    // request's slots rather than being folded into the first.
    let mut refs: Vec<String> = (0..40).map(|i| format!("candidate-{i:02}")).collect();
    refs[7] = "needle".to_string();
    refs[33] = "needle".to_string();
    let borrowed: Vec<&str> = refs.iter().map(|s| s.as_str()).collect();
    let slots = slots_for(&borrowed);

    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(slot_digest(&slots, 7), log.clone());
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 2)]);

    let results = sched.crack_batch(HashType::Md5, &slots).expect("batch runs");

    assert_eq!(results.len(), 40, "one result per slot");
    assert!(results[7], "slot 7 holds the target");
    assert!(results[33], "slot 33 holds the same target, in the second request");
    assert_eq!(
        results.iter().filter(|r| **r).count(),
        2,
        "exactly two matches: {results:?}"
    );
}

#[test]
fn every_slot_is_sent_exactly_once() {
    let candidates: Vec<String> = (0..100).map(|i| format!("c{i:03}")).collect();
    let refs: Vec<&str> = candidates.iter().map(|s| s.as_str()).collect();
    let slots = slots_for(&refs);

    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new([0u8; 16], log.clone());
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    let results = sched.crack_batch(HashType::Md5, &slots).expect("batch runs");
    assert_eq!(results.len(), 100);
    assert!(!results.iter().any(|r| *r), "no candidate is the target");

    // 100 slots at 32 per request is four requests: 32, 32, 32, 4.
    let seen = log.lock().unwrap().requests.clone();
    assert_eq!(seen.len(), 4, "one request per 32 slot group");
    let mut total = 0usize;
    for (i, r) in seen.iter().enumerate() {
        let count = u32::from_le_bytes(r[12..16].try_into().unwrap()) as usize;
        total += count;
        assert!(count <= 32, "request {i} carries {count} slots, over the mask width");
    }
    assert_eq!(total, 100, "no slot sent twice, none skipped");
}

#[test]
fn a_corrupt_reply_is_rejected_rather_than_believed() {
    match batch_with_mode(Misbehaviour::BadCrc) {
        Err(FpgaError::CrcMismatch { stated, computed }) => assert_ne!(stated, computed),
        other => panic!("expected a checksum error, got {other:?}"),
    }
}

#[test]
fn a_reply_for_another_request_is_rejected() {
    match batch_with_mode(Misbehaviour::WrongSequence) {
        Err(FpgaError::InvalidPacket(msg)) => {
            assert!(msg.contains("sequence"), "message names the sequence: {msg}");
        }
        other => panic!("expected a sequence mismatch, got {other:?}"),
    }
}

#[test]
fn an_unknown_protocol_version_is_rejected() {
    match batch_with_mode(Misbehaviour::WrongVersion) {
        Err(FpgaError::VersionMismatch { got, expected }) => {
            assert_eq!(got, protocol::PROTOCOL_VERSION + 7);
            assert_eq!(expected, protocol::PROTOCOL_VERSION);
        }
        other => panic!("expected a version mismatch, got {other:?}"),
    }
}

#[test]
fn a_device_that_never_answers_is_a_timeout_not_a_success() {
    match batch_with_mode(Misbehaviour::Silent) {
        Err(FpgaError::Timeout) => {}
        other => panic!(
            "a silent device must not be read as zero matches, got {other:?}"
        ),
    }
}

#[test]
fn matches_reported_in_the_wrong_positions_are_still_wrong() {
    // The device reports the right number of matches in the wrong bits. The
    // scheduler has no way to know, so this test documents that the bit position
    // carries the meaning: shifting the mask shifts the answer.
    let candidates = vec!["alpha", "target-here", "gamma"];
    let slots = slots_for(&candidates);

    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(slot_digest(&slots, 1), log);
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    let honest = sched.crack_batch(HashType::Md5, &slots).expect("batch runs");
    assert_eq!(honest, vec![false, true, false], "the honest answer");

    let log2 = Arc::new(Mutex::new(Log::default()));
    let mut device2 = SimulatedDevice::new(slot_digest(&slots, 1), log2);
    device2.misbehaviour = Misbehaviour::ShiftedMask;
    let mut sched2 = FpgaScheduler::new(Box::new(device2), &[(HashType::Md5, 1)]);
    let shifted = sched2.crack_batch(HashType::Md5, &slots).expect("batch runs");
    assert_eq!(
        shifted,
        vec![false, false, true],
        "a shifted mask credits the neighbouring slot, which is why the position \
         must be the wire contract"
    );
}

#[test]
fn a_batch_is_refused_when_the_image_has_no_core_for_it() {
    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(md5::compute(b"absent").0, log);
    // The image has only MD5 cores.
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    let slots = slots_for(&["only"]);
    match sched.crack_batch(HashType::Ntlm, &slots) {
        Err(FpgaError::UnknownCore(msg)) => assert!(msg.contains("Ntlm"), "names the hash: {msg}"),
        other => panic!("expected UnknownCore, got {other:?}"),
    }
}

#[test]
fn a_buffer_that_is_not_whole_slots_is_refused_before_anything_is_sent() {
    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(md5::compute(b"absent").0, log.clone());
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    let odd = vec![0u8; SLOT_LEN + 1];
    assert!(sched.crack_batch(HashType::Md5, &odd).is_err());
    assert!(
        log.lock().unwrap().requests.is_empty(),
        "a malformed batch must not reach the device"
    );
}

#[test]
fn an_empty_batch_is_a_no_op() {
    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(md5::compute(b"absent").0, log.clone());
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    assert_eq!(sched.crack_batch(HashType::Md5, &[]).unwrap(), Vec::<bool>::new());
    assert!(log.lock().unwrap().requests.is_empty());
}

#[test]
fn bench_rejects_a_device_that_reports_a_different_iteration_count() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut device = SimulatedDevice::new(md5::compute(b"absent").0, log);
    device.misbehaviour = Misbehaviour::WrongIterationCount;
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    match sched.bench(HashType::Md5, 1000) {
        Err(FpgaError::InvalidPacket(msg)) => {
            assert!(msg.contains("iterations"), "message names the count: {msg}");
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn bench_reports_no_rate_when_the_device_sends_no_rate() {
    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(md5::compute(b"absent").0, log);
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    let r = sched.bench(HashType::Md5, 1000).expect("bench runs");
    assert_eq!(r.iterations, 1000);
    assert!(
        r.device_rate.is_none(),
        "no rate field exists in protocol version {}, so none is reported",
        protocol::PROTOCOL_VERSION
    );
    let text = r.to_string();
    assert!(
        text.contains("not reported"),
        "display must say unknown rather than print a number: {text}"
    );
    assert!(!text.contains("H/s"), "no rate was printed: {text}");
}

#[test]
fn reset_waits_for_a_confirmed_reply() {
    let log = Arc::new(Mutex::new(Log::default()));
    let device = SimulatedDevice::new(md5::compute(b"absent").0, log.clone());
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    sched.reset().expect("reset confirmed");

    let seen = log.lock().unwrap().requests.clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0][6], Command::Reset as u8);
    assert_eq!(
        HashType::from_u8(seen[0][7]),
        Some(HashType::Any),
        "reset names no hash type because it acts on every core"
    );
}

#[test]
fn reset_fails_loudly_when_the_device_is_silent() {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut device = SimulatedDevice::new(md5::compute(b"absent").0, log);
    device.misbehaviour = Misbehaviour::Silent;
    let mut sched = FpgaScheduler::new(Box::new(device), &[(HashType::Md5, 1)]);

    // The old scheduler returned Ok here without reading a reply, so a caller
    // would proceed to submit work against cores that were never reset.
    assert!(matches!(sched.reset(), Err(FpgaError::Timeout)));
}

#[test]
fn the_simulated_device_agrees_with_a_known_md5_vector() {
    // Guards the oracle. If md5::compute were wrong, every other test in this
    // file would be measuring a fiction.
    assert_eq!(
        hex::encode(md5::compute(b"abc").0),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        hex::encode(md5::compute(b"").0),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
}

/// The digest a device must produce for slot `i`.
///
/// The whole 64 byte slot is hashed, padding included. The host pre-pads each
/// candidate to a single block and the core compresses exactly one block, so the
/// digest covers the padding bytes too. Computing the target from the bare
/// password instead would give a different value, which is why every test here
/// derives its target through this function rather than calling `md5::compute` on
/// the password text.
fn slot_digest(slots: &[u8], index: usize) -> [u8; 16] {
    md5::compute(&slots[index * SLOT_LEN..(index + 1) * SLOT_LEN]).0
}

/// Pins the padding convention.
///
/// If the host and the device disagree about whether the 64 byte slot is hashed
/// whole, every match silently disappears and the tool reports no cracks found
/// while working perfectly. This asserts the convention explicitly so a change to
/// it fails loudly.
#[test]
fn the_device_hashes_the_whole_padded_slot() {
    let slots = slots_for(&["candidate-07"]);
    let padded = &slots[0..SLOT_LEN];
    assert_eq!(&padded[12..], &[0u8; 52], "the slot is zero padded to 64 bytes");
    assert_ne!(
        slot_digest(&slots, 0),
        md5::compute(b"candidate-07").0,
        "the padded slot must digest differently from the bare password, which is \
         the whole reason the target has to be derived from the slot"
    );
}
///
/// The transport is owned by the scheduler behind a trait object with no
/// accessor, so a misbehaving device has to be installed by constructing the
/// scheduler around it. Each caller therefore gets its own scheduler rather than
/// sharing one.
fn batch_with_mode(mode: Misbehaviour) -> Result<Vec<bool>, FpgaError> {
    let log = Arc::new(Mutex::new(Log::default()));
    let inner = SimulatedDevice::new(md5::compute(b"only").0, log.clone());
    let transport = WrappingDevice {
        inner,
        mode,
        log,
    };
    let mut sched = FpgaScheduler::new(Box::new(transport), &[(HashType::Md5, 1)]);
    sched.crack_batch(HashType::Md5, &slots_for(&["only"]))
}

/// Wraps the real simulated device and damages its replies.
struct WrappingDevice {
    inner: SimulatedDevice,
    mode: Misbehaviour,
    log: Arc<Mutex<Log>>,
}

impl Transport for WrappingDevice {
    fn submit(&mut self, request: &[u8]) -> Result<usize, FpgaError> {
        self.log.lock().unwrap().requests.push(request.to_vec());

        // Silent means the device produces no frame at all. Handled here rather
        // than by pushing an empty one: an empty frame is a different condition,
        // and it parses as a length error rather than as a timeout.
        if self.mode == Misbehaviour::Silent {
            return Ok(request.len());
        }

        let reply = self.inner.handle(request);
        if !reply.is_empty() {
            self.inner.replies.push(corrupt(reply, self.mode));
        }
        Ok(request.len())
    }

    fn poll_completion(&mut self) -> Result<Option<Vec<u8>>, FpgaError> {
        if self.inner.replies.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.inner.replies.remove(0)))
    }

    fn name(&self) -> &str {
        "wrapping"
    }
}