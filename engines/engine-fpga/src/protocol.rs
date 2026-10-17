//! Host to FPGA wire protocol.
//!
//! # Layout
//!
//! Request, host to FPGA:
//!
//! ```text
//! offset  size  field
//!      0     4  magic       0x5043524B  "PCRK"
//!      4     2  version     little endian, see PROTOCOL_VERSION
//!      6     1  command
//!      7     1  hash type
//!      8     4  sequence id, little endian
//!     12     4  item count, little endian
//!     16     N  payload
//!      16+N   4  CRC-32 of bytes 0..16+N
//! ```
//!
//! Response, FPGA to host:
//!
//! ```text
//! offset  size  field
//!      0     4  magic       0x50435246  "PCRF"
//!      4     2  version
//!      6     1  command, echoed
//!      7     1  hash type, echoed
//!      8     4  sequence id, echoed
//!     12     4  matches found
//!     16     4  CRC-32 of bytes 0..16
//! ```
//!
//! # What was wrong before, and why it mattered
//!
//! Three defects, none of which a compiler or a smoke test would catch.
//!
//! **The CRC was never verified.** `parse_response` read the trailing CRC field
//! into the returned struct and never compared it against a computed value.
//! Corrupted data, a stale descriptor, or a bit flip in the payload all parsed
//! cleanly and reported a match count. The one check that exists to detect data
//! corruption was decorative.
//!
//! **There was no version field.** A host and an FPGA image built from different
//! revisions would exchange packets that both considered well formed. P8.3.01
//! asks for an explicit version; an unknown one is now rejected rather than
//! guessed at.
//!
//! **The host and the FPGA computed different CRCs.** `rtl/cores/crc_accelerator.sv`
//! implements CRC-32 as specified in IEEE 802.3, the reflected algorithm with
//! polynomial 0xEDB88320, an initial value of 0xFFFFFFFF and a final XOR of
//! 0xFFFFFFFF. Its own testbench asserts `CRC32("abc") == 0x352441c2`, which is
//! the standard value. The Rust `crc32` in this file started from 0 and omitted
//! the final XOR, giving `0xca6598d0` for the same input. Every packet would
//! have been rejected by the device, and nothing would have said why.
//!
//! `crc32` here is now the standard function, checked against `zlib.crc32` and
//! against the values in the RTL testbench.
//!
//! # No panics on untrusted input
//!
//! Every function here takes untrusted bytes and returns a `Result`. The previous
//! `build_crack_packet` used `assert!` for its length check, which turns a caller
//! passing an odd length into an abort of the whole process. Malformed input from
//! a device, or a programming error in the host, produces an error value.

use crate::error::{FpgaError, FpgaResult};

/// Request magic, "PCRK".
pub const MAGIC_HOST: u32 = 0x5043_524B;

/// Response magic, "PCRF".
pub const MAGIC_FPGA: u32 = 0x5043_5246;

/// Protocol revision understood by this build.
///
/// A peer presenting any other value is rejected. Incrementing this is a
/// breaking change and must come with a version check on the device side.
pub const PROTOCOL_VERSION: u16 = 1;

/// Bytes before the payload in a request.
pub const REQUEST_HEADER_LEN: usize = 16;

/// Bytes in a response, which carries no payload.
pub const RESPONSE_LEN: usize = 20;

/// Width of one candidate slot in the request payload.
///
/// A 64 byte slot holds a password of up to 55 bytes once MD5 padding is applied,
/// which is the largest single block digest.
pub const SLOT_LEN: usize = 64;

/// Largest payload accepted, as a guard against a corrupt length field causing a
/// huge allocation. 4 MiB is roughly 65536 candidates.
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Verify a batch of candidates against a target hash.
    Crack = 0x01,
    /// Measure a core's throughput.
    Bench = 0x02,
    /// Read core counters.
    Stats = 0x03,
    /// Reset the cores.
    Reset = 0x04,
}

impl Command {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Command::Crack),
            0x02 => Some(Command::Bench),
            0x03 => Some(Command::Stats),
            0x04 => Some(Command::Reset),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashType {
    /// Not applicable. Used by commands that act on every core at once, such as
    /// `Reset`, where naming a hash type would be a lie.
    Any = 0x00,
    Md5 = 0x01,
    Sha256 = 0x02,
    Ntlm = 0x03,
}

impl HashType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(HashType::Any),
            0x01 => Some(HashType::Md5),
            0x02 => Some(HashType::Sha256),
            0x03 => Some(HashType::Ntlm),
            _ => None,
        }
    }
}

/// Builds a request with the shared header and a CRC over everything before it.
///
/// One helper for every command. The previous code built `Crack`, `Bench` and
/// `Reset` packets by hand in three different shapes: `Bench` wrote the hash type
/// after the sequence number and had no version field, `Reset` had neither, and
/// neither matched the layout in this module's documentation. Three layouts on
/// one wire means a device can only be correct for one of them.
fn build_request(
    seq_id: u32,
    cmd: Command,
    hash_type: HashType,
    count: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet =
        Vec::with_capacity(REQUEST_HEADER_LEN + payload.len() + 4);
    packet.extend_from_slice(&MAGIC_HOST.to_le_bytes());
    packet.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    packet.push(cmd as u8);
    packet.push(hash_type as u8);
    packet.extend_from_slice(&seq_id.to_le_bytes());
    packet.extend_from_slice(&count.to_le_bytes());
    packet.extend_from_slice(payload);
    let crc = crc32(&packet);
    packet.extend_from_slice(&crc.to_le_bytes());
    packet
}

/// Builds a crack request.
///
/// `slots` must be a whole number of [`SLOT_LEN`] byte slots. An empty slice
/// produces an error rather than a zero length packet, because a device given
/// zero work has nothing meaningful to reply and the resulting ambiguity is
/// harder to diagnose than a rejected call.
pub fn build_crack_request(
    seq_id: u32,
    hash_type: HashType,
    slots: &[u8],
) -> FpgaResult<Vec<u8>> {
    if hash_type == HashType::Any {
        return Err(FpgaError::InvalidPacket(
            "crack request needs a concrete hash type".into(),
        ));
    }
    if slots.is_empty() {
        return Err(FpgaError::InvalidPacket(
            "crack request with no candidates".into(),
        ));
    }
    if slots.len() % SLOT_LEN != 0 {
        return Err(FpgaError::InvalidPacket(format!(
            "payload of {} bytes is not a multiple of the {SLOT_LEN} byte slot",
            slots.len()
        )));
    }
    if slots.len() > MAX_PAYLOAD_LEN {
        return Err(FpgaError::InvalidPacket(format!(
            "payload of {} bytes exceeds the {MAX_PAYLOAD_LEN} byte limit",
            slots.len()
        )));
    }

    let count = (slots.len() / SLOT_LEN) as u32;
    Ok(build_request(seq_id, Command::Crack, hash_type, count, slots))
}

/// Builds a benchmark request.
///
/// `iterations` travels in the count field, which is a u32, so a larger value is
/// rejected rather than silently truncated. Truncation here would report a
/// throughput derived from a different number of iterations than were run.
pub fn build_bench_request(
    seq_id: u32,
    hash_type: HashType,
    iterations: u64,
) -> FpgaResult<Vec<u8>> {
    if hash_type == HashType::Any {
        return Err(FpgaError::InvalidPacket(
            "bench request needs a concrete hash type".into(),
        ));
    }
    if iterations == 0 || iterations > u32::MAX as u64 {
        return Err(FpgaError::InvalidPacket(format!(
            "bench iteration count {iterations} is outside 1..={}",
            u32::MAX
        )));
    }
    Ok(build_request(
        seq_id,
        Command::Bench,
        hash_type,
        iterations as u32,
        &[],
    ))
}

/// Builds a reset request.
///
/// Carries [`HashType::Any`]: reset acts on every core, so naming one hash type
/// would misrepresent what the device is being asked to do.
pub fn build_reset_request(seq_id: u32) -> Vec<u8> {
    build_request(seq_id, Command::Reset, HashType::Any, 0, &[])
}

/// Builds a statistics request.
pub fn build_stats_request(seq_id: u32, hash_type: HashType) -> Vec<u8> {
    build_request(seq_id, Command::Stats, hash_type, 0, &[])
}

/// A decoded and verified response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    pub cmd: Command,
    pub hash_type: HashType,
    pub seq_id: u32,
    pub found: u32,
}

/// Parses a response, rejecting anything malformed.
///
/// Checks in order, each with its own error so the cause is never ambiguous:
/// length, magic, version, CRC, then the field values. The CRC is verified over
/// the bytes that precede it, which is the whole point of having it.
pub fn parse_response(data: &[u8]) -> FpgaResult<Response> {
    if data.len() < RESPONSE_LEN {
        return Err(FpgaError::InvalidPacket(format!(
            "response of {} bytes is shorter than the {RESPONSE_LEN} byte minimum",
            data.len()
        )));
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != MAGIC_FPGA {
        return Err(FpgaError::InvalidPacket(format!(
            "magic 0x{magic:08x} is not the response magic 0x{MAGIC_FPGA:08x}"
        )));
    }

    let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
    if version != PROTOCOL_VERSION {
        return Err(FpgaError::VersionMismatch {
            got: version,
            expected: PROTOCOL_VERSION,
        });
    }

    // The CRC covers everything before itself. Verified before any field is
    // trusted, because a value read out of a corrupt packet is not a value.
    let stated = u32::from_le_bytes(data[RESPONSE_LEN - 4..].try_into().unwrap());
    let computed = crc32(&data[..RESPONSE_LEN - 4]);
    if stated != computed {
        return Err(FpgaError::CrcMismatch {
            stated,
            computed,
        });
    }

    let cmd = Command::from_u8(data[6])
        .ok_or_else(|| FpgaError::InvalidPacket(format!("unknown command 0x{:02x}", data[6])))?;
    let hash_type = HashType::from_u8(data[7]).ok_or_else(|| {
        FpgaError::InvalidPacket(format!("unknown hash type 0x{:02x}", data[7]))
    })?;
    let seq_id = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let found = u32::from_le_bytes(data[12..16].try_into().unwrap());

    Ok(Response {
        cmd,
        hash_type,
        seq_id,
        found,
    })
}

/// Builds a response. Used by the device side and by the simulated transport in
/// the tests, so the tests exercise the same encoder the hardware must match.
pub fn build_response(
    cmd: Command,
    hash_type: HashType,
    seq_id: u32,
    found: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RESPONSE_LEN);
    buf.extend_from_slice(&MAGIC_FPGA.to_le_bytes());
    buf.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    buf.push(cmd as u8);
    buf.push(hash_type as u8);
    buf.extend_from_slice(&seq_id.to_le_bytes());
    buf.extend_from_slice(&found.to_le_bytes());
    let crc = crc32(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    buf
}

/// CRC-32 as specified in IEEE 802.3, the algorithm the RTL implements.
///
/// Reflected, polynomial 0xEDB88320, initial value 0xFFFFFFFF, final XOR
/// 0xFFFFFFFF. The previous version in this file started from 0 and omitted the
/// final XOR, which is a different function that happens to share a table; see
/// the module comment.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        // Eight table-free shifts. The table version is faster but the byte wise
        // form keeps the polynomial visible, which matters for a value that has
        // to agree with RTL written by someone else.
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors in `rtl/cores/tb_crc_accelerator.sv`.
    ///
    /// This is the test that matters most in this file. It ties the host to the
    /// device: if these two disagree, every packet is rejected by the FPGA and the
    /// symptom is a timeout with no explanation.
    #[test]
    fn crc32_matches_the_values_the_rtl_asserts() {
        assert_eq!(crc32(b""), 0x0000_0000, "RTL asserts CRC32(\"\") == 0");
        assert_eq!(crc32(b"abc"), 0x3524_41c2, "RTL asserts CRC32(\"abc\") == 0x352441c2");
    }

    #[test]
    fn crc32_matches_the_standard_reference() {
        // Values from zlib, which is the same algorithm.
        for (input, want) in [
            (&b""[..], 0x0000_0000u32),
            (&b"a"[..], 0xe8b7_be43),
            (&b"abc"[..], 0x3524_41c2),
            (&b"123456789"[..], 0xcbf4_3926),
            (&b"The quick brown fox jumps over the lazy dog"[..], 0x414f_a339),
        ] {
            assert_eq!(
                crc32(input),
                want,
                "CRC32 mismatch for {:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn crc32_detects_single_bit_flips() {
        let base = b"pwdcrack fpga payload";
        let base_crc = crc32(base);
        for bit in 0..(base.len() * 8) {
            let mut mutated = base.to_vec();
            mutated[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(
                crc32(&mutated),
                base_crc,
                "flipping bit {bit} went undetected"
            );
        }
    }

    fn sample_request(seq: u32) -> Vec<u8> {
        let slots = vec![0u8; SLOT_LEN * 4];
        build_crack_request(seq, HashType::Md5, &slots).expect("request builds")
    }

    #[test]
    fn round_trip_request_carries_the_fields() {
        let pkt = sample_request(0xDEAD_BEEF);
        assert_eq!(
            u32::from_le_bytes(pkt[0..4].try_into().unwrap()),
            MAGIC_HOST
        );
        assert_eq!(u16::from_le_bytes(pkt[4..6].try_into().unwrap()), PROTOCOL_VERSION);
        assert_eq!(pkt[6], Command::Crack as u8);
        assert_eq!(pkt[7], HashType::Md5 as u8);
        assert_eq!(
            u32::from_le_bytes(pkt[8..12].try_into().unwrap()),
            0xDEAD_BEEF
        );
        assert_eq!(
            u32::from_le_bytes(pkt[12..16].try_into().unwrap()),
            4,
            "item count"
        );
    }

    #[test]
    fn request_crc_covers_the_header_and_payload() {
        let pkt = sample_request(1);
        let stated = u32::from_le_bytes(pkt[pkt.len() - 4..].try_into().unwrap());
        assert_eq!(stated, crc32(&pkt[..pkt.len() - 4]));
    }

    #[test]
    fn response_round_trip() {
        let raw = build_response(Command::Crack, HashType::Ntlm, 99, 7);
        let r = parse_response(&raw).expect("valid response parses");
        assert_eq!(r.cmd, Command::Crack);
        assert_eq!(r.hash_type, HashType::Ntlm);
        assert_eq!(r.seq_id, 99);
        assert_eq!(r.found, 7);
    }

    /// The defect that motivated rewriting this file: the CRC was read but never
    /// checked, so a corrupt packet produced a confident wrong answer.
    #[test]
    fn corrupted_payload_is_rejected() {
        let mut raw = build_response(Command::Crack, HashType::Md5, 5, 1);
        // Flip a bit inside the found count.
        let idx = 13;
        raw[idx] ^= 0x01;
        match parse_response(&raw) {
            Err(FpgaError::CrcMismatch { .. }) => {}
            other => panic!("expected CrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_crc_field_is_rejected() {
        let mut raw = build_response(Command::Crack, HashType::Md5, 5, 1);
        let last = raw.len() - 1;
        raw[last] ^= 0x80;
        assert!(matches!(
            parse_response(&raw),
            Err(FpgaError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn every_bit_of_the_header_is_protected() {
        // Walk each header byte and confirm the CRC catches a flip there too.
        let base = build_response(Command::Stats, HashType::Sha256, 1, 0);
        for i in 0..(base.len() - 4) {
            let mut m = base.clone();
            m[i] ^= 0xFF;
            assert!(
                parse_response(&m).is_err(),
                "flipping byte {i} of the response went undetected"
            );
        }
    }

    #[test]
    fn unknown_version_is_rejected_rather_than_guessed() {
        let mut raw = build_response(Command::Crack, HashType::Md5, 1, 0);
        // Bump the version and recompute the CRC so only the version is wrong.
        raw[4..6].copy_from_slice(&(PROTOCOL_VERSION + 1).to_le_bytes());
        let crc = crc32(&raw[..RESPONSE_LEN - 4]);
        raw[RESPONSE_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

        match parse_response(&raw) {
            Err(FpgaError::VersionMismatch { got, expected }) => {
                assert_eq!(got, PROTOCOL_VERSION + 1);
                assert_eq!(expected, PROTOCOL_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut raw = build_response(Command::Crack, HashType::Md5, 1, 0);
        raw[0] ^= 0xFF;
        assert!(matches!(
            parse_response(&raw),
            Err(FpgaError::InvalidPacket(_))
        ));
    }

    #[test]
    fn short_input_does_not_panic() {
        for n in 0..RESPONSE_LEN {
            let data = vec![0u8; n];
            // The point is that this returns rather than indexing out of range.
            assert!(parse_response(&data).is_err(), "{n} bytes should not parse");
        }
    }

    #[test]
    fn unknown_command_and_hash_type_are_rejected() {
        let mut raw = build_response(Command::Crack, HashType::Md5, 1, 0);
        raw[6] = 0xEE;
        let crc = crc32(&raw[..RESPONSE_LEN - 4]);
        raw[RESPONSE_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_response(&raw),
            Err(FpgaError::InvalidPacket(_))
        ));

        let mut raw = build_response(Command::Crack, HashType::Md5, 1, 0);
        raw[7] = 0xEE;
        let crc = crc32(&raw[..RESPONSE_LEN - 4]);
        raw[RESPONSE_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_response(&raw),
            Err(FpgaError::InvalidPacket(_))
        ));
    }

    #[test]
    fn bad_payload_lengths_are_errors_not_panics() {
        // Empty.
        assert!(build_crack_request(1, HashType::Md5, &[]).is_err());
        // Not a whole number of slots.
        assert!(build_crack_request(1, HashType::Md5, &[0u8; 65]).is_err());
        // One byte short of two slots.
        assert!(build_crack_request(1, HashType::Md5, &[0u8; 127]).is_err());
        // Over the limit.
        assert!(build_crack_request(1, HashType::Md5, &vec![0u8; MAX_PAYLOAD_LEN + SLOT_LEN]).is_err());
        // Exactly one slot is fine.
        assert!(build_crack_request(1, HashType::Md5, &[0u8; SLOT_LEN]).is_ok());
    }

    #[test]
    fn a_large_but_legal_request_builds() {
        let slots = SLOT_LEN * 1024;
        let pkt = build_crack_request(7, HashType::Sha256, &vec![0u8; slots]).expect("builds");
        assert_eq!(pkt.len(), REQUEST_HEADER_LEN + slots + 4);
    }
}