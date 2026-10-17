//! Framing: how a [`Message`](crate::protocol::Message) becomes bytes.
//!
//! # What this replaces
//!
//! The protocol used to be a 4 byte big endian length followed by
//! `serde_json::to_vec` of the message. Three things were wrong with that.
//!
//! 1. **No version.** A master and a worker from different builds would send
//!    JSON that happened to parse into the wrong variant, or fail to parse, with
//!    no way for either side to say so.
//! 2. **No integrity check.** A truncated frame is a JSON syntax error; a
//!    corrupted one is a JSON syntax error somewhere else. Neither is
//!    distinguishable from a peer sending rubbish, and neither can be reported
//!    as what it is.
//! 3. **Cost.** JSON for a `Ping` is 6 bytes where the whole frame could be 16
//!    with a code and a CRC, and for a `Result` carrying a hundred cracked
//!    entries it is several times the binary form. This engine sends a
//!    `Result` per chunk and a `Worklist` of arbitrary size, so the wire cost is
//!    not a rounding error.
//!
//! # The frame
//!
//! All integers little endian.
//!
//! ```text
//! offset  size  field
//!      0     4  magic            "PWC1"
//!      4     2  framing version  u16
//!      6     2  code             u16, see `Code`
//!      8     4  payload length   u32, must be <= the negotiated limit
//!     12     4  payload CRC-32   u32, IEEE, over the payload only
//!     16   len  payload          bincode of the whole `Message`
//! ```
//!
//! # Why the code and the payload can disagree
//!
//! The code is redundant with the variant inside the payload, and that is the
//! point: it is redundancy that is checked. `encode` derives the code from the
//! variant, `decode` refuses a frame whose header code does not match the
//! variant the payload actually decodes to
//! ([`ProtoError::CodeMismatch`]). A frame that claims to be a `Ping` and
//! decodes to a `Shutdown` is a protocol violation and ends the connection
//! rather than being executed.
//!
//! The other direction is not checkable, and does not need to be: the master
//! only ever executes a `Result` from a connection that passed admission, and
//! admission is not a function of the header.
//!
//! # Sizes
//!
//! `MAX_FRAME` is enforced twice, on purpose. The header length field is
//! compared against the limit *before* a buffer is allocated, so a peer cannot
//! make the process reserve memory by announcing it. The deserialiser then runs
//! with a compile time byte budget, so a payload that fits inside the frame
//! limit still cannot drive an unbounded read inside `bincode`. The const must
//! be at least the runtime limit; [`checked_limit`] is what enforces the
//! relationship and every entry point goes through it.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::Message;

/// Identifies a well formed stream.
///
/// A peer that opens this port and sends something else gets this back instead
/// of an unbounded attempt to interpret the bytes, which is what pointing a
/// worker at an SSH port or a web server used to produce.
pub const MAGIC: [u8; 4] = *b"PWC1";

/// Layout version of the header above.
///
/// Bumped when the header changes. Separate from
/// [`SCHEMA_VERSION`](crate::protocol::SCHEMA_VERSION), which guards the
/// meaning of the payload.
pub const FRAMING_VERSION: u16 = 1;

/// Bytes before the payload.
pub const HEADER_LEN: usize = 16;

/// Default largest accepted or produced frame.
///
/// Eight mebibytes is generous for every frame this protocol sends except a
/// `Wordlist`, and a worker that has not received a `Wordlist` refuses the chunk
/// that references it rather than guessing.
pub const DEFAULT_MAX_FRAME: usize = 8 * 1024 * 1024;

/// Byte budget handed to the deserialiser.
///
/// Compile time because `bincode`'s limit is a const generic. Set equal to
/// [`DEFAULT_MAX_FRAME`]; a runtime limit below it is enforced by the frame
/// length check before this value matters.
pub const CODEC_BYTE_LIMIT: usize = DEFAULT_MAX_FRAME;

/// The message kind, as it appears in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum Code {
    Ping = 1,
    Pong = 2,
    Challenge = 3,
    Authenticate = 4,
    Handshake = 5,
    Heartbeat = 6,
    HeartbeatAck = 7,
    WorkProgress = 8,
    AssignWork = 9,
    Wordlist = 10,
    Shutdown = 11,
    Error = 12,
    Result = 13,
}

impl Code {
    /// The numeric value, for the header and for error messages.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// A short name, for logs that should not need the whole enum.
    pub fn name(self) -> &'static str {
        match self {
            Code::Ping => "Ping",
            Code::Pong => "Pong",
            Code::Challenge => "Challenge",
            Code::Authenticate => "Authenticate",
            Code::Handshake => "Handshake",
            Code::Heartbeat => "Heartbeat",
            Code::HeartbeatAck => "HeartbeatAck",
            Code::WorkProgress => "WorkProgress",
            Code::AssignWork => "AssignWork",
            Code::Wordlist => "Wordlist",
            Code::Shutdown => "Shutdown",
            Code::Error => "Error",
            Code::Result => "Result",
        }
    }
}

/// Why a frame could not be read, written, or interpreted.
///
/// Every variant ends a connection. There is no recoverable case: a stream whose
/// framing cannot be trusted cannot be resynchronised, because the length field
/// is the only thing that says where the next frame starts and it is the thing
/// that is wrong.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtoError {
    /// The stream did not start with [`MAGIC`].
    BadMagic { got: [u8; 4] },
    /// The peer's framing version is not this one.
    UnsupportedFraming { got: u16, supported: u16 },
    /// The peer's message schema version is not this one.
    SchemaMismatch {
        peer: u16,
        supported: u16,
    },
    /// The header named a code this build does not know.
    UnknownCode(u16),
    /// The announced payload length exceeds the limit.
    FrameTooLarge { got: u64, limit: usize },
    /// The stream ended part way through a frame.
    Truncated { field: &'static str, expected: usize, got: usize },
    /// The payload did not match its CRC.
    CrcMismatch { expected: u32, got: u32 },
    /// The header code and the decoded variant disagree.
    CodeMismatch { header: u16, payload: &'static str },
    /// The payload did not deserialise.
    Decode(String),
    /// The message could not be serialised.
    Encode(String),
    /// The underlying stream failed.
    Io(String),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::BadMagic { got } => write!(
                f,
                "not a pwdcrack cluster stream: magic {:02x?} is not {:02x?}",
                got, MAGIC
            ),
            ProtoError::UnsupportedFraming { got, supported } => write!(
                f,
                "framing version {got} is not supported, this build speaks {supported}"
            ),
            ProtoError::SchemaMismatch { peer, supported } => write!(
                f,
                "protocol schema version {peer} is not supported, this build speaks {supported}"
            ),
            ProtoError::UnknownCode(c) => {
                write!(f, "unknown message code {c}")
            }
            ProtoError::FrameTooLarge { got, limit } => write!(
                f,
                "frame of {got} bytes exceeds the {limit} byte limit, refused before allocating"
            ),
            ProtoError::Truncated {
                field,
                expected,
                got,
            } => write!(
                f,
                "connection closed part way through the {field}: expected {expected} bytes, got {got}"
            ),
            ProtoError::CrcMismatch { expected, got } => write!(
                f,
                "frame payload is corrupt: header says CRC {expected:08x}, computed {got:08x}"
            ),
            ProtoError::CodeMismatch { header, payload } => write!(
                f,
                "frame header says code {header} but the payload decoded as {payload}"
            ),
            ProtoError::Decode(m) => write!(f, "payload is not a valid message: {m}"),
            ProtoError::Encode(m) => write!(f, "message could not be serialised: {m}"),
            ProtoError::Io(m) => write!(f, "stream error: {m}"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<std::io::Error> for ProtoError {
    fn from(e: std::io::Error) -> Self {
        ProtoError::Io(e.to_string())
    }
}

/// Lets `?` carry a protocol failure into the `Result<(), String>` the connection
/// handlers already return, so a framing failure and a business logic failure
/// reach the same log line.
impl From<ProtoError> for String {
    fn from(e: ProtoError) -> String {
        e.to_string()
    }
}

/// The header's view of a message: which kind it is, independent of its payload.
pub fn code_of(msg: &Message) -> Code {
    match msg {
        Message::Ping => Code::Ping,
        Message::Pong => Code::Pong,
        Message::Challenge { .. } => Code::Challenge,
        Message::Authenticate { .. } => Code::Authenticate,
        Message::Handshake { .. } => Code::Handshake,
        Message::Heartbeat { .. } => Code::Heartbeat,
        Message::HeartbeatAck { .. } => Code::HeartbeatAck,
        Message::WorkProgress { .. } => Code::WorkProgress,
        Message::AssignWork { .. } => Code::AssignWork,
        Message::Wordlist { .. } => Code::Wordlist,
        Message::Shutdown { .. } => Code::Shutdown,
        Message::Error { .. } => Code::Error,
        Message::Result { .. } => Code::Result,
    }
}

fn code_from_u16(v: u16) -> Result<Code, ProtoError> {
    Ok(match v {
        1 => Code::Ping,
        2 => Code::Pong,
        3 => Code::Challenge,
        4 => Code::Authenticate,
        5 => Code::Handshake,
        6 => Code::Heartbeat,
        7 => Code::HeartbeatAck,
        8 => Code::WorkProgress,
        9 => Code::AssignWork,
        10 => Code::Wordlist,
        11 => Code::Shutdown,
        12 => Code::Error,
        13 => Code::Result,
        other => return Err(ProtoError::UnknownCode(other)),
    })
}

/// The deserialiser configuration, with the compile time byte budget applied.
fn config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<CODEC_BYTE_LIMIT>()
}

/// Clamps a requested limit into the range the deserialiser can honour.
///
/// Returns the limit to actually use and logs when it had to clamp, because a
/// limit above [`CODEC_BYTE_LIMIT`] would otherwise be silently a lower one.
pub fn checked_limit(limit: usize) -> usize {
    if limit == 0 || limit > CODEC_BYTE_LIMIT {
        log::warn!(
            "cluster frame limit {limit} is unusable, using {CODEC_BYTE_LIMIT} instead"
        );
        return CODEC_BYTE_LIMIT;
    }
    limit
}

/// Serialises a message into a complete frame.
///
/// Fails rather than truncating when the frame would exceed `limit`. Truncating
/// would produce a frame that the peer decodes as a different, shorter message,
/// which is the failure mode this codec exists to remove.
pub fn encode_frame(msg: &Message, limit: usize) -> Result<Vec<u8>, ProtoError> {
    let limit = checked_limit(limit);
    let payload = bincode::serde::encode_to_vec(msg, config())
        .map_err(|e| ProtoError::Encode(e.to_string()))?;
    if payload.len() > limit {
        return Err(ProtoError::FrameTooLarge {
            got: payload.len() as u64,
            limit,
        });
    }

    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FRAMING_VERSION.to_le_bytes());
    out.extend_from_slice(&code_of(msg).as_u16().to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Parses one complete frame, header included.
///
/// The length field is compared against `limit` before the payload slice is
/// taken, so a 4 gigabyte length prefix costs nothing.
pub fn decode_frame(bytes: &[u8], limit: usize) -> Result<Message, ProtoError> {
    let limit = checked_limit(limit);
    let (code, payload) = decode_payload(bytes, limit)?;
    let cfg = config();
    let (msg, _consumed): (Message, usize) = bincode::serde::decode_from_slice(payload, cfg)
        .map_err(|e| ProtoError::Decode(e.to_string()))?;

    // The redundancy is checked, not trusted. See the module note.
    if code_of(&msg).as_u16() != code.as_u16() {
        return Err(ProtoError::CodeMismatch {
            header: code.as_u16(),
            payload: code_of(&msg).name(),
        });
    }
    Ok(msg)
}

/// Validates the header and returns the code plus the payload slice.
fn decode_payload<'a>(bytes: &'a [u8], limit: usize) -> Result<(Code, &'a [u8]), ProtoError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProtoError::Truncated {
            field: "header",
            expected: HEADER_LEN,
            got: bytes.len(),
        });
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[0..4]);
    if magic != MAGIC {
        return Err(ProtoError::BadMagic { got: magic });
    }
    let framing = u16::from_le_bytes([bytes[4], bytes[5]]);
    if framing != FRAMING_VERSION {
        return Err(ProtoError::UnsupportedFraming {
            got: framing,
            supported: FRAMING_VERSION,
        });
    }
    let code = code_from_u16(u16::from_le_bytes([bytes[6], bytes[7]]))?;
    let len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    if len > limit {
        return Err(ProtoError::FrameTooLarge {
            got: len as u64,
            limit,
        });
    }
    let want_crc = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let end = HEADER_LEN
        .checked_add(len)
        .ok_or(ProtoError::FrameTooLarge {
            got: u64::MAX,
            limit,
        })?;
    if bytes.len() < end {
        return Err(ProtoError::Truncated {
            field: "payload",
            expected: end,
            got: bytes.len(),
        });
    }
    let payload = &bytes[HEADER_LEN..end];
    let got_crc = crc32fast::hash(payload);
    if got_crc != want_crc {
        return Err(ProtoError::CrcMismatch {
            expected: want_crc,
            got: got_crc,
        });
    }
    Ok((code, payload))
}

/// Writes one message with the default frame limit.
pub async fn write_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<(), ProtoError> {
    write_msg_limited(writer, msg, DEFAULT_MAX_FRAME).await
}

/// Writes one message, refusing to produce a frame above `limit`.
pub async fn write_msg_limited<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
    limit: usize,
) -> Result<(), ProtoError> {
    let bytes = encode_frame(msg, limit)?;
    writer.write_all(&bytes).await?;
    // Every frame is flushed rather than left to the runtime. A worker that
    // finishes a batch and is then descheduled must not hold a result the master
    // is waiting on; the alternative costs a syscall per frame, which at a few
    // hundred frames per second is nothing.
    writer.flush().await?;
    Ok(())
}

/// Reads one message with the default frame limit.
///
/// `Ok(None)` means the peer closed cleanly at a frame boundary. Anything else
/// is a [`ProtoError`] and ends the connection.
pub async fn read_msg<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Message>, ProtoError> {
    read_msg_limited(reader, DEFAULT_MAX_FRAME).await
}

/// Reads one message, refusing to allocate for a frame above `limit`.
///
/// The first byte is read on its own so a clean close can be told apart from a
/// connection that died part way through a header. `read_exact` reports both as
/// `UnexpectedEof`, which would have turned a truncated frame into a normal
/// disconnect.
pub async fn read_msg_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Message>, ProtoError> {
    let limit = checked_limit(limit);

    let mut header = [0u8; HEADER_LEN];
    let first = read_first_byte(reader, &mut header[0]).await?;
    if first == 0 {
        return Ok(None);
    }

    // The magic is checked as soon as four bytes have arrived, not after all
    // sixteen. A peer that is not speaking this protocol gets refused in four
    // bytes rather than being made to fill out a header it does not have, which
    // is the difference between an immediate error and a timeout.
    if reader.read_exact(&mut header[1..4]).await.is_err() {
        return Err(ProtoError::Truncated {
            field: "magic",
            expected: 4,
            got: 1,
        });
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&header[0..4]);
    if magic != MAGIC {
        return Err(ProtoError::BadMagic { got: magic });
    }

    if reader.read_exact(&mut header[4..]).await.is_err() {
        return Err(ProtoError::Truncated {
            field: "header",
            expected: HEADER_LEN,
            got: 4,
        });
    }

    let len = u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if len > limit {
        // Refused here, before the `vec![0u8; len]` on the next line. That
        // allocation is the whole attack surface of a length prefixed protocol.
        return Err(ProtoError::FrameTooLarge { got: len as u64, limit });
    }

    let mut buf = vec![0u8; HEADER_LEN + len];
    buf[..HEADER_LEN].copy_from_slice(&header);
    if len > 0 && reader.read_exact(&mut buf[HEADER_LEN..]).await.is_err() {
        return Err(ProtoError::Truncated {
            field: "payload",
            expected: HEADER_LEN + len,
            got: HEADER_LEN,
        });
    }

    match decode_frame(&buf, limit) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(e),
    }
}

/// Reads one byte, reporting how many arrived. Returns `0` only at a clean EOF.
async fn read_first_byte<R: AsyncRead + Unpin>(
    reader: &mut R,
    into: &mut u8,
) -> Result<usize, ProtoError> {
    let mut buf = [0u8; 1];
    let mut got = 0;
    while got < 1 {
        match reader.read(&mut buf).await? {
            0 => break,
            n => {
                *into = buf[0];
                got += n;
            }
        }
    }
    Ok(got)
}

/// A byte stream that is either plain TCP or a TLS session.
///
/// Exists so the message loop in `master.rs` and `worker.rs` is written once
/// rather than twice. Before this, adding TLS would have meant a generic
/// function in both loops plus a parallel path through the admission gate and
/// the reconnect logic, and the four paths would drift.
#[derive(Debug)]
pub enum Link {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>),
    ClientTls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl Link {
    /// True when this connection is encrypted.
    pub fn is_tls(&self) -> bool {
        !matches!(self, Link::Plain(_))
    }

    /// A description for a log line: the peer's certificate fingerprint when
    /// there is one, the socket address otherwise.
    pub fn peer_label(&self) -> String {
        match self {
            Link::Plain(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown>".to_string()),
            Link::Tls(s) => {
                let (tcp, conn) = s.get_ref();
                let addr = tcp
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "<unknown>".to_string());
                // A server connection has no peer certificate unless client
                // authentication is on, which it is not, so the field is only
                // printed when there is something in it.
                match crate::tls::peer_fingerprint(conn) {
                    Some(fp) => format!("tls:{addr} cert={}", &fp[..16]),
                    None => format!("tls:{addr}"),
                }
            }
            Link::ClientTls(s) => {
                let (tcp, _) = s.get_ref();
                format!(
                    "tls:{}",
                    tcp.peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "<unknown>".to_string())
                )
            }
        }
    }
}

impl tokio::io::AsyncRead for Link {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Link::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Link::ClientTls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Link {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Link::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Link::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Link::ClientTls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Plain(s) => Pin::new(s).poll_flush(cx),
            Link::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Link::ClientTls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Link::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Link::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Link::ClientTls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AttackType, Capabilities, CrackedEntry, TargetHash, WorkUnit};
    use crate::protocol::SCHEMA_VERSION;

    fn sample() -> Message {
        Message::AssignWork {
            worker_id: 4,
            batch_id: 91,
            work: WorkUnit {
                job_id: 1,
                attack_type: AttackType::BruteForce {
                    mask: "?l?l?d".into(),
                },
                targets: vec![TargetHash::new("NTLM", "8846F7EAEE8FB117AD06BDD830B7586C")],
                keyspace_start: 1_000,
                keyspace_end: 2_000,
                keyspace_total: 4_000,
            },
        }
    }

    #[test]
    fn a_frame_round_trips() {
        let m = sample();
        let bytes = encode_frame(&m, DEFAULT_MAX_FRAME).unwrap();
        assert_eq!(&bytes[0..4], &MAGIC);
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            FRAMING_VERSION
        );
        assert_eq!(decode_frame(&bytes, DEFAULT_MAX_FRAME).unwrap(), m);
    }

    #[test]
    fn the_header_carries_the_message_code() {
        let bytes = encode_frame(&Message::Ping, DEFAULT_MAX_FRAME).unwrap();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), Code::Ping.as_u16());
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            code_of(&Message::Ping).as_u16()
        );
    }

    /// A binary frame for the common case is smaller than the JSON one it
    /// replaced. Recorded as a test so a future switch back to a text format
    /// cannot happen quietly.
    #[test]
    fn the_binary_form_is_smaller_than_json() {
        let m = Message::Handshake {
            protocol_version: SCHEMA_VERSION,
            node_name: "node-1".into(),
            tier: "x86_64".into(),
            caps: Capabilities {
                simd: "avx2".into(),
                gpu: false,
                fpga: false,
                max_threads: 8,
                ram_mb: 16384,
            },
        };
        let bin = encode_frame(&m, DEFAULT_MAX_FRAME).unwrap();
        let json = serde_json::to_vec(&serde_json::json!({
            "Handshake": {
                "node_name": "node-1",
                "tier": "x86_64",
                "caps": {
                    "simd": "avx2", "gpu": false, "fpga": false,
                    "max_threads": 8, "ram_mb": 16384
                }
            }
        }))
        .unwrap();
        assert!(
            bin.len() < json.len(),
            "binary {} was not smaller than json {}",
            bin.len(),
            json.len()
        );
    }

    #[test]
    fn a_bad_magic_is_reported_as_such() {
        let mut bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::BadMagic { .. })
        ));
    }

    #[test]
    fn a_different_framing_version_is_refused() {
        let mut bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::UnsupportedFraming {
                got: 99,
                supported: FRAMING_VERSION
            })
        );
    }

    #[test]
    fn an_unknown_code_is_refused_rather_than_guessed() {
        let mut bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        bytes[6..8].copy_from_slice(&4242u16.to_le_bytes());
        assert_eq!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::UnknownCode(4242))
        );
    }

    #[test]
    fn a_flipped_payload_bit_is_caught_by_the_crc() {
        let mut bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::CrcMismatch { .. })
        ));
    }

    /// The check that makes the redundant header code worth its two bytes: a
    /// frame whose code lies about its payload is a violation, not a message.
    #[test]
    fn a_header_that_lies_about_the_payload_is_refused() {
        // A Ping frame whose payload, length and CRC all describe a Shutdown.
        // Every field is internally consistent except the code, so only the
        // cross-check between header and payload can catch it.
        let mut bytes = encode_frame(&Message::Ping, DEFAULT_MAX_FRAME).unwrap();
        let real = encode_frame(
            &Message::Shutdown {
                reason: "go away".into(),
            },
            DEFAULT_MAX_FRAME,
        )
        .unwrap();
        bytes.truncate(HEADER_LEN);
        bytes[8..12].copy_from_slice(&real[8..12]);
        bytes[12..16].copy_from_slice(&real[12..16]);
        bytes.extend_from_slice(&real[HEADER_LEN..]);
        assert!(matches!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::CodeMismatch { .. })
        ));
    }

    #[test]
    fn an_oversized_length_is_refused_before_any_allocation() {
        let mut bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_frame(&bytes, DEFAULT_MAX_FRAME),
            Err(ProtoError::FrameTooLarge {
                got: u32::MAX as u64,
                limit: DEFAULT_MAX_FRAME
            })
        );
    }

    #[test]
    fn a_short_header_is_truncation_not_a_bad_magic() {
        let bytes = encode_frame(&Message::Ping, DEFAULT_MAX_FRAME).unwrap();
        assert!(matches!(
            decode_frame(&bytes[..8], DEFAULT_MAX_FRAME),
            Err(ProtoError::Truncated { field: "header", .. })
        ));
    }

    #[test]
    fn a_short_payload_is_truncation() {
        let bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        assert!(matches!(
            decode_frame(&bytes[..bytes.len() - 3], DEFAULT_MAX_FRAME),
            Err(ProtoError::Truncated {
                field: "payload",
                ..
            })
        ));
    }

    #[test]
    fn a_frame_over_the_limit_is_not_encoded() {
        let big = Message::Result {
            node_name: "n".into(),
            batch_id: 1,
            cracked: (0..10_000)
                .map(|i| CrackedEntry {
                    hash: format!("{i:064x}"),
                    password: "x".repeat(64),
                    algorithm: "MD5".into(),
                })
                .collect(),
            solved: vec![],
        };
        assert!(matches!(
            encode_frame(&big, 1024),
            Err(ProtoError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn a_limit_above_the_const_is_clamped_rather_than_ignored() {
        assert_eq!(checked_limit(usize::MAX), CODEC_BYTE_LIMIT);
        assert_eq!(checked_limit(0), CODEC_BYTE_LIMIT);
        assert_eq!(checked_limit(4096), 4096);
    }

    #[tokio::test]
    async fn messages_round_trip_through_a_stream() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let msgs = vec![
            Message::Ping,
            sample(),
            Message::Result {
                node_name: "n1".into(),
                batch_id: 2,
                cracked: vec![CrackedEntry {
                    hash: "deadbeef".into(),
                    password: "hello".into(),
                    algorithm: "MD5".into(),
                }],
                solved: vec![TargetHash::new("MD5", "deadbeef")],
            },
        ];
        let (mut reader, writer) = tokio::io::split(client);
        let pump = {
            let msgs = msgs.clone();
            let mut writer = writer;
            tokio::spawn(async move {
                for m in &msgs {
                    let bytes = encode_frame(m, DEFAULT_MAX_FRAME).unwrap();
                    writer.write_all(&bytes).await.unwrap();
                }
            })
        };
        for m in &msgs {
            assert_eq!(read_msg(&mut server).await.unwrap(), Some(m.clone()));
        }
        drop(reader);
        pump.await.unwrap();
    }

    #[tokio::test]
    async fn a_clean_close_at_a_frame_boundary_is_not_an_error() {
        let (client, mut server) = tokio::io::duplex(1024);
        drop(client);
        assert_eq!(read_msg(&mut server).await.unwrap(), None);
    }

    /// A peer that vanishes mid frame is a truncation, not a disconnect. Reading
    /// it as a disconnect is what let a half written frame look like an idle
    /// worker.
    #[tokio::test]
    async fn a_close_part_way_through_a_frame_is_truncation() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        // Written below, then dropped to close the stream.
        let bytes = encode_frame(&sample(), DEFAULT_MAX_FRAME).unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, &bytes[..bytes.len() - 4])
            .await
            .unwrap();
        drop(client);
        assert!(matches!(
            read_msg(&mut server).await,
            Err(ProtoError::Truncated { .. })
        ));
    }

    #[tokio::test]
    async fn an_oversized_announcement_is_refused_without_allocating() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&FRAMING_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&Code::Result.as_u16().to_le_bytes());
        header[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        tokio::io::AsyncWriteExt::write_all(&mut client, &header)
            .await
            .unwrap();
        assert!(matches!(
            read_msg(&mut server).await,
            Err(ProtoError::FrameTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn garbage_on_the_port_is_refused_not_parsed() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::io::AsyncWriteExt::write_all(&mut client, b"{\"Ping\":null}")
            .await
            .unwrap();
        // Closed, so the reader has the whole thirteen bytes and does not wait
        // for the fifteen more the header claims. The point of the test is that
        // these bytes are rejected on sight, not that a partial read is.
        drop(client);
        assert!(matches!(
            read_msg(&mut server).await,
            Err(ProtoError::BadMagic { .. })
        ));
    }
}