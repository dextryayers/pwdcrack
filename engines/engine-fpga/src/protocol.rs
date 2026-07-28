//! Host-FPGA communication protocol
//!
//! Command format (host → FPGA):
//! [4B magic][1B cmd][4B seq_id][1B hash_type][4B count][N*B data][4B crc]
//!
//! Response format (FPGA → host):
//! [4B magic][1B cmd][4B seq_id][4B found][4B crc]

pub const MAGIC_HOST: u32 = 0x5043524B; // "PCRK"
pub const MAGIC_FPGA: u32 = 0x50435246; // "PCRF"

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Command {
    Crack  = 0x01,  // Verify passwords against hash
    Bench  = 0x02,  // Benchmark core
    Stats  = 0x03,  // Get core stats
    Reset  = 0x04,  // Reset cores
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum HashType {
    MD5    = 0x01,
    SHA256 = 0x02,
    NTLM   = 0x03,
}

/// Build a crack command packet
pub fn build_crack_packet(
    seq_id: u32,
    hash_type: HashType,
    passwords: &[u8],
) -> Vec<u8> {
    assert!(passwords.len() % 64 == 0, "passwords length must be a multiple of 64");
    let count = passwords.len() / 64;
    let mut packet = Vec::with_capacity(16 + passwords.len());

    packet.extend_from_slice(&MAGIC_HOST.to_le_bytes());
    packet.push(Command::Crack as u8);
    packet.extend_from_slice(&seq_id.to_le_bytes());
    packet.push(hash_type as u8);
    packet.extend_from_slice(&(count as u32).to_le_bytes());
    packet.extend_from_slice(passwords);
    let crc = crc32(&packet);
    packet.extend_from_slice(&crc.to_le_bytes());

    packet
}

/// Parse FPGA response
pub fn parse_response(data: &[u8]) -> Option<Response> {
    if data.len() < 17 { return None; }

    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic != MAGIC_FPGA { return None; }

    let cmd = data[4];
    let seq_id = u32::from_le_bytes(data[5..9].try_into().ok()?);
    let found = u32::from_le_bytes(data[9..13].try_into().ok()?);
    let crc = u32::from_le_bytes(data[13..17].try_into().ok()?);

    Some(Response { cmd, seq_id, found, crc })
}

#[derive(Debug)]
pub struct Response {
    pub cmd: u8,
    pub seq_id: u32,
    pub found: u32,
    pub crc: u32,
}

pub fn crc32(data: &[u8]) -> u32 {
    data.iter().fold(0u32, |acc, &b| {
        (acc >> 8) ^ CRC32_TABLE[((acc ^ b as u32) & 0xFF) as usize]
    })
}

static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};
