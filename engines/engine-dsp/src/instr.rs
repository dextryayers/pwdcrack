#[derive(Debug, Clone)]
pub enum DspInstruction {
    Load { addr: u32, dst: u8 },
    Store { addr: u32, src: u8 },
    Add { dst: u8, a: u8, b: u8 },
    Sub { dst: u8, a: u8, b: u8 },
    Mul { dst: u8, a: u8, b: u8 },
    Xor { dst: u8, a: u8, b: u8 },
    Rotate { dst: u8, src: u8, shift: u8 },
    Branch { target: u32 },
    Call { target: u32 },
    Return,
}

impl DspInstruction {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DspInstruction::Load { addr, dst } => vec![0x01, *dst, (addr >> 24) as u8, (addr >> 16) as u8, (addr >> 8) as u8, *addr as u8],
            DspInstruction::Store { addr, src } => vec![0x02, *src, (addr >> 24) as u8, (addr >> 16) as u8, (addr >> 8) as u8, *addr as u8],
            DspInstruction::Add { dst, a, b } => vec![0x10, *dst, *a, *b, 0x00, 0x00],
            DspInstruction::Sub { dst, a, b } => vec![0x11, *dst, *a, *b, 0x00, 0x00],
            DspInstruction::Mul { dst, a, b } => vec![0x12, *dst, *a, *b, 0x00, 0x00],
            DspInstruction::Xor { dst, a, b } => vec![0x13, *dst, *a, *b, 0x00, 0x00],
            DspInstruction::Rotate { dst, src, shift } => vec![0x14, *dst, *src, *shift, 0x00, 0x00],
            DspInstruction::Branch { target } => vec![0x20, 0x00, (target >> 24) as u8, (target >> 16) as u8, (target >> 8) as u8, *target as u8],
            DspInstruction::Call { target } => vec![0x21, 0x00, (target >> 24) as u8, (target >> 16) as u8, (target >> 8) as u8, *target as u8],
            DspInstruction::Return => vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00],
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 6 { return None; }
        match bytes[0] {
            0x01 => Some(DspInstruction::Load {
                addr: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
                dst: bytes[1],
            }),
            0x02 => Some(DspInstruction::Store {
                addr: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
                src: bytes[1],
            }),
            0x10 => Some(DspInstruction::Add { dst: bytes[1], a: bytes[2], b: bytes[3] }),
            0x11 => Some(DspInstruction::Sub { dst: bytes[1], a: bytes[2], b: bytes[3] }),
            0x12 => Some(DspInstruction::Mul { dst: bytes[1], a: bytes[2], b: bytes[3] }),
            0x13 => Some(DspInstruction::Xor { dst: bytes[1], a: bytes[2], b: bytes[3] }),
            0x14 => Some(DspInstruction::Rotate { dst: bytes[1], src: bytes[2], shift: bytes[3] }),
            0x20 => Some(DspInstruction::Branch {
                target: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            }),
            0x21 => Some(DspInstruction::Call {
                target: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            }),
            0x22 => Some(DspInstruction::Return),
            _ => None,
        }
    }
}
