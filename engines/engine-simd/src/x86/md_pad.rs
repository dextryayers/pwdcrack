//! Padding shared by the little endian Merkle-Damgard hashes of the MD family.
//!
//! MD4, MD5 and NTLM all pad the same way: a `0x80` terminator, zeros, then the
//! message length in **bits** as a little endian `u64` in the last eight bytes of
//! the final block. They differ in the compression function, never in the
//! padding, so one implementation serves all three.
//!
//! # Why this is shared rather than copied
//!
//! Padding is the part of these hashes that is easy to get wrong in a way no
//! short input reveals. The defects recorded against the AVX2 MD5 kernel were
//! all here: a terminator skipped when the message length was an exact multiple
//! of 64, a bit length written to the wrong block, and a two block window
//! accepted for a message that needed three. A second copy for MD4 would be a
//! second chance to make each of those mistakes, and the two copies could drift
//! without either kernel's own tests noticing.

/// Number of 64 byte blocks the padded form of a `len` byte message needs.
///
/// 55 is the largest length that fits in one block once the terminator and the
/// eight length bytes are added.
pub(crate) fn block_count(len: usize) -> usize {
    if len + 9 <= 64 { 1 } else { (len + 9).div_ceil(64) }
}

/// Builds the padded block sequence for one message.
///
/// Returns the block count, or `None` when the message needs more than two
/// blocks. Two blocks is what keeps the multi-buffer kernels' register pressure
/// fixed, and a message past that window is handled by the scalar path instead.
pub(crate) fn pad_message(msg: &[u8], out: &mut [[u8; 64]; 2]) -> Option<usize> {
    let blocks = block_count(msg.len());
    if blocks > 2 {
        return None;
    }
    out[0] = [0u8; 64];
    out[1] = [0u8; 64];
    if msg.len() > out[0].len() * 2 - 9 {
        return None;
    }

    // Copy across block boundaries.
    let mut written = 0usize;
    for block in out.iter_mut().take(blocks) {
        let start = written;
        let end = (start + 64).min(msg.len());
        if start < end {
            block[..end - start].copy_from_slice(&msg[start..end]);
        }
        written = end;
    }

    // The marker sits at byte offset `msg.len()` within the padded stream, which
    // may be exactly a block boundary. Walking blocks looking for one with
    // `pos < 64` skips the marker entirely when `msg.len()` is a multiple of 64,
    // so every 64 byte message would produce a wrong digest.
    let marker_pos = msg.len();
    if marker_pos < blocks * 64 {
        let block = marker_pos / 64;
        let off = marker_pos % 64;
        out[block][off] = 0x80;
    }
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let last = blocks - 1;
    out[last][56..64].copy_from_slice(&bit_len.to_le_bytes());
    Some(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_count_boundaries() {
        // 55 bytes fit in one block, 56 need two, 119 fit in two, 120 need
        // three. These four lengths are the whole contract of this module.
        assert_eq!(block_count(0), 1);
        assert_eq!(block_count(55), 1);
        assert_eq!(block_count(56), 2);
        assert_eq!(block_count(119), 2);
        assert_eq!(block_count(120), 3);
    }

    #[test]
    fn the_terminator_is_written_when_the_length_fills_a_block() {
        // 64 bytes places the terminator at the first byte of the second block,
        // not past the end of the first.
        let msg = vec![b'a'; 64];
        let mut out = [[0u8; 64]; 2];
        let blocks = pad_message(&msg, &mut out).expect("64 bytes needs two blocks");
        assert_eq!(blocks, 2);
        assert_eq!(out[1][0], 0x80);
        assert_eq!(out[0][63], b'a');
    }

    #[test]
    fn the_bit_length_is_little_endian_in_the_last_block() {
        let msg = vec![b'a'; 60];
        let mut out = [[0u8; 64]; 2];
        let blocks = pad_message(&msg, &mut out).unwrap();
        assert_eq!(blocks, 2);
        // 60 bytes is 480 bits, which is 0x01e0.
        assert_eq!(&out[1][56..64], &480u64.to_le_bytes());
    }

    #[test]
    fn messages_past_the_two_block_window_are_refused() {
        let msg = vec![b'a'; 120];
        let mut out = [[0u8; 64]; 2];
        assert!(pad_message(&msg, &mut out).is_none());
    }
}
