//! Reassembly of `TTLock` frames from BLE notification chunks.

use crate::packet::CRLF;

/// Fixed frame prefix: `7f5a` magic through the length field at byte 11.
const HEADER_LEN: usize = 12;

/// Accumulates notification payloads and yields complete frames.
///
/// Frames are recognized by the `7f5a` header and the length field at byte
/// 11, rather than by scanning for the trailing CRLF, so encrypted payloads
/// that happen to contain `0d0a` are handled correctly. Yielded frames have
/// the trailing CRLF stripped, matching what [`crate::packet::Envelope::parse`]
/// expects.
#[derive(Debug, Default)]
pub struct FrameAssembler {
    buffer: Vec<u8>,
}

impl FrameAssembler {
    /// Create an empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw notification bytes into the assembler.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Pop the next complete frame, if one has been assembled.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.resync();

        if self.buffer.len() < HEADER_LEN {
            return None;
        }
        let payload_len = usize::from(self.buffer[11]);
        let frame_len = HEADER_LEN + payload_len + 1;
        let wire_len = frame_len + CRLF.len();
        if self.buffer.len() < wire_len {
            return None;
        }

        let mut rest = self.buffer.split_off(wire_len);
        std::mem::swap(&mut rest, &mut self.buffer);
        let mut frame = rest;
        // Drop the trailing CRLF; tolerate its absence rather than stalling,
        // since Envelope::parse validates the frame contents anyway.
        frame.truncate(frame_len);
        Some(frame)
    }

    /// Drop leading bytes until the buffer starts with the `7f5a` magic (or
    /// could once more data arrives), so a garbled chunk cannot wedge the
    /// stream.
    fn resync(&mut self) {
        let start = self
            .buffer
            .windows(2)
            .position(|pair| pair == [0x7f, 0x5a])
            .unwrap_or_else(|| {
                if self.buffer.last() == Some(&0x7f) {
                    self.buffer.len() - 1
                } else {
                    self.buffer.len()
                }
            });
        self.buffer.drain(..start);
    }
}

#[cfg(test)]
mod tests {
    use super::FrameAssembler;
    use crate::crc::crc8;
    use crate::packet::CRLF;

    /// Hand-build an on-wire frame: header, length, payload, CRC, CRLF.
    fn frame_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0x7f, 0x5a, 0x05, 0x03, 0x02, 0x00, 0x01, 0x00, 0x01, 0x14, 0xaa,
        ];
        frame.push(u8::try_from(payload.len()).unwrap_or(0));
        frame.extend_from_slice(payload);
        let crc = crc8(&frame);
        frame.push(crc);
        frame.extend_from_slice(&CRLF);
        frame
    }

    #[test]
    fn yields_nothing_until_frame_complete() {
        let wire = frame_with_payload(&[1, 2, 3, 4]);
        let mut assembler = FrameAssembler::new();
        assembler.push(&wire[..5]);
        assert_eq!(assembler.next_frame(), None);
        assembler.push(&wire[5..wire.len() - 1]);
        assert_eq!(assembler.next_frame(), None);
        assembler.push(&wire[wire.len() - 1..]);
        let frame = assembler.next_frame();
        assert_eq!(frame.as_deref(), Some(&wire[..wire.len() - 2]));
    }

    #[test]
    fn yields_single_frame_from_one_push() {
        let wire = frame_with_payload(&[9, 9]);
        let mut assembler = FrameAssembler::new();
        assembler.push(&wire);
        assert_eq!(
            assembler.next_frame().as_deref(),
            Some(&wire[..wire.len() - 2])
        );
        assert_eq!(assembler.next_frame(), None);
    }

    #[test]
    fn yields_two_concatenated_frames_in_order() {
        let first = frame_with_payload(&[1]);
        let second = frame_with_payload(&[2, 2]);
        let mut assembler = FrameAssembler::new();
        let mut wire = first.clone();
        wire.extend_from_slice(&second);
        assembler.push(&wire);
        assert_eq!(
            assembler.next_frame().as_deref(),
            Some(&first[..first.len() - 2])
        );
        assert_eq!(
            assembler.next_frame().as_deref(),
            Some(&second[..second.len() - 2])
        );
        assert_eq!(assembler.next_frame(), None);
    }

    #[test]
    fn payload_containing_crlf_is_not_split() {
        let wire = frame_with_payload(&[0x0d, 0x0a, 0x0d, 0x0a]);
        let mut assembler = FrameAssembler::new();
        assembler.push(&wire);
        assert_eq!(
            assembler.next_frame().as_deref(),
            Some(&wire[..wire.len() - 2])
        );
    }

    #[test]
    fn resynchronizes_after_leading_garbage() {
        let wire = frame_with_payload(&[7]);
        let mut assembler = FrameAssembler::new();
        assembler.push(&[0x00, 0x42, 0x7f]);
        assembler.push(&wire);
        assert_eq!(
            assembler.next_frame().as_deref(),
            Some(&wire[..wire.len() - 2])
        );
    }

    #[test]
    fn empty_assembler_yields_nothing() {
        let mut assembler = FrameAssembler::new();
        assert_eq!(assembler.next_frame(), None);
    }
}
