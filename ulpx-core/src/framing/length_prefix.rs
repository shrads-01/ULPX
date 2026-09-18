//! Length-prefixed framing strategy.
//!
//! Each record is preceded by a 4-byte **big-endian unsigned** integer
//! specifying the number of payload bytes that follow.  The length prefix
//! bytes themselves are **not** included in the returned [`FramedRecord`];
//! only the payload bytes are preserved.
//!
//! ```text
//! ┌──────────────────┬────────────────────────────────┐
//! │  length (4 B BE) │  payload bytes (length octets) │
//! └──────────────────┴────────────────────────────────┘
//! ```
//!
//! # Incomplete input
//!
//! If fewer than 4 bytes remain, or if the payload is shorter than the
//! declared length, [`FrameError::Incomplete`] is returned.
//!
//! # Size limit
//!
//! Declared lengths exceeding [`super::MAX_FRAME_BYTES`] are rejected with
//! [`FrameError::OversizedFrame`] to prevent memory exhaustion.

use super::{FrameError, FramedRecord, Framer, MAX_FRAME_BYTES};

const PREFIX_LEN: usize = 4;

/// Length-prefixed framer.
///
/// See [module documentation](self) for the wire format.
pub struct LengthPrefixFramer;

impl Framer for LengthPrefixFramer {
    fn frame_all(&self, input: &[u8]) -> (Vec<FramedRecord>, Option<FrameError>) {
        if input.is_empty() {
            return (Vec::new(), None);
        }

        let mut records = Vec::new();
        let mut cursor = 0usize;

        loop {
            let remaining = &input[cursor..];

            if remaining.is_empty() {
                return (records, None);
            }

            // Need at least 4 bytes for the length prefix.
            if remaining.len() < PREFIX_LEN {
                return (records, Some(FrameError::Incomplete));
            }

            let declared_len =
                u32::from_be_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                    as usize;

            if declared_len > MAX_FRAME_BYTES {
                return (records, Some(FrameError::OversizedFrame(declared_len)));
            }

            let payload_start = cursor + PREFIX_LEN;
            let payload_end = payload_start + declared_len;

            if payload_end > input.len() {
                return (records, Some(FrameError::Incomplete));
            }

            let payload = input[payload_start..payload_end].to_vec();
            records.push(FramedRecord::new(payload));
            cursor = payload_end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PREFIX_LEN + payload.len());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn single_record() {
        let input = encode(b"hello");
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), b"hello");
    }

    #[test]
    fn multiple_records() {
        let mut input = encode(b"first");
        input.extend_from_slice(&encode(b"second"));
        input.extend_from_slice(&encode(b"third"));
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].as_bytes(), b"first");
        assert_eq!(records[1].as_bytes(), b"second");
        assert_eq!(records[2].as_bytes(), b"third");
    }

    #[test]
    fn empty_payload() {
        let input = encode(b"");
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert!(records[0].is_empty());
    }

    #[test]
    fn empty_input() {
        let (records, err) = LengthPrefixFramer.frame_all(b"");
        assert_eq!(err, None);
        assert!(records.is_empty());
    }

    #[test]
    fn incomplete_prefix() {
        let (records, err) = LengthPrefixFramer.frame_all(b"\x00\x00");
        assert_eq!(err, Some(FrameError::Incomplete));
        assert!(records.is_empty());
    }

    #[test]
    fn incomplete_payload() {
        // Declare 5 bytes, only supply 3.
        let input = vec![0x00, 0x00, 0x00, 0x05, b'a', b'b', b'c'];
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(err, Some(FrameError::Incomplete));
        assert!(records.is_empty());
    }

    #[test]
    fn oversized_frame() {
        // Declare MAX_FRAME_BYTES + 1 in the length prefix.
        let size = (super::MAX_FRAME_BYTES + 1) as u32;
        let input = size.to_be_bytes().to_vec();
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert!(matches!(err, Some(FrameError::OversizedFrame(_))));
        assert!(records.is_empty());
    }

    #[test]
    fn binary_bytes_preserved() {
        let payload = vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
        let input = encode(&payload);
        let (records, err) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(err, None);
        assert_eq!(records[0].as_bytes(), payload.as_slice());
    }

    #[test]
    fn multiple_records_no_cross_contamination() {
        let mut input = encode(b"aaa");
        input.extend_from_slice(&encode(b"bbb"));
        let (records, _) = LengthPrefixFramer.frame_all(&input);
        assert_eq!(records[0].as_bytes(), b"aaa");
        assert_eq!(records[1].as_bytes(), b"bbb");
    }
}
