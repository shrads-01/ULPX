//! Newline-delimited framing strategy.
//!
//! Splits a byte slice into records using `\n` as the record terminator.
//! Both Unix (`\n`) and Windows (`\r\n`) line endings are handled: a trailing
//! `\r` is stripped from each record so that `\r\n`-terminated streams produce
//! the same record bytes as `\n`-terminated streams.
//!
//! # Empty records
//!
//! A blank line (two consecutive newlines) produces an empty [`FramedRecord`].
//! Callers may filter empty records if desired; the framer preserves them to
//! avoid silently discarding data.
//!
//! # Trailing data
//!
//! If `input` does not end with a newline the remaining bytes form an
//! incomplete record.  [`frame_all`](super::Framer::frame_all) returns
//! [`FrameError::Incomplete`] for this case.  The incomplete bytes are **not**
//! returned as a record; the caller must buffer them and retry.
//!
//! # Size limit
//!
//! Individual records exceeding [`super::MAX_FRAME_BYTES`] are rejected with
//! [`FrameError::OversizedFrame`]; processing stops at that point.

use super::{FrameError, FramedRecord, Framer, MAX_FRAME_BYTES};

/// Newline-delimited framer.
///
/// See [module documentation](self) for full semantics.
pub struct NewlineFramer;

impl Framer for NewlineFramer {
    fn frame_all(&self, input: &[u8]) -> (Vec<FramedRecord>, Option<FrameError>) {
        if input.is_empty() {
            return (Vec::new(), None);
        }

        let mut records = Vec::new();
        let mut start = 0usize;

        while start < input.len() {
            match memchr(b'\n', &input[start..]) {
                None => {
                    // No newline found: remaining bytes are an incomplete record.
                    let remaining = &input[start..];
                    if remaining.len() > MAX_FRAME_BYTES {
                        return (records, Some(FrameError::OversizedFrame(remaining.len())));
                    }
                    return (records, Some(FrameError::Incomplete));
                }
                Some(rel) => {
                    let end = start + rel; // index of the '\n'
                    let record_bytes = strip_cr(&input[start..end]);
                    if record_bytes.len() > MAX_FRAME_BYTES {
                        return (
                            records,
                            Some(FrameError::OversizedFrame(record_bytes.len())),
                        );
                    }
                    records.push(FramedRecord::with_byte_range(
                        record_bytes.to_vec(),
                        start..end + 1,
                    ));
                    start = end + 1; // skip past the '\n'
                }
            }
        }

        (records, None)
    }
}

/// Strip a trailing `\r` if present.
fn strip_cr(bytes: &[u8]) -> &[u8] {
    if bytes.last() == Some(&b'\r') {
        &bytes[..bytes.len() - 1]
    } else {
        bytes
    }
}

/// Minimal `memchr` replacement using the standard library to avoid the
/// `memchr` crate dependency.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line() {
        let (records, err) = NewlineFramer.frame_all(b"hello\n");
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), b"hello");
    }

    #[test]
    fn multiple_lines() {
        let (records, err) = NewlineFramer.frame_all(b"one\ntwo\nthree\n");
        assert_eq!(err, None);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].as_bytes(), b"one");
        assert_eq!(records[1].as_bytes(), b"two");
        assert_eq!(records[2].as_bytes(), b"three");
    }

    #[test]
    fn crlf_endings_stripped() {
        let (records, err) = NewlineFramer.frame_all(b"line1\r\nline2\r\n");
        assert_eq!(err, None);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_bytes(), b"line1");
        assert_eq!(records[1].as_bytes(), b"line2");
    }

    #[test]
    fn empty_input() {
        let (records, err) = NewlineFramer.frame_all(b"");
        assert_eq!(err, None);
        assert!(records.is_empty());
    }

    #[test]
    fn blank_line_produces_empty_record() {
        let (records, err) = NewlineFramer.frame_all(b"a\n\nb\n");
        assert_eq!(err, None);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].as_bytes(), b"a");
        assert_eq!(records[1].as_bytes(), b"");
        assert_eq!(records[2].as_bytes(), b"b");
    }

    #[test]
    fn incomplete_trailing_data() {
        let (records, err) = NewlineFramer.frame_all(b"complete\nincomplete");
        assert_eq!(err, Some(FrameError::Incomplete));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), b"complete");
    }

    #[test]
    fn no_newline_at_all_is_incomplete() {
        let (records, err) = NewlineFramer.frame_all(b"no newline");
        assert_eq!(err, Some(FrameError::Incomplete));
        assert!(records.is_empty());
    }

    #[test]
    fn binary_bytes_preserved() {
        let input = b"binary\x00\x01\x7f\xff\n";
        let (records, err) = NewlineFramer.frame_all(input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), b"binary\x00\x01\x7f\xff");
    }

    #[test]
    fn multiple_records_no_cross_contamination() {
        let input = b"aaa\nbbb\nccc\n";
        let (records, _) = NewlineFramer.frame_all(input);
        assert_eq!(records[0].as_bytes(), b"aaa");
        assert_eq!(records[1].as_bytes(), b"bbb");
        assert_eq!(records[2].as_bytes(), b"ccc");
    }
}
