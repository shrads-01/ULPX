//! JSON-object framing strategy.
//!
//! Scans the input for complete, top-level JSON object boundaries â€” i.e., a
//! `{` byte that is matched by its closing `}` at brace depth 0.
//!
//! # Limitations (intentionally documented)
//!
//! - Only top-level **objects** (`{â€¦}`) are supported.  Arrays, strings,
//!   numbers, or `true`/`false`/`null` at the top level are not valid frames
//!   and produce [`FrameError::Malformed`].
//! - String literals inside the JSON are tracked for nesting purposes, but
//!   the contents are not validated; malformed escape sequences inside strings
//!   do not cause a `Malformed` error â€” only a structural mismatch (unbalanced
//!   braces, unclosed strings) does.
//! - Input must be UTF-8 encoded JSON.  Non-UTF-8 bytes produce
//!   [`FrameError::Malformed`].
//! - Whitespace between records (spaces, tabs, newlines) is silently skipped.
//!
//! # Incomplete input
//!
//! If an opening `{` is found but the matching `}` is not present in the
//! input, [`FrameError::Incomplete`] is returned.
//!
//! # Size limit
//!
//! Objects exceeding [`super::MAX_FRAME_BYTES`] are rejected with
//! [`FrameError::OversizedFrame`].

use super::{FrameError, FramedRecord, Framer, MAX_FRAME_BYTES};

/// JSON-object framer.
///
/// See [module documentation](self) for semantics and limitations.
pub struct JsonObjectFramer;

impl Framer for JsonObjectFramer {
    fn frame_all(&self, input: &[u8]) -> (Vec<FramedRecord>, Option<FrameError>) {
        if input.is_empty() {
            return (Vec::new(), None);
        }

        // Validate UTF-8 up front so we can work with str slices.
        let text = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(e) => {
                return (
                    Vec::new(),
                    Some(FrameError::Malformed(format!("invalid UTF-8: {e}"))),
                );
            }
        };

        let mut records = Vec::new();
        let mut chars = text.char_indices().peekable();

        loop {
            // Skip inter-record whitespace.
            loop {
                match chars.peek() {
                    Some((_, c)) if c.is_whitespace() => {
                        chars.next();
                    }
                    _ => break,
                }
            }

            // Determine what the next non-whitespace character is.
            match chars.peek() {
                None => return (records, None), // cleanly consumed
                Some((_, '{')) => {}            // expected: start of object
                Some((pos, c)) => {
                    let bad = *c;
                    let at = *pos;
                    let _ = at;
                    return (
                        records,
                        Some(FrameError::Malformed(format!(
                            "expected '{{' at top level, found '{bad}'"
                        ))),
                    );
                }
            }

            // Find the matching closing brace.
            let (start_pos, _) = chars.next().unwrap(); // consume '{'
            let mut depth: usize = 1;
            let mut in_string = false;
            let mut after_backslash = false;
            let mut end_pos: Option<usize> = None;

            for (pos, ch) in chars.by_ref() {
                if after_backslash {
                    after_backslash = false;
                    continue;
                }
                if in_string {
                    match ch {
                        '\\' => after_backslash = true,
                        '"' => in_string = false,
                        _ => {}
                    }
                } else {
                    match ch {
                        '"' => in_string = true,
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end_pos = Some(pos);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            match end_pos {
                None => {
                    // Opening brace was not closed.
                    return (records, Some(FrameError::Incomplete));
                }
                Some(end) => {
                    // end points to the '}'; the record is input[start_pos..=end].
                    let record_bytes = &input[start_pos..=end];
                    if record_bytes.len() > MAX_FRAME_BYTES {
                        return (
                            records,
                            Some(FrameError::OversizedFrame(record_bytes.len())),
                        );
                    }
                    records.push(FramedRecord::new(record_bytes.to_vec()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_object() {
        let (records, err) = JsonObjectFramer.frame_all(br#"{"a":1}"#);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), br#"{"a":1}"#);
    }

    #[test]
    fn multiple_objects() {
        let input = br#"{"x":1}{"y":2}"#;
        let (records, err) = JsonObjectFramer.frame_all(input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_bytes(), br#"{"x":1}"#);
        assert_eq!(records[1].as_bytes(), br#"{"y":2}"#);
    }

    #[test]
    fn objects_separated_by_newlines() {
        let input = b"{\"a\":1}\n{\"b\":2}\n";
        let (records, err) = JsonObjectFramer.frame_all(input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn nested_object_preserved() {
        let input = br#"{"outer":{"inner":42}}"#;
        let (records, err) = JsonObjectFramer.frame_all(input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), br#"{"outer":{"inner":42}}"#);
    }

    #[test]
    fn string_containing_braces_not_misinterpreted() {
        let input = br#"{"key":"val{ue}"}"#;
        let (records, err) = JsonObjectFramer.frame_all(input);
        assert_eq!(err, None);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_bytes(), br#"{"key":"val{ue}"}"#);
    }

    #[test]
    fn empty_input() {
        let (records, err) = JsonObjectFramer.frame_all(b"");
        assert_eq!(err, None);
        assert!(records.is_empty());
    }

    #[test]
    fn incomplete_object() {
        let (records, err) = JsonObjectFramer.frame_all(br#"{"key":"value""#);
        assert_eq!(err, Some(FrameError::Incomplete));
        assert!(records.is_empty());
    }

    #[test]
    fn non_object_at_top_level() {
        let (records, err) = JsonObjectFramer.frame_all(b"[1,2,3]");
        assert!(matches!(err, Some(FrameError::Malformed(_))));
        assert!(records.is_empty());
    }

    #[test]
    fn invalid_utf8() {
        let input = b"\xff\xfe";
        let (records, err) = JsonObjectFramer.frame_all(input);
        assert!(matches!(err, Some(FrameError::Malformed(_))));
        assert!(records.is_empty());
    }

    #[test]
    fn bytes_preserved_exactly() {
        let raw = b"{\"k\":\"v\"}";
        let (records, err) = JsonObjectFramer.frame_all(raw);
        assert_eq!(err, None);
        assert_eq!(records[0].as_bytes(), raw);
    }

    #[test]
    fn multiple_objects_no_cross_contamination() {
        let input = br#"{"a":1}{"b":2}{"c":3}"#;
        let (records, _) = JsonObjectFramer.frame_all(input);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].as_bytes(), br#"{"a":1}"#);
        assert_eq!(records[1].as_bytes(), br#"{"b":2}"#);
        assert_eq!(records[2].as_bytes(), br#"{"c":3}"#);
    }
}
