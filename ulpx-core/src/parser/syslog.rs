//! Syslog parser (RFC 3164, simplified).
//!
//! # Supported syntax
//!
//! Parses syslog messages with the following structure:
//!
//! ```text
//! <priority>Mmm DD HH:MM:SS hostname tag: message
//! ```
//!
//! Where:
//! - `<priority>` — optional; a decimal integer wrapped in `<` `>`.
//!   If present, the facility and severity are computed from it.
//! - `Mmm DD HH:MM:SS` — BSD-style timestamp (month abbreviation, day,
//!   time-of-day).  The year is not present in RFC 3164.
//! - `hostname` — the originating host (a single token, no spaces).
//! - `tag` — process name optionally followed by `[pid]`, terminated by `:`.
//! - `message` — the remainder of the line.
//!
//! # Extracted fields
//!
//! | Field name | Description |
//! |---|---|
//! | `syslog.priority` | Raw priority string (without `<>`), if present |
//! | `syslog.facility` | Computed facility number (priority >> 3), if priority present |
//! | `syslog.severity` | Computed severity number (priority & 7), if priority present |
//! | `syslog.timestamp` | Raw timestamp string as it appeared in the input |
//! | `syslog.hostname` | Originating host |
//! | `syslog.tag` | Process name + optional PID, without the trailing `:` |
//! | `syslog.message` | Message body |
//!
//! # Intentional limitations
//!
//! - RFC 5424 (structured data, `SD-ID`) is **not** supported.  Messages
//!   beginning with `<N>1 ` (the RFC 5424 VERSION field) are rejected with
//!   [`ParserError::Unsupported`].
//! - The timestamp is captured as raw text; no calendar parsing is performed.
//! - Hostnames containing spaces are not supported.
//! - This implementation is line-oriented and expects a single record per call.

use super::{ParsedField, Parser, ParserError, ParserMetadata, ParserResult, ParserVersion};
use crate::framing::FramedRecord;

const MONTH_ABBREVS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Parser ID used for registry lookup.
pub const PARSER_ID: &str = "syslog-rfc3164";

/// Simplified RFC 3164 syslog parser.
pub struct SyslogParser {
    meta: ParserMetadata,
}

impl SyslogParser {
    pub fn new() -> Self {
        SyslogParser {
            meta: ParserMetadata {
                id: PARSER_ID.to_owned(),
                description: "Parses RFC 3164 syslog records (simplified; no RFC 5424 support)"
                    .to_owned(),
                format: "syslog".to_owned(),
                version: ParserVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
            },
        }
    }
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for SyslogParser {
    fn metadata(&self) -> &ParserMetadata {
        &self.meta
    }

    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        use crate::parser::Span;

        let full_text = std::str::from_utf8(record.as_bytes())
            .map_err(|e| ParserError::Malformed(format!("invalid UTF-8: {e}")))?;
        let text_start = full_text.find(|c: char| !c.is_whitespace()).unwrap_or(0);
        let text = full_text.trim();

        if text.is_empty() {
            return Err(ParserError::Unsupported);
        }

        let mut pos = 0usize;
        let mut fields = Vec::new();

        let extract_field = |name: &str, start_idx: usize, end_idx: usize| {
            let slice = &text[start_idx..end_idx];
            let trimmed = slice.trim();
            let trim_start = slice.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let abs_start = text_start + start_idx + trim_start;
            let abs_end = abs_start + trimmed.len();
            ParsedField::new(name, trimmed, Span::new(abs_start, abs_end).unwrap())
        };

        // ── Optional <priority> ────────────────────────────────────────────
        if text.starts_with('<') {
            let close = text.find('>').ok_or_else(|| {
                ParserError::Malformed("unclosed '<' in priority field".to_owned())
            })?;
            let pri_str = &text[1..close];
            let pri: u32 = pri_str.parse().map_err(|_| {
                ParserError::Malformed(format!("non-numeric priority: '{pri_str}'"))
            })?;

            let pri_field = extract_field("syslog.priority", 1, close);
            // Derived fields shouldn't technically have spans pointing to the raw string if they are fundamentally different,
            // but for simple derived integer strings from the exact same priority token, reusing the priority span is acceptable.
            // A more exact provenance would record the transform. We will reuse the priority span.
            let fac_span = pri_field.span;
            let sev_span = pri_field.span;

            fields.push(pri_field);
            fields.push(ParsedField::new(
                "syslog.facility",
                (pri >> 3).to_string(),
                fac_span,
            ));
            fields.push(ParsedField::new(
                "syslog.severity",
                (pri & 7).to_string(),
                sev_span,
            ));
            pos = close + 1;
        }

        let rest_offset = pos + text[pos..].find(|c: char| !c.is_whitespace()).unwrap_or(0);
        let rest = text[pos..].trim_start();

        // Detect RFC 5424 (VERSION field immediately after priority).
        // RFC 5424 begins with "<N>1 "; we don't support it.
        if rest.starts_with("1 ") {
            return Err(ParserError::Unsupported);
        }

        // ── Timestamp: "Mmm DD HH:MM:SS" ──────────────────────────────────
        // Expect at least 15 characters: "Jan  1 00:00:00"
        let ts_end = find_timestamp_end(rest);
        if ts_end == 0 {
            return Err(ParserError::Malformed(
                "could not find RFC 3164 timestamp".to_owned(),
            ));
        }

        fields.push(extract_field(
            "syslog.timestamp",
            rest_offset,
            rest_offset + ts_end,
        ));

        let after_ts_offset = rest_offset + ts_end;
        let rest2_offset = after_ts_offset
            + text[after_ts_offset..]
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(0);
        let rest2 = text[after_ts_offset..].trim_start();

        // ── Hostname ───────────────────────────────────────────────────────
        let (hostname, _rest3) = split_first_token(rest2)
            .ok_or_else(|| ParserError::Malformed("missing hostname".to_owned()))?;

        let host_len = hostname.len();
        fields.push(extract_field(
            "syslog.hostname",
            rest2_offset,
            rest2_offset + host_len,
        ));

        let after_host_offset = rest2_offset + host_len;
        let rest3_offset = after_host_offset
            + text[after_host_offset..]
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(0);
        let rest3 = text[after_host_offset..].trim_start();

        // ── Tag (process name, optional PID, terminated by ':') ───────────
        let colon_pos = rest3.find(':').unwrap_or(rest3.len());
        fields.push(extract_field(
            "syslog.tag",
            rest3_offset,
            rest3_offset + colon_pos,
        ));

        let message_offset = if colon_pos + 1 < rest3.len() {
            let after_colon = rest3_offset + colon_pos + 1;
            after_colon
                + text[after_colon..]
                    .find(|c: char| !c.is_whitespace())
                    .unwrap_or(0)
        } else {
            text.len()
        };

        if message_offset < text.len() {
            fields.push(extract_field("syslog.message", message_offset, text.len()));
        } else {
            fields.push(extract_field("syslog.message", text.len(), text.len()));
        }

        Ok(ParserResult {
            fields,
            parser_id: self.meta.id.clone(),
            parser_version: self.meta.version,
            raw_bytes: record.as_bytes().to_vec(),
        })
    }
}

/// Find the end position of a BSD-syslog timestamp in `text`.
///
/// Looks for the pattern `Mmm [D]D HH:MM:SS`.
/// Returns the byte position immediately after the timestamp, or 0 if not found.
fn find_timestamp_end(text: &str) -> usize {
    // The timestamp must start with a three-letter month abbreviation.
    if text.len() < 15 {
        return 0;
    }
    let month = &text[..3];
    if !MONTH_ABBREVS.contains(&month) {
        return 0;
    }
    // After the month we expect exactly 15 characters: "Mmm DD HH:MM:SS"
    // but day can be single or double digit.  Find the space after month,
    // then skip day, then verify time format.
    // Simple approach: find "HH:MM:SS" after the month+day portion.
    // Month(3) + space(1) + day(1-2) + space(1) + time(8) = 14-15 chars.
    let after_month = &text[3..];
    // Skip optional leading space and day digits.
    let mut i = 0;
    // BSD syslog pads single-digit days with a space: "Jan  5" has two spaces.
    // Skip all leading spaces.
    while i < after_month.len() && after_month.as_bytes()[i] == b' ' {
        i += 1;
    }
    // Day: 1 or 2 digits.
    while i < after_month.len() && after_month.as_bytes()[i].is_ascii_digit() {
        i += 1;
    }
    // Space.
    if after_month.as_bytes().get(i) != Some(&b' ') {
        return 0;
    }
    i += 1;
    // Time: HH:MM:SS — 8 characters.
    if i + 8 > after_month.len() {
        return 0;
    }
    let time_part = &after_month[i..i + 8];
    // Validate HH:MM:SS structure.
    let tb = time_part.as_bytes();
    if tb[2] != b':' || tb[5] != b':' {
        return 0;
    }
    // All good: the timestamp ends at 3 + 1 + i + 8 = 3 + (after_month offset to end of time).
    3 + (i + 8)
}

/// Split off the first whitespace-delimited token from `text`.
fn split_first_token(text: &str) -> Option<(&str, &str)> {
    let end = text.find(' ').unwrap_or(text.len());
    if end == 0 {
        return None;
    }
    let token = &text[..end];
    let rest = &text[end..];
    Some((token, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::FramedRecord;

    fn parse(input: &[u8]) -> Result<ParserResult, ParserError> {
        SyslogParser::new().parse(&FramedRecord::new(input.to_vec()))
    }

    fn field<'a>(r: &'a ParserResult, name: &str) -> Option<&'a str> {
        r.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.raw_value.as_str())
    }

    #[test]
    fn basic_with_priority() {
        let input = b"<34>Jan  5 12:34:56 myhost myapp: hello world";
        let r = parse(input).unwrap();
        assert_eq!(field(&r, "syslog.priority"), Some("34"));
        assert_eq!(field(&r, "syslog.facility"), Some("4")); // 34 >> 3 == 4
        assert_eq!(field(&r, "syslog.severity"), Some("2")); // 34 & 7 == 2
        assert_eq!(field(&r, "syslog.hostname"), Some("myhost"));
        assert_eq!(field(&r, "syslog.tag"), Some("myapp"));
        assert_eq!(field(&r, "syslog.message"), Some("hello world"));
    }

    #[test]
    fn without_priority() {
        let input = b"Feb 14 08:00:00 server1 kernel: something happened";
        let r = parse(input).unwrap();
        assert!(field(&r, "syslog.priority").is_none());
        assert_eq!(field(&r, "syslog.hostname"), Some("server1"));
        assert_eq!(field(&r, "syslog.tag"), Some("kernel"));
        assert_eq!(field(&r, "syslog.message"), Some("something happened"));
    }

    #[test]
    fn raw_bytes_preserved() {
        let input = b"<13>Mar  1 00:00:01 host tag: msg";
        let r = parse(input).unwrap();
        assert_eq!(r.raw_bytes, input);
    }

    #[test]
    fn timestamp_captured() {
        let input = b"<0>Dec 31 23:59:59 h t: m";
        let r = parse(input).unwrap();
        let ts = field(&r, "syslog.timestamp").unwrap();
        assert!(ts.contains("Dec"));
        assert!(ts.contains("23:59:59"));
    }

    #[test]
    fn empty_input_is_unsupported() {
        assert_eq!(parse(b""), Err(ParserError::Unsupported));
    }

    #[test]
    fn rfc5424_is_unsupported() {
        // RFC 5424 format starts with VERSION = 1.
        let input = b"<165>1 2023-01-01T00:00:00Z host app - - - message";
        assert_eq!(parse(input), Err(ParserError::Unsupported));
    }

    #[test]
    fn unclosed_priority_is_malformed() {
        let input = b"<13 Jan  1 00:00:00 h t: m";
        assert!(matches!(parse(input), Err(ParserError::Malformed(_))));
    }
}
