//! Structural detectors that produce [`FormatCandidate`] evidence for a
//! framed record.
//!
//! Each detector is a free function that inspects the raw bytes of a record
//! and returns an `Option<FormatCandidate>` — `None` means the detector found
//! no evidence worth reporting at all, not even contradicting evidence.
//!
//! Detectors must be:
//! * **deterministic** — same input, same output
//! * **non-modifying** — they only read bytes
//! * **independent** — they do not call other detectors
//! * **bounded** — they must not loop unboundedly over input
//!
//! A detector may add both supporting and contradicting [`Evidence`] items to
//! a single candidate.  The engine aggregates all detectors before deciding.

use crate::model::{Evidence, FormatCandidate, InferenceConfidence};

// ─────────────────────────────────────────────
// JSON detector
// ─────────────────────────────────────────────

/// Detect JSON objects by structural markers.
///
/// Looks for:
/// * First non-whitespace byte is `{`
/// * Last non-whitespace byte is `}`
/// * Input is valid UTF-8
/// * Presence of at least one `"key": value` pattern (`:` inside the object)
pub fn detect_json(bytes: &[u8]) -> Option<FormatCandidate> {
    let trimmed = bytes.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }

    let mut evidence = Vec::new();

    // UTF-8 check — JSON is always UTF-8.
    let text = match std::str::from_utf8(trimmed) {
        Ok(t) => t,
        Err(_) => {
            evidence.push(Evidence::contradict(
                "json-utf8",
                "input is not valid UTF-8; JSON requires UTF-8",
            ));
            return Some(FormatCandidate {
                parser_id: "json-flat",
                format_name: "JSON",
                confidence: InferenceConfidence::Low,
                evidence,
            });
        }
    };

    let starts_brace = text.starts_with('{');
    let ends_brace = text.ends_with('}');

    if starts_brace {
        evidence.push(Evidence::support(
            "json-object-delimiters",
            "first non-whitespace character is '{'",
        ));
    } else {
        evidence.push(Evidence::contradict(
            "json-object-delimiters",
            format!(
                "first non-whitespace character is '{}', not '{{'",
                text.chars().next().unwrap_or('?')
            ),
        ));
    }

    if ends_brace {
        evidence.push(Evidence::support(
            "json-object-delimiters",
            "last non-whitespace character is '}'",
        ));
    } else {
        evidence.push(Evidence::contradict(
            "json-object-delimiters",
            "last non-whitespace character is not '}'",
        ));
    }

    // Look for at least one colon, which is mandatory in a non-empty JSON object.
    if text.contains(':') {
        evidence.push(Evidence::support(
            "json-key-colon",
            "colon found, consistent with JSON key-value pairs",
        ));
    } else if starts_brace && ends_brace {
        // {} is valid empty JSON but warn that it carries no fields
        evidence.push(Evidence::support(
            "json-key-colon",
            "empty JSON object (no key-value pairs)",
        ));
    }

    let confidence = if starts_brace && ends_brace {
        InferenceConfidence::High
    } else if starts_brace || ends_brace {
        InferenceConfidence::Medium
    } else {
        return None; // No JSON markers at all; don't emit a candidate
    };

    Some(FormatCandidate {
        parser_id: "json-flat",
        format_name: "JSON",
        confidence,
        evidence,
    })
}

// ─────────────────────────────────────────────
// CEF detector
// ─────────────────────────────────────────────

/// Detect CEF (Common Event Format) by its mandatory header prefix.
///
/// CEF:0|… has a precisely defined header structure.  We check:
/// * Starts with `CEF:` (case-sensitive per spec)
/// * Followed by a single decimal digit and `|`
/// * Contains at least 6 pipe separators (the 7 mandatory header fields)
pub fn detect_cef(bytes: &[u8]) -> Option<FormatCandidate> {
    let trimmed = bytes.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(trimmed).ok()?;

    let mut evidence = Vec::new();

    if !text.starts_with("CEF:") {
        // No CEF marker at all; don't emit a candidate (saves noise).
        return None;
    }

    evidence.push(Evidence::support(
        "cef-header-prefix",
        "record starts with 'CEF:'",
    ));

    // Version digit immediately after "CEF:"
    let after_prefix = &text[4..];
    let version_ok = after_prefix.starts_with('0') && after_prefix[1..].starts_with('|');
    if version_ok {
        evidence.push(Evidence::support(
            "cef-version-digit",
            "CEF version digit '0' and pipe separator present",
        ));
    } else {
        evidence.push(Evidence::contradict(
            "cef-version-digit",
            "unexpected CEF version or missing pipe after version",
        ));
    }

    // Count pipe characters to check for mandatory fields.
    let pipe_count = text.bytes().filter(|&b| b == b'|').count();
    if pipe_count >= 6 {
        evidence.push(Evidence::support(
            "cef-pipe-count",
            format!("found {pipe_count} pipe separators (≥6 required for valid CEF header)"),
        ));
    } else {
        evidence.push(Evidence::contradict(
            "cef-pipe-count",
            format!("only {pipe_count} pipe separators; CEF requires at least 6"),
        ));
    }

    let confidence = if version_ok && pipe_count >= 6 {
        InferenceConfidence::High
    } else if pipe_count >= 4 {
        InferenceConfidence::Medium
    } else {
        InferenceConfidence::Low
    };

    Some(FormatCandidate {
        parser_id: "cef",
        format_name: "CEF",
        confidence,
        evidence,
    })
}

// ─────────────────────────────────────────────
// Syslog detector
// ─────────────────────────────────────────────

/// Detect RFC 3164 syslog by its priority marker and timestamp shape.
///
/// Checks:
/// * Starts with `<` followed by 1-3 decimal digits and `>`
/// * After the priority, either a timestamp-looking string or a hostname
pub fn detect_syslog(bytes: &[u8]) -> Option<FormatCandidate> {
    let trimmed = bytes.trim_ascii();
    if trimmed.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(trimmed).ok()?;

    let mut evidence = Vec::new();

    if !text.starts_with('<') {
        // Also check for bare hostname + timestamp (syslog without priority).
        // We want to avoid false positives so only emit a Low candidate.
        // Match: 3-letter month name at the start of a line after optional hostname
        if looks_like_syslog_timestamp_start(text) {
            evidence.push(Evidence::support(
                "syslog-timestamp-shape",
                "record starts with a 3-letter month abbreviation consistent with syslog",
            ));
            return Some(FormatCandidate {
                parser_id: "syslog-rfc3164",
                format_name: "Syslog (RFC 3164)",
                confidence: InferenceConfidence::Medium,
                evidence,
            });
        }
        return None;
    }

    evidence.push(Evidence::support(
        "syslog-priority-bracket",
        "record starts with '<' (priority field marker)",
    ));

    // Find closing '>'
    let close = text[1..].find('>');
    match close {
        None => {
            evidence.push(Evidence::contradict(
                "syslog-priority-bracket",
                "no closing '>' found for priority field",
            ));
            return Some(FormatCandidate {
                parser_id: "syslog-rfc3164",
                format_name: "Syslog (RFC 3164)",
                confidence: InferenceConfidence::Low,
                evidence,
            });
        }
        Some(close_pos) => {
            let pri_str = &text[1..=close_pos]; // excludes the '>'
            if pri_str.len() <= 3 && pri_str.bytes().all(|b| b.is_ascii_digit()) {
                evidence.push(Evidence::support(
                    "syslog-priority-value",
                    format!("priority value '{pri_str}' is 1-3 digits (valid syslog range)"),
                ));
            } else {
                evidence.push(Evidence::contradict(
                    "syslog-priority-value",
                    format!("priority value '{pri_str}' is not 1-3 digits"),
                ));
            }
            // Check for timestamp after the priority
            let after_priority = &text[close_pos + 2..]; // skip '>'
            if looks_like_syslog_timestamp_start(after_priority) {
                evidence.push(Evidence::support(
                    "syslog-timestamp-shape",
                    "text after priority looks like a syslog timestamp (3-letter month)",
                ));
            }
        }
    }

    let supporting = evidence.iter().filter(|e| e.supports).count();
    let confidence = if supporting >= 3 {
        InferenceConfidence::High
    } else if supporting >= 2 {
        InferenceConfidence::Medium
    } else {
        InferenceConfidence::Low
    };

    Some(FormatCandidate {
        parser_id: "syslog-rfc3164",
        format_name: "Syslog (RFC 3164)",
        confidence,
        evidence,
    })
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// Returns true if the text starts with a 3-letter month abbreviation followed
/// by a space (e.g. "Jan ", "Feb ", …), consistent with syslog timestamps.
fn looks_like_syslog_timestamp_start(text: &str) -> bool {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if text.len() < 4 {
        return false;
    }
    let prefix = &text[..3];
    let after = text.chars().nth(3).unwrap_or('?');
    MONTHS.contains(&prefix) && after == ' '
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_detector_recognizes_object() {
        let c = detect_json(b"{\"key\": \"value\"}").unwrap();
        assert_eq!(c.parser_id, "json-flat");
        assert_eq!(c.confidence, InferenceConfidence::High);
        assert!(c.evidence.iter().all(|e| e.supports));
    }

    #[test]
    fn json_detector_rejects_non_object() {
        // A plain string is not a JSON object
        assert!(detect_json(b"hello world").is_none());
    }

    #[test]
    fn json_detector_contradicts_non_utf8() {
        let c = detect_json(b"{\xff\xfe}").unwrap();
        assert_eq!(c.confidence, InferenceConfidence::Low);
        assert!(c.evidence.iter().any(|e| !e.supports));
    }

    #[test]
    fn cef_detector_recognizes_full_header() {
        let c = detect_cef(b"CEF:0|Vendor|Product|1.0|100|Event|5|").unwrap();
        assert_eq!(c.parser_id, "cef");
        assert_eq!(c.confidence, InferenceConfidence::High);
    }

    #[test]
    fn cef_detector_not_triggered_without_prefix() {
        assert!(detect_cef(b"Some random log line").is_none());
    }

    #[test]
    fn cef_detector_low_confidence_few_pipes() {
        let c = detect_cef(b"CEF:0|A|B").unwrap();
        assert!(c.confidence < InferenceConfidence::High);
    }

    #[test]
    fn syslog_detector_recognizes_priority() {
        let c = detect_syslog(b"<34>Jan  5 12:34:56 myhost myapp: hello").unwrap();
        assert_eq!(c.parser_id, "syslog-rfc3164");
        assert_eq!(c.confidence, InferenceConfidence::High);
    }

    #[test]
    fn syslog_detector_not_triggered_for_json() {
        assert!(detect_syslog(b"{\"msg\": \"hello\"}").is_none());
    }

    #[test]
    fn syslog_detector_medium_confidence_no_priority() {
        let c = detect_syslog(b"Jan  5 12:34:56 myhost myapp: hello").unwrap();
        assert_eq!(c.parser_id, "syslog-rfc3164");
        assert_eq!(c.confidence, InferenceConfidence::Medium);
    }
}
