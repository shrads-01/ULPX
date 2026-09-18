//! Common Event Format (CEF) parser.
//!
//! # Supported syntax
//!
//! Parses records matching the CEF:0 prefix defined by ArcSight:
//!
//! ```text
//! CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
//! ```
//!
//! The seven header fields are extracted as named fields:
//! - `cef.version` — always `"0"` for CEF:0
//! - `cef.device_vendor`
//! - `cef.device_product`
//! - `cef.device_version`
//! - `cef.signature_id`
//! - `cef.name`
//! - `cef.severity`
//!
//! Extension key-value pairs (`key=value key2=value2`) are parsed and
//! returned as individual fields with their names unchanged.
//!
//! # Intentional limitations
//!
//! - Only CEF version 0 is handled.  Other version numbers produce
//!   [`ParserError::Unsupported`].
//! - Extension values containing spaces must be escaped with `\` per the
//!   CEF specification; the escape is preserved verbatim in the raw_value.
//! - Pipe characters inside header field values must be escaped as `\|`; this
//!   implementation does *not* handle escaped pipes in header fields — unescaped
//!   pipes in header fields will cause incorrect field boundaries.
//! - Maximum number of extension fields: 500.

use super::{ParsedField, Parser, ParserError, ParserMetadata, ParserResult, ParserVersion};
use crate::framing::FramedRecord;

const MAX_EXTENSION_FIELDS: usize = 500;

/// Parser ID used for registry lookup.
pub const PARSER_ID: &str = "cef";

/// CEF:0 parser.
pub struct CefParser {
    meta: ParserMetadata,
}

impl CefParser {
    pub fn new() -> Self {
        CefParser {
            meta: ParserMetadata {
                id: PARSER_ID.to_owned(),
                description: "Parses Common Event Format (CEF:0) records".to_owned(),
                format: "CEF".to_owned(),
                version: ParserVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
            },
        }
    }
}

impl Default for CefParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for CefParser {
    fn metadata(&self) -> &ParserMetadata {
        &self.meta
    }

    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        use crate::parser::Span;

        let full_text = std::str::from_utf8(record.as_bytes())
            .map_err(|e| ParserError::Malformed(format!("invalid UTF-8: {e}")))?;

        // Find the start offset of the trimmed text to calculate absolute bounds
        let text_start = full_text.find(|c: char| !c.is_whitespace()).unwrap_or(0);
        let text = full_text.trim();

        if !text.starts_with("CEF:") {
            return Err(ParserError::Unsupported);
        }

        // parts contains (start_offset, end_offset) relative to `text`
        let parts = split_cef_header(text);
        if parts.len() < 8 {
            return Err(ParserError::Malformed(format!(
                "CEF record has {} pipe-delimited segments; expected at least 8",
                parts.len()
            )));
        }

        let mut fields = Vec::with_capacity(7);

        // Helper to extract a trimmed field and its absolute span
        let extract_field = |name: &str, start_idx: usize, end_idx: usize| {
            let slice = &text[start_idx..end_idx];
            let trimmed = slice.trim();
            // Calculate how much whitespace was trimmed from the start
            let trim_start = slice.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let abs_start = text_start + start_idx + trim_start;
            let abs_end = abs_start + trimmed.len();
            ParsedField::new(name, trimmed, Span::new(abs_start, abs_end).unwrap())
        };

        // parts[0] is "CEF:0"
        let p0 = &text[parts[0].0..parts[0].1];
        let p0_content_start = if p0.starts_with("CEF:") {
            parts[0].0 + 4
        } else {
            parts[0].0
        };
        let cef_version_field = extract_field("cef.version", p0_content_start, parts[0].1);

        if cef_version_field.raw_value != "0" {
            return Err(ParserError::Unsupported);
        }
        fields.push(cef_version_field);

        fields.push(extract_field("cef.device_vendor", parts[1].0, parts[1].1));
        fields.push(extract_field("cef.device_product", parts[2].0, parts[2].1));
        fields.push(extract_field("cef.device_version", parts[3].0, parts[3].1));
        fields.push(extract_field("cef.signature_id", parts[4].0, parts[4].1));
        fields.push(extract_field("cef.name", parts[5].0, parts[5].1));
        fields.push(extract_field("cef.severity", parts[6].0, parts[6].1));

        let ext_start = parts[7].0;
        let ext_str = &text[ext_start..];
        let ext_fields = parse_extensions(ext_str, text_start + ext_start)?;
        fields.extend(ext_fields);

        Ok(ParserResult {
            fields,
            parser_id: self.meta.id.clone(),
            parser_version: self.meta.version,
            raw_bytes: record.as_bytes().to_vec(),
        })
    }
}

/// Split the CEF header by unescaped `|` characters.
///
/// Returns a `Vec` of `(start, end)` byte indices into `text`.
fn split_cef_header(text: &str) -> Vec<(usize, usize)> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'|' {
            parts.push((start, i));
            start = i + 1;
        }
        i += 1;
    }
    parts.push((start, bytes.len()));
    parts
}

/// Parse CEF extension key=value pairs.
///
/// CEF extensions look like: `src=192.168.1.1 dst=10.0.0.1 msg=hello world`
/// Values may contain spaces if followed by another `key=` token.
fn parse_extensions(ext_str: &str, global_offset: usize) -> Result<Vec<ParsedField>, ParserError> {
    use crate::parser::Span;

    // We do not want to change global offsets, so instead of a simple `.trim()`
    // which changes indices, we calculate how much whitespace to skip.
    let trim_start = ext_str.find(|c: char| !c.is_whitespace()).unwrap_or(0);
    let _ext_end = ext_str.trim_end().len(); // from start of string to end of non-whitespace
                                             // Note: actually trim_end doesn't give us the index.
                                             // ext_str.len() - ext_str.trim_end().len() is trailing whitespace
    let ext = if trim_start < ext_str.len() {
        let trailing_len = ext_str.len() - ext_str.trim_end().len();
        &ext_str[trim_start..ext_str.len() - trailing_len]
    } else {
        ""
    };

    let base_offset = global_offset + trim_start;

    if ext.is_empty() {
        return Ok(Vec::new());
    }

    let mut fields = Vec::new();
    // Find all positions where a key= token starts (alphanumeric key followed by '=').
    let key_positions = find_key_positions(ext);

    for i in 0..key_positions.len() {
        let key_start = key_positions[i];
        let eq_pos = ext[key_start..].find('=').unwrap() + key_start;
        let key = &ext[key_start..eq_pos];
        let value_start = eq_pos + 1;
        let value_end = if i + 1 < key_positions.len() {
            // Value ends just before the next key (strip trailing space).
            let next_key = key_positions[i + 1];
            // Remove the space separator before the next key.
            if next_key > 0 && ext.as_bytes().get(next_key - 1) == Some(&b' ') {
                next_key - 1
            } else {
                next_key
            }
        } else {
            ext.len()
        };

        let value = &ext[value_start..value_end];

        if fields.len() >= MAX_EXTENSION_FIELDS {
            return Err(ParserError::ResourceLimit(format!(
                "exceeded maximum extension field count of {MAX_EXTENSION_FIELDS}"
            )));
        }

        let _abs_start = base_offset + key_start;
        let _abs_end = base_offset + value_end;
        // The value spans from key to end of value, or just value?
        // Wait, "exact byte span corresponding to the source representation from which its raw value was extracted."
        // A single ParsedField has one Span. The CEF parser currently uses `key=value` as the parsed field, where name is key and raw_value is value.
        // It's probably better for the Span to represent the exact location of the `value`, or does it mean the whole KV pair?
        // "exact byte span of the raw value in the original source evidence" -> The definition in `ParsedField` I added says "raw value".
        let abs_val_start = base_offset + value_start;
        let abs_val_end = base_offset + value_end;

        let span = Span::new(abs_val_start, abs_val_end).unwrap();
        fields.push(ParsedField::new(key, value, span));
    }

    Ok(fields)
}

/// Returns the start position (byte index into `ext`) of each `key=` token.
///
/// A token is identified as a word boundary followed by identifier characters
/// and then `=`.
fn find_key_positions(ext: &str) -> Vec<usize> {
    let bytes = ext.as_bytes();
    let mut positions = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        // A key starts after a space (or at the beginning) and consists of
        // ASCII alphanumeric / underscore / dot / dash characters followed immediately by '='.
        let at_word_start = i == 0 || bytes[i - 1] == b' ';
        if at_word_start && is_cef_key_char(bytes[i]) {
            // Scan ahead for '='.
            let mut j = i;
            while j < bytes.len() && is_cef_key_char(bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' {
                positions.push(i);
                i = j + 1; // skip past the '='
                continue;
            }
        }

        i += 1;
    }

    positions
}

fn is_cef_key_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::FramedRecord;

    fn parse(input: &[u8]) -> Result<ParserResult, ParserError> {
        CefParser::new().parse(&FramedRecord::new(input.to_vec()))
    }

    #[test]
    fn basic_cef_no_extensions() {
        let r = parse(b"CEF:0|Acme|Widget|1.0|100|Login|5|").unwrap();
        assert_eq!(field(&r, "cef.version"), Some("0"));
        assert_eq!(field(&r, "cef.device_vendor"), Some("Acme"));
        assert_eq!(field(&r, "cef.device_product"), Some("Widget"));
        assert_eq!(field(&r, "cef.device_version"), Some("1.0"));
        assert_eq!(field(&r, "cef.signature_id"), Some("100"));
        assert_eq!(field(&r, "cef.name"), Some("Login"));
        assert_eq!(field(&r, "cef.severity"), Some("5"));
    }

    #[test]
    fn cef_with_extensions() {
        let r = parse(b"CEF:0|Vendor|Product|1.0|200|Test|3|src=1.2.3.4 dst=5.6.7.8").unwrap();
        assert_eq!(field(&r, "src"), Some("1.2.3.4"));
        assert_eq!(field(&r, "dst"), Some("5.6.7.8"));
    }

    #[test]
    fn non_cef_is_unsupported() {
        assert_eq!(parse(b"not CEF at all"), Err(ParserError::Unsupported));
    }

    #[test]
    fn wrong_cef_version_is_unsupported() {
        assert_eq!(
            parse(b"CEF:1|Vendor|Product|1.0|100|Name|5|"),
            Err(ParserError::Unsupported)
        );
    }

    #[test]
    fn raw_bytes_preserved() {
        let input = b"CEF:0|V|P|1|1|N|5|";
        let r = parse(input).unwrap();
        assert_eq!(r.raw_bytes, input);
    }

    #[test]
    fn too_few_pipes() {
        assert!(matches!(
            parse(b"CEF:0|only|three|pipes"),
            Err(ParserError::Malformed(_))
        ));
    }

    fn field<'a>(r: &'a ParserResult, name: &str) -> Option<&'a str> {
        r.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.raw_value.as_str())
    }

    #[test]
    fn cef_with_custom_keys() {
        let r = parse(b"CEF:0|V|P|1.0|200|Test|3|custom.field=1 tenant-id=2_b").unwrap();
        assert_eq!(field(&r, "custom.field"), Some("1"));
        assert_eq!(field(&r, "tenant-id"), Some("2_b"));
    }
}
