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
        let text = std::str::from_utf8(record.as_bytes())
            .map_err(|e| ParserError::Malformed(format!("invalid UTF-8: {e}")))?;

        let text = text.trim();

        if !text.starts_with("CEF:") {
            return Err(ParserError::Unsupported);
        }

        // Split on the first 7 pipes to get the 8 header segments.
        // We do a manual split to handle exactly 7 unescaped pipes.
        let parts = split_cef_header(text);
        if parts.len() < 8 {
            return Err(ParserError::Malformed(format!(
                "CEF record has {} pipe-delimited segments; expected at least 8",
                parts.len()
            )));
        }

        // parts[0] is "CEF:0"
        let cef_version = parts[0].strip_prefix("CEF:").unwrap_or("").trim();
        if cef_version != "0" {
            return Err(ParserError::Unsupported);
        }

        let mut fields = vec![
            ParsedField::new("cef.version", cef_version),
            ParsedField::new("cef.device_vendor", parts[1].trim()),
            ParsedField::new("cef.device_product", parts[2].trim()),
            ParsedField::new("cef.device_version", parts[3].trim()),
            ParsedField::new("cef.signature_id", parts[4].trim()),
            ParsedField::new("cef.name", parts[5].trim()),
            ParsedField::new("cef.severity", parts[6].trim()),
        ];

        // Remaining parts (index 7+) are extension key-value pairs joined back
        // (they may contain pipe characters as data in practice, but the standard
        // says extensions follow the 7th pipe).
        let extensions_raw = parts[7..].join("|");
        let ext_fields = parse_extensions(&extensions_raw)?;
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
/// Returns a `Vec` where element 0 is `"CEF:0"`, elements 1–6 are the header
/// fields, and element 7 onward is the extension string.
fn split_cef_header(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'|' {
            parts.push(&text[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    parts.push(&text[start..]);
    parts
}

/// Parse CEF extension key=value pairs.
///
/// CEF extensions look like: `src=192.168.1.1 dst=10.0.0.1 msg=hello world`
/// Values may contain spaces if followed by another `key=` token.
fn parse_extensions(ext: &str) -> Result<Vec<ParsedField>, ParserError> {
    let ext = ext.trim();
    if ext.is_empty() {
        return Ok(Vec::new());
    }

    let mut fields = Vec::new();
    // Find all positions where a key= token starts (alphanumeric key followed by '=').
    // Strategy: find all `key=` boundaries, then slice values between them.
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

        fields.push(ParsedField::new(key, value));
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
