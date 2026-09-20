//! JSON parser for flat JSON objects.
//!
//! # Supported syntax
//!
//! Parses JSON objects (`{…}`) whose top-level values are one of:
//! - JSON strings (`"…"`)
//! - JSON numbers (integer or floating-point, no exponent validation)
//! - `true`, `false`, `null`
//!
//! # Intentional limitations
//!
//! - Nested objects and arrays are extracted as their raw JSON text rather than
//!   being recursively expanded.  The raw string is preserved as the field
//!   value.
//! - Unicode escape sequences (`\uXXXX`) inside strings are preserved verbatim
//!   rather than decoded.
//! - Duplicate keys: the last value wins (standard JSON implementations vary).
//! - Maximum field count: 1 000.  Records with more top-level fields are
//!   rejected with [`ParserError::ResourceLimit`].
//!
//! These limitations are documented rather than silently ignored.

use super::{ParsedField, Parser, ParserError, ParserMetadata, ParserResult, ParserVersion};
use crate::framing::FramedRecord;

/// Maximum number of top-level fields extracted from a single record.
const MAX_FIELDS: usize = 1_000;

/// Parser ID used for registry lookup.
pub const PARSER_ID: &str = "json-flat";

/// JSON flat-object parser.
pub struct JsonParser {
    meta: ParserMetadata,
}

impl JsonParser {
    pub fn new() -> Self {
        JsonParser {
            meta: ParserMetadata {
                id: PARSER_ID.to_owned(),
                description:
                    "Parses flat JSON objects; nested structures are preserved as raw text"
                        .to_owned(),
                format: "JSON".to_owned(),
                version: ParserVersion {
                    major: 0,
                    minor: 1,
                    patch: 0,
                },
            },
        }
    }
}

impl Default for JsonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser for JsonParser {
    fn metadata(&self) -> &ParserMetadata {
        &self.meta
    }

    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        let full_text = std::str::from_utf8(record.as_bytes())
            .map_err(|e| ParserError::Malformed(format!("invalid UTF-8: {e}")))?;

        let text = full_text.strip_prefix('\u{FEFF}').unwrap_or(full_text).trim();

        if !text.starts_with('{') || !text.ends_with('}') {
            return Err(ParserError::Unsupported);
        }

        let inner_start = (text.as_ptr() as usize - full_text.as_ptr() as usize) + 1;
        let fields = parse_flat_object(text, inner_start)?;

        Ok(ParserResult {
            fields,
            parser_id: self.meta.id.clone(),
            parser_version: self.meta.version,
            raw_bytes: record.as_bytes().to_vec(),
        })
    }
}

/// Extract top-level key-value pairs from a JSON object string.
///
/// This is a hand-rolled scanner and does not use any external JSON library.
/// It handles the subset described in the module documentation.
fn parse_flat_object(text: &str, global_offset: usize) -> Result<Vec<ParsedField>, ParserError> {
    use crate::parser::Span;

    // Strip outer `{` and `}`.
    let inner = &text[1..text.len() - 1];
    let mut fields = Vec::new();
    let mut chars = inner.char_indices().peekable();

    loop {
        // Skip whitespace.
        skip_whitespace(&mut chars);

        // Are we done?
        if chars.peek().is_none() {
            break;
        }

        // Expect a key (must be a JSON string).
        if chars.peek().map(|(_, c)| *c) != Some('"') {
            return Err(ParserError::Malformed("expected '\"' for key".to_owned()));
        }
        let (key, _) = read_json_string(inner, &mut chars, global_offset)?;

        // Skip whitespace, then expect ':'.
        skip_whitespace(&mut chars);
        match chars.next() {
            Some((_, ':')) => {}
            _ => return Err(ParserError::Malformed("expected ':' after key".to_owned())),
        }

        // Skip whitespace, then read the value.
        skip_whitespace(&mut chars);
        let (value, span) = read_json_value(inner, &mut chars, global_offset)?;

        if fields.len() >= MAX_FIELDS {
            return Err(ParserError::ResourceLimit(format!(
                "exceeded maximum field count of {MAX_FIELDS}"
            )));
        }

        let valid_span = Span::new(span.start, span.end)
            .ok_or_else(|| ParserError::Malformed("invalid span generated".to_owned()))?;
        fields.push(ParsedField::new(key, value, valid_span));

        // Skip whitespace, then expect ',' or end.
        skip_whitespace(&mut chars);
        match chars.peek() {
            Some((_, ',')) => {
                chars.next();
            }
            None => break,
            Some((_, c)) => {
                let bad = *c;
                return Err(ParserError::Malformed(format!(
                    "unexpected character '{bad}' after value"
                )));
            }
        }
    }

    Ok(fields)
}

type CharIter<'a> = std::iter::Peekable<std::str::CharIndices<'a>>;

fn skip_whitespace(chars: &mut CharIter<'_>) {
    while chars.peek().map(|(_, c)| c.is_whitespace()) == Some(true) {
        chars.next();
    }
}

/// Read a JSON string value (including the surrounding `"` delimiters).
/// Returns the content without the surrounding quotes and its global span.
fn read_json_string(
    source: &str,
    chars: &mut CharIter<'_>,
    global_offset: usize,
) -> Result<(String, crate::parser::Span), ParserError> {
    use crate::parser::Span;

    // Consume opening '"'.
    let start_idx = match chars.next() {
        Some((idx, '"')) => idx,
        _ => return Err(ParserError::Malformed("expected '\"'".to_owned())),
    };

    let value_start = start_idx + 1;

    let mut result = String::new();
    let mut escaped = false;
    let value_end;

    loop {
        match chars.next() {
            None => return Err(ParserError::Malformed("unterminated string".to_owned())),
            Some((idx, c)) => {
                if escaped {
                    // Preserve common escape sequences as-is in raw_value.
                    result.push('\\');
                    result.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    value_end = idx;
                    break;
                } else {
                    result.push(c);
                }
            }
        }
    }
    let _ = source;
    let span = Span::new(global_offset + value_start, global_offset + value_end).unwrap();
    Ok((result, span))
}

/// Read a JSON value: string, number, boolean, null, or a nested object/array
/// (returned as raw text).
fn read_json_value(
    source: &str,
    chars: &mut CharIter<'_>,
    global_offset: usize,
) -> Result<(String, crate::parser::Span), ParserError> {
    match chars.peek() {
        Some((_, '"')) => {
            // String value — return the content without quotes.
            read_json_string(source, chars, global_offset)
        }
        Some((_, '{')) | Some((_, '[')) => {
            // Nested object or array — capture raw text.
            read_balanced(source, chars, global_offset)
        }
        Some((_, 't')) | Some((_, 'f')) | Some((_, 'n')) => {
            // true / false / null
            read_bare_word(source, chars, global_offset)
        }
        Some((_, c)) if c.is_ascii_digit() || *c == '-' => {
            read_number(source, chars, global_offset)
        }
        Some((_, c)) => {
            let bad = *c;
            Err(ParserError::Malformed(format!(
                "unexpected character '{bad}' at start of value"
            )))
        }
        None => Err(ParserError::Malformed(
            "expected value, found end of input".to_owned(),
        )),
    }
}

/// Capture a balanced `{…}` or `[…]` region as raw text.
fn read_balanced(
    _source: &str,
    chars: &mut CharIter<'_>,
    global_offset: usize,
) -> Result<(String, crate::parser::Span), ParserError> {
    use crate::parser::Span;

    let (start_idx, open) = chars.next().unwrap();
    let close = if open == '{' { '}' } else { ']' };
    let mut buf = String::new();
    buf.push(open);
    let mut depth = 1usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut end_idx;

    loop {
        match chars.next() {
            None => {
                return Err(ParserError::Malformed(format!(
                    "unterminated nested structure starting with '{open}'"
                )))
            }
            Some((idx, c)) => {
                buf.push(c);
                end_idx = idx + c.len_utf8();
                if escaped {
                    escaped = false;
                } else if in_string {
                    match c {
                        '\\' => escaped = true,
                        '"' => in_string = false,
                        _ => {}
                    }
                } else {
                    match c {
                        '"' => in_string = true,
                        '{' | '[' => depth += 1,
                        '}' | ']' if c == close => {
                            depth -= 1;
                            if depth == 0 {
                                let span =
                                    Span::new(global_offset + start_idx, global_offset + end_idx)
                                        .unwrap();
                                return Ok((buf, span));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Read a bare word (true, false, null).
fn read_bare_word(
    _source: &str,
    chars: &mut CharIter<'_>,
    global_offset: usize,
) -> Result<(String, crate::parser::Span), ParserError> {
    use crate::parser::Span;

    let mut word = String::new();
    let start_idx = chars.peek().unwrap().0;
    let mut end_idx = start_idx;

    while let Some(&(idx, c)) = chars.peek() {
        if c.is_alphabetic() {
            word.push(c);
            end_idx = idx + c.len_utf8();
            chars.next();
        } else {
            break;
        }
    }
    let span = Span::new(global_offset + start_idx, global_offset + end_idx).unwrap();
    Ok((word, span))
}

/// Read a JSON number.
fn read_number(
    _source: &str,
    chars: &mut CharIter<'_>,
    global_offset: usize,
) -> Result<(String, crate::parser::Span), ParserError> {
    use crate::parser::Span;

    let mut num = String::new();
    let start_idx = chars.peek().unwrap().0;
    let mut end_idx = start_idx;

    while let Some(&(idx, c)) = chars.peek() {
        if matches!(c, '0'..='9' | '-' | '+' | '.' | 'e' | 'E') {
            num.push(c);
            end_idx = idx + c.len_utf8();
            chars.next();
        } else {
            break;
        }
    }
    let span = Span::new(global_offset + start_idx, global_offset + end_idx).unwrap();
    Ok((num, span))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::FramedRecord;

    fn parse(input: &[u8]) -> Result<ParserResult, ParserError> {
        JsonParser::new().parse(&FramedRecord::new(input.to_vec()))
    }

    #[test]
    fn flat_object() {
        let r = parse(br#"{"host":"server1","port":"8080"}"#).unwrap();
        assert_eq!(r.fields.len(), 2);
        assert_eq!(r.fields[0].name, "host");
        assert_eq!(r.fields[0].raw_value, "server1");
        assert_eq!(r.fields[1].name, "port");
        assert_eq!(r.fields[1].raw_value, "8080");
    }

    #[test]
    fn numeric_value() {
        let r = parse(br#"{"count":42}"#).unwrap();
        assert_eq!(r.fields[0].name, "count");
        assert_eq!(r.fields[0].raw_value, "42");
    }

    #[test]
    fn boolean_and_null() {
        let r = parse(br#"{"active":true,"deleted":false,"tag":null}"#).unwrap();
        assert_eq!(r.fields[0].raw_value, "true");
        assert_eq!(r.fields[1].raw_value, "false");
        assert_eq!(r.fields[2].raw_value, "null");
    }

    #[test]
    fn nested_object_as_raw_text() {
        let r = parse(br#"{"meta":{"version":1}}"#).unwrap();
        assert_eq!(r.fields[0].name, "meta");
        assert_eq!(r.fields[0].raw_value, r#"{"version":1}"#);
    }

    #[test]
    fn empty_object() {
        let r = parse(br#"{}"#).unwrap();
        assert!(r.fields.is_empty());
    }

    #[test]
    fn unsupported_non_object() {
        assert_eq!(parse(b"not json"), Err(ParserError::Unsupported));
        assert_eq!(parse(b"[1,2,3]"), Err(ParserError::Unsupported));
    }

    #[test]
    fn raw_bytes_preserved() {
        let input = br#"{"k":"v"}"#;
        let r = parse(input).unwrap();
        assert_eq!(r.raw_bytes, input);
    }

    #[test]
    fn parser_id_and_version_in_result() {
        let r = parse(br#"{"x":1}"#).unwrap();
        assert_eq!(r.parser_id, PARSER_ID);
        assert_eq!(
            r.parser_version,
            ParserVersion {
                major: 0,
                minor: 1,
                patch: 0
            }
        );
    }
    #[test]
    fn string_with_special_chars() {
        let r = parse(br#"{"msg":"hello, {world} [and] \"quotes\""}"#).unwrap();
        assert_eq!(r.fields[0].raw_value, "hello, {world} [and] \\\"quotes\\\"");
    }
}
