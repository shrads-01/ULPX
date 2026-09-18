//! Generated parser implementation.

use ulpx_core::framing::FramedRecord;
use ulpx_core::parser::{ParsedField, Parser, ParserError, ParserMetadata, ParserResult};

use crate::spec::{ExtractionSpec, ParserSpec};

/// A dynamically generated parser built from a [`ParserSpec`].
///
/// This implements [`Parser`] and enforces all ULPX architectural invariants:
/// - Extracts fields purely from the framed record
/// - Preserves exact original bytes in the result
/// - Honors `Unsupported`, `Malformed`, and `ResourceLimit` error variants
pub struct GeneratedParser {
    metadata: ParserMetadata,
    spec: ParserSpec,
}

impl GeneratedParser {
    /// Create a new generated parser. The spec is assumed to be validated already.
    pub fn new(spec: ParserSpec) -> Self {
        let metadata = ParserMetadata {
            id: spec.parser_id.clone(),
            description: spec.description.clone(),
            format: spec.format_name.clone(),
            version: spec.version,
        };
        GeneratedParser { metadata, spec }
    }
}

impl Parser for GeneratedParser {
    fn metadata(&self) -> &ParserMetadata {
        &self.metadata
    }

    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        let bytes = record.as_bytes();
        if bytes.is_empty() {
            return Err(ParserError::Unsupported);
        }

        let text = std::str::from_utf8(bytes)
            .map_err(|_| ParserError::Malformed("input is not valid UTF-8".to_string()))?;

        let mut fields = Vec::new();

        match &self.spec.extraction {
            ExtractionSpec::KeyValue {
                pair_separator,
                kv_separator,
            } => {
                if !text.contains(*kv_separator) {
                    return Err(ParserError::Unsupported);
                }

                let mut start = 0;
                while start < text.len() {
                    let next_idx = text[start..]
                        .find(*pair_separator)
                        .map(|i| start + i)
                        .unwrap_or(text.len());
                    let pair_slice = &text[start..next_idx];

                    let pair_trim_start =
                        pair_slice.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                    let pair = pair_slice.trim();
                    let pair_abs_start = start + pair_trim_start;

                    if !pair.is_empty() {
                        if let Some(idx) = pair.find(*kv_separator) {
                            let k = pair[..idx].trim();
                            let v_slice = &pair[idx + kv_separator.len_utf8()..];
                            let v_trim_start =
                                v_slice.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                            let v = v_slice.trim();

                            if k.is_empty() {
                                return Err(ParserError::Malformed(format!(
                                    "empty key in pair '{}'",
                                    pair
                                )));
                            }

                            let abs_v_start =
                                pair_abs_start + idx + kv_separator.len_utf8() + v_trim_start;
                            let abs_v_end = abs_v_start + v.len();
                            fields.push(ParsedField::new(
                                k,
                                v,
                                ulpx_core::parser::Span::new(abs_v_start, abs_v_end).unwrap(),
                            ));
                        } else {
                            return Err(ParserError::Malformed(format!(
                                "missing kv separator '{}' in pair '{}'",
                                kv_separator, pair
                            )));
                        }

                        if fields.len() > 1000 {
                            return Err(ParserError::ResourceLimit(
                                "exceeded maximum of 1000 extracted fields".into(),
                            ));
                        }
                    }

                    start = next_idx + pair_separator.len_utf8();
                }
            }
            ExtractionSpec::Delimiter {
                separator,
                field_names,
            } => {
                if field_names.len() > 1 && !text.contains(*separator) {
                    return Err(ParserError::Unsupported);
                }

                let mut start = 0;
                let mut i = 0;
                while start <= text.len() && i < field_names.len() {
                    let next_idx = text[start..]
                        .find(*separator)
                        .map(|idx| start + idx)
                        .unwrap_or(text.len());
                    let val_slice = &text[start..next_idx];

                    let trim_start = val_slice.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                    let v = val_slice.trim();

                    let abs_start = start + trim_start;
                    let abs_end = abs_start + v.len();

                    let k = field_names[i].trim();
                    fields.push(ParsedField::new(
                        k,
                        v,
                        ulpx_core::parser::Span::new(abs_start, abs_end).unwrap(),
                    ));

                    if next_idx == text.len() {
                        break;
                    }
                    start = next_idx + separator.len_utf8();
                    i += 1;
                }

                if fields.len() > 1000 {
                    return Err(ParserError::ResourceLimit(
                        "exceeded maximum of 1000 extracted fields".into(),
                    ));
                }
            }
        }

        Ok(ParserResult {
            fields,
            parser_id: self.metadata.id.clone(),
            parser_version: self.metadata.version,
            raw_bytes: bytes.to_vec(),
        })
    }
}
