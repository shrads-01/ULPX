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
                // If there is no kv_separator anywhere in the string, it's not our format
                if !text.contains(*kv_separator) {
                    return Err(ParserError::Unsupported);
                }

                for pair in text.split(*pair_separator) {
                    let pair = pair.trim();
                    if pair.is_empty() {
                        continue;
                    }

                    if let Some(idx) = pair.find(*kv_separator) {
                        let k = pair[..idx].trim();
                        let v = pair[idx + 1..].trim();
                        if k.is_empty() {
                            return Err(ParserError::Malformed(format!(
                                "empty key in pair '{}'",
                                pair
                            )));
                        }
                        fields.push(ParsedField::new(k, v));
                    } else {
                        // We expected KV pairs, but found a token with no separator.
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

                // If we ended up with no fields despite having the separator (e.g. malformed '='), unsupported/malformed.
                // We let it pass as empty list if valid, though typically KV has fields.
            }
            ExtractionSpec::Delimiter {
                separator,
                field_names,
            } => {
                // If the separator doesn't exist and we expect multiple fields, maybe unsupported?
                // For simplicity, we just parse it. But if it's completely alien, let's check
                // if at least one separator exists (unless it's a 1-field format, which is rare).
                if field_names.len() > 1 && !text.contains(*separator) {
                    return Err(ParserError::Unsupported);
                }

                for (i, val) in text.split(*separator).enumerate() {
                    if i < field_names.len() {
                        let k = field_names[i].trim();
                        let v = val.trim();
                        fields.push(ParsedField::new(k, v));
                    }
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
