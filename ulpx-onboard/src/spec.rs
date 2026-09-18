//! Declarative parser specification.

use std::collections::HashSet;
use ulpx_core::parser::ParserVersion;

/// The extraction strategy used by the generated parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionSpec {
    /// Extracts key-value pairs (e.g. `key=value foo=bar`).
    KeyValue {
        /// Separates different key-value pairs (e.g. `' '` or `','`).
        pair_separator: char,
        /// Separates the key from the value (e.g. `'='` or `':'`).
        kv_separator: char,
    },
    /// Extracts fields based on positional delimiters.
    Delimiter {
        /// The character separating fields (e.g. `','` or `'\t'`).
        separator: char,
        /// Ordered list of field names. If a record has fewer fields, the extra names are ignored.
        /// If a record has more fields, they are ignored.
        field_names: Vec<String>,
    },
}

/// A declarative specification for a parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserSpec {
    /// Canonical identifier for the parser (e.g. "custom-kv-1").
    pub parser_id: String,
    /// Human-readable description.
    pub description: String,
    /// Format or vendor association.
    pub format_name: String,
    /// Semantic version of this parser definition.
    pub version: ParserVersion,
    /// How to extract fields from the record bytes.
    pub extraction: ExtractionSpec,
}

/// Errors returned when validating a [`ParserSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecValidationError {
    EmptyParserId,
    EmptyFormatName,
    DuplicateField(String),
    EmptyFieldNames,
    InvalidSeparator(char),
    ContradictorySeparators,
}

impl std::fmt::Display for SpecValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecValidationError::EmptyParserId => write!(f, "parser_id cannot be empty"),
            SpecValidationError::EmptyFormatName => write!(f, "format_name cannot be empty"),
            SpecValidationError::DuplicateField(name) => {
                write!(f, "duplicate or empty field name: '{}'", name)
            }
            SpecValidationError::EmptyFieldNames => {
                write!(f, "delimiter spec requires at least one field name")
            }
            SpecValidationError::InvalidSeparator(c) => {
                write!(f, "invalid or control-character separator: {:?}", c)
            }
            SpecValidationError::ContradictorySeparators => {
                write!(
                    f,
                    "pair separator and kv separator cannot be the same character"
                )
            }
        }
    }
}

impl std::error::Error for SpecValidationError {}

impl ParserSpec {
    /// Validates the specification for completeness and correctness.
    pub fn validate(&self) -> Result<(), SpecValidationError> {
        if self.parser_id.trim().is_empty() {
            return Err(SpecValidationError::EmptyParserId);
        }
        if self.format_name.trim().is_empty() {
            return Err(SpecValidationError::EmptyFormatName);
        }

        match &self.extraction {
            ExtractionSpec::KeyValue {
                pair_separator,
                kv_separator,
            } => {
                if pair_separator.is_control() {
                    return Err(SpecValidationError::InvalidSeparator(*pair_separator));
                }
                if kv_separator.is_control() {
                    return Err(SpecValidationError::InvalidSeparator(*kv_separator));
                }
                if pair_separator == kv_separator {
                    return Err(SpecValidationError::ContradictorySeparators);
                }
            }
            ExtractionSpec::Delimiter {
                separator,
                field_names,
            } => {
                if separator.is_control() {
                    return Err(SpecValidationError::InvalidSeparator(*separator));
                }
                if field_names.is_empty() {
                    return Err(SpecValidationError::EmptyFieldNames);
                }
                let mut seen = HashSet::new();
                for name in field_names {
                    let trimmed = name.trim();
                    if trimmed.is_empty() {
                        return Err(SpecValidationError::DuplicateField("<empty>".into()));
                    }
                    if !seen.insert(trimmed.to_string()) {
                        return Err(SpecValidationError::DuplicateField(trimmed.to_string()));
                    }
                }
            }
        }

        Ok(())
    }
}
