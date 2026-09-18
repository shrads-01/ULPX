use std::collections::BTreeMap;
use ulpx_core::event::EventId;
use ulpx_core::parser::ParserVersion;

/// Strongly typed value for un-normalized fields.
#[derive(Debug, Clone, PartialEq)]
pub enum IrValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Null,
}

/// The Universal Log Processing Intermediate Representation (ULPX-IR).
///
/// This representation preserves original evidence and provenance.
/// It acts as a typed container for parsed fields prior to semantic mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct EventIr {
    // ── Provenance & Identity ──
    /// Link back to the original ingested event in the EvidenceStore.
    pub event_id: EventId,
    /// The parser that produced these fields.
    pub parser_id: String,
    /// The version of the parser, for reproducibility.
    pub parser_version: ParserVersion,
    /// A preserved copy of the exact bytes that were parsed.
    /// NOTE: This is a localized convenience copy for downstream transformations.
    /// The authoritative, immutable evidence remains in `ulpx_core::storage`.
    pub raw_bytes: Vec<u8>,

    // ── Un-normalized Extracted Fields ──
    /// All fields extracted by the parser, strongly typed.
    /// A BTreeMap is used to guarantee deterministic iteration and serialization.
    pub fields: BTreeMap<String, IrValue>,
}

impl EventIr {
    /// Create a new EventIr with required provenance fields.
    pub fn new(
        event_id: EventId,
        parser_id: String,
        parser_version: ParserVersion,
        raw_bytes: Vec<u8>,
    ) -> Self {
        Self {
            event_id,
            parser_id,
            parser_version,
            raw_bytes,
            fields: BTreeMap::new(),
        }
    }
}
