use std::collections::BTreeMap;
use ulpx_core::event::EventId;
use ulpx_core::parser::{ParserVersion, Span};
use ulpx_ir::model::IrValue;

/// Standardized severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Severity {
    #[default]
    Unknown,
    Trace,
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

/// Represents the level of confidence in a mapped field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Heuristic guess, e.g. based on common field names like "host"
    Heuristic,
    /// Strong structural indicator, e.g. mapping CEF "name" to message
    Probable,
    /// Strict adherence to vendor specification, e.g. syslog timestamp
    Certain,
}

/// The reason a mapper declined to map a semantic field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstentionReason {
    /// Multiple conflicting fields suggest the same semantic concept.
    Ambiguous,
    /// A field was present but lacked enough detail (e.g. empty string).
    InsufficientEvidence,
    /// The field's type/format did not match the required canonical schema.
    TypeMismatch,
}

/// Strict provenance for a single field mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldProvenance {
    /// The exact original field name in the IR.
    pub source_field: String,
    /// The exact byte span from the raw evidence.
    pub span: Option<Span>,
    /// Any transformations applied during mapping (e.g. "lowercase", "type-coerce").
    pub transformations: Vec<String>,
    /// The rule that executed the mapping.
    pub rule_id: String,
    /// The confidence of this mapping.
    pub confidence: Confidence,
    /// The parser that originated the data.
    pub parser_id: String,
    /// The version of the parser.
    pub parser_version: ParserVersion,
}

/// A value bounded with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalField<T> {
    pub value: T,
    pub provenance: FieldProvenance,
}

/// An audit log of why a mapping was declined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstentionRecord {
    pub canonical_target: String,
    pub involved_source_fields: Vec<String>,
    pub rule_id: String,
    pub reason: AbstentionReason,
}

/// The Canonical Event representation.
///
/// Preserves original evidence and provenance, while strictly isolating
/// mapped schemas from unmapped remnants.
#[derive(Debug, Clone, PartialEq)]
pub struct CanonicalEvent {
    // ── Original Evidence & Provenance ──
    pub event_id: EventId,
    pub parser_id: String,
    pub parser_version: ParserVersion,
    pub raw_bytes: Vec<u8>,

    // ── Core Canonical Schema ──
    pub timestamp: Option<CanonicalField<String>>,
    pub source_ip: Option<CanonicalField<String>>,
    pub source_hostname: Option<CanonicalField<String>>,
    pub dest_ip: Option<CanonicalField<String>>,
    pub dest_hostname: Option<CanonicalField<String>>,
    pub severity: Option<CanonicalField<Severity>>,
    pub message: Option<CanonicalField<String>>,
    pub action: Option<CanonicalField<String>>,

    // ── Remnants ──
    /// Fields that were NOT canonically mapped. Guaranteed to be preserved.
    pub unmapped: BTreeMap<String, IrValue>,

    // ── Audit ──
    /// A record of fields the mapper considered but declined to map.
    pub abstentions: Vec<AbstentionRecord>,
}
