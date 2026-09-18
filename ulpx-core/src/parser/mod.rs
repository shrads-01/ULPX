//! Parser runtime for ULPX.
//!
//! # Architectural boundary
//!
//! **Parsing** interprets a [`FramedRecord`](crate::framing::FramedRecord) that
//! has already been produced by the framing layer.  Parsers do **not** perform
//! framing; they receive bytes whose boundaries are already known.
//!
//! Parsing results include the [`raw_bytes`](ParserResult::raw_bytes) of the
//! original frame so that the original evidence is never lost through the
//! parsing step.
//!
//! # Parser lifecycle
//!
//! Parsers are registered in a [`ParserRegistry`].  The registry is the
//! single point of dispatch.  In this increment the lifecycle stages
//! (candidate → validated → approved → deployed) are represented by the
//! [`LifecycleStage`] enum attached to each parser registration, but
//! lifecycle promotion logic belongs to a later phase.
//!
//! # Implementations
//!
//! | Module | Format |
//! |---|---|
//! | [`json`] | Flat JSON objects |
//! | [`cef`] | Common Event Format (CEF:0) |
//! | [`syslog`] | RFC 3164 syslog (simplified) |

pub mod cef;
pub mod json;
pub mod syslog;

use std::collections::HashMap;
use std::fmt;

use crate::framing::FramedRecord;

// ─────────────────────────────────────────────
// ParserVersion
// ─────────────────────────────────────────────

/// Semantic version of a parser implementation.
///
/// Version changes that affect the interpretation of a field must increment
/// at least the minor component so that reprocessing pipelines can detect
/// whether a stored interpretation is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParserVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for ParserVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ─────────────────────────────────────────────
// ParserMetadata
// ─────────────────────────────────────────────

/// Static metadata describing a parser.
///
/// The `id` is the canonical identifier used to look the parser up in a
/// [`ParserRegistry`].  It must be unique across all parsers registered in the
/// same registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserMetadata {
    /// Unique identifier, e.g. `"json-flat"`, `"cef"`, `"syslog-rfc3164"`.
    pub id: String,
    /// Human-readable description of what this parser handles.
    pub description: String,
    /// Format or vendor association, if applicable (e.g. `"JSON"`, `"CEF"`).
    pub format: String,
    /// Version of this parser implementation.
    pub version: ParserVersion,
}

// ─────────────────────────────────────────────
// LifecycleStage
// ─────────────────────────────────────────────

/// Lifecycle stage of a parser in the registry.
///
/// In this increment parsers are registered directly at a specific stage.
/// Promotion between stages belongs to a future ParserLab phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStage {
    Candidate,
    Validated,
    Approved,
    Deployed,
}

// ─────────────────────────────────────────────
// Span
// ─────────────────────────────────────────────

/// A contiguous byte range in the original source evidence.
///
/// Offsets are byte indices into the original parsed buffer. The range is
/// half-open `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// Creates a new Span. Returns `None` if `start > end`.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if start > end {
            None
        } else {
            Some(Span { start, end })
        }
    }
}

// ─────────────────────────────────────────────
// ParsedField
// ─────────────────────────────────────────────

/// A single extracted key-value field from a parsed record.
///
/// Both the field name and value are preserved as strings derived directly
/// from the raw evidence.  No type coercion is performed in this layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedField {
    /// Field name as extracted from the source evidence.
    pub name: String,
    /// Raw string value as extracted from the source evidence.
    pub raw_value: String,
    /// Exact byte span of the raw value in the original source evidence.
    pub span: Span,
}

impl ParsedField {
    pub fn new(name: impl Into<String>, raw_value: impl Into<String>, span: Span) -> Self {
        ParsedField {
            name: name.into(),
            raw_value: raw_value.into(),
            span,
        }
    }
}

// ─────────────────────────────────────────────
// ParserResult
// ─────────────────────────────────────────────

/// The outcome of a successful parse.
///
/// The `raw_bytes` field preserves the original frame bytes so that the
/// evidence is never lost through parsing.  The `fields` list contains
/// structured key-value pairs extracted from those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserResult {
    /// Structured fields extracted from the record.
    pub fields: Vec<ParsedField>,
    /// ID of the parser that produced this result.
    pub parser_id: String,
    /// Version of the parser that produced this result.
    pub parser_version: ParserVersion,
    /// The original frame bytes, preserved verbatim.
    pub raw_bytes: Vec<u8>,
}

// ─────────────────────────────────────────────
// ParserError
// ─────────────────────────────────────────────

/// An error returned by a parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParserError {
    /// The record is not in the format this parser handles.
    ///
    /// The registry uses this to try the next candidate parser.
    Unsupported,

    /// The record claims to be in the expected format but contains structural
    /// errors that prevent extraction.
    Malformed(String),

    /// Parsing was aborted to protect against resource exhaustion (e.g. too
    /// many fields, nesting too deep).
    ResourceLimit(String),
}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParserError::Unsupported => write!(f, "record format not supported by this parser"),
            ParserError::Malformed(msg) => write!(f, "malformed record: {msg}"),
            ParserError::ResourceLimit(msg) => write!(f, "resource limit exceeded: {msg}"),
        }
    }
}

impl std::error::Error for ParserError {}

// ─────────────────────────────────────────────
// Parser trait
// ─────────────────────────────────────────────

/// A parser that interprets a [`FramedRecord`] and extracts structured fields.
///
/// # Contract
///
/// - A parser must return [`ParserError::Unsupported`] when the record is not
///   in its expected format.  This allows the registry to try other parsers.
/// - A parser must never modify the `raw_bytes` of the record.
/// - A parser must return the original `raw_bytes` inside [`ParserResult`].
/// - A parser must be deterministic: the same input always produces the same
///   output.
pub trait Parser: Send + Sync {
    /// Static metadata describing this parser.
    fn metadata(&self) -> &ParserMetadata;

    /// Attempt to parse a framed record.
    ///
    /// Returns `Ok(ParserResult)` on success, or an appropriate
    /// [`ParserError`] on failure.
    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError>;
}

// ─────────────────────────────────────────────
// RegistryError
// ─────────────────────────────────────────────

/// Errors produced by the [`ParserRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// A parser with the same ID is already registered.
    DuplicateParser(String),
    /// No parser with the requested ID exists.
    NotFound(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::DuplicateParser(id) => {
                write!(f, "parser already registered: '{id}'")
            }
            RegistryError::NotFound(id) => write!(f, "parser not found: '{id}'"),
        }
    }
}

impl std::error::Error for RegistryError {}

// ─────────────────────────────────────────────
// ParserRegistry
// ─────────────────────────────────────────────

/// Registry that maps parser IDs to parser implementations.
///
/// Registration order is preserved for deterministic iteration.  Duplicate
/// IDs are rejected with [`RegistryError::DuplicateParser`] so that two
/// parsers cannot silently claim the same identity.
pub struct ParserRegistry {
    /// Parsers stored in insertion order (for deterministic dispatch).
    order: Vec<String>,
    parsers: HashMap<String, (Box<dyn Parser + Send + Sync>, LifecycleStage)>,
}

impl ParserRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        ParserRegistry {
            order: Vec::new(),
            parsers: HashMap::new(),
        }
    }

    /// Register a parser at the given lifecycle stage.
    ///
    /// Returns [`RegistryError::DuplicateParser`] if a parser with the same ID
    /// is already present.
    pub fn register(
        &mut self,
        parser: Box<dyn Parser + Send + Sync>,
        stage: LifecycleStage,
    ) -> Result<(), RegistryError> {
        let id = parser.metadata().id.clone();
        if self.parsers.contains_key(&id) {
            return Err(RegistryError::DuplicateParser(id));
        }
        self.order.push(id.clone());
        self.parsers.insert(id, (parser, stage));
        Ok(())
    }

    /// Retrieve a parser by its ID.
    pub fn get(&self, id: &str) -> Option<&(dyn Parser + Send + Sync)> {
        self.parsers.get(id).map(|(p, _)| p.as_ref())
    }

    /// Lifecycle stage of a registered parser.
    pub fn stage(&self, id: &str) -> Option<LifecycleStage> {
        self.parsers.get(id).map(|(_, s)| *s)
    }

    /// Number of registered parsers.
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Returns `true` if no parsers are registered.
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Try each registered parser in insertion order and return the first
    /// successful parse result.
    ///
    /// If a parser recognizes the format but the record is malformed, or if a
    /// resource limit is exceeded, that error is returned immediately and
    /// subsequent parsers are not tried.
    ///
    /// Returns `Err(ParserError::Unsupported)` if no registered parser could
    /// handle the record.
    pub fn parse_first(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        for id in &self.order {
            if let Some((parser, _)) = self.parsers.get(id) {
                match parser.parse(record) {
                    Ok(result) => return Ok(result),
                    Err(ParserError::Unsupported) => continue,
                    Err(err) => return Err(err),
                }
            }
        }
        Err(ParserError::Unsupported)
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}
