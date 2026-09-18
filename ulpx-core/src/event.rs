//! Core event model for ULPX.
//!
//! Provides the minimal set of types to represent an incoming event while
//! preserving the raw bytes exactly.

use std::fmt::{self, Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can arise during core event model construction.
#[derive(Debug)]
pub enum EventError {
    /// The supplied event ID string is empty.
    EmptyEventId,
}

impl Display for EventError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EventError::EmptyEventId => write!(f, "event ID cannot be empty"),
        }
    }
}

impl std::error::Error for EventError {}

/// Unique identifier for an event. The inner string is private to enforce the
/// non‑empty invariant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventId(String);

impl EventId {
    /// Creates a new EventId after validating that the supplied string is not empty.
    pub fn new<S: Into<String>>(value: S) -> Result<Self, EventError> {
        let s = value.into();
        if s.is_empty() {
            Err(EventError::EmptyEventId)
        } else {
            Ok(EventId(s))
        }
    }

    /// Returns a reference to the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Source of an event (e.g., filename, socket). No validation required in Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Source(pub String);

/// Timestamp with nanosecond precision since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u128); // nanoseconds since UNIX_EPOCH

impl Timestamp {
    /// Returns the current system time with nanosecond precision.
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp(dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128)
    }
}

/// Core metadata attached to every event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMetadata {
    pub event_id: EventId,
    pub ingestion_timestamp: Timestamp,
    pub source: Source,
    pub integrity: Option<crate::integrity::IntegrityMetadata>,
}

/// Raw event storing the original bytes exactly, without any transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    pub metadata: EventMetadata,
    raw_bytes: Vec<u8>, // private – never mutated after construction
}

impl RawEvent {
    /// Constructs a new RawEvent. Empty raw_bytes is allowed.
    pub(crate) fn from_parts(metadata: EventMetadata, raw_bytes: Vec<u8>) -> Self {
        RawEvent {
            metadata,
            raw_bytes,
        }
    }

    /// Constructs a new RawEvent. Empty raw_bytes is allowed.
    pub fn new(event_id: EventId, raw_bytes: Vec<u8>, source: Source) -> Self {
        let metadata = EventMetadata {
            event_id,
            ingestion_timestamp: Timestamp::now(),
            source,
            integrity: None,
        };
        RawEvent {
            metadata,
            raw_bytes,
        }
    }

    /// Read‑only view of the stored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Consumes the event and returns ownership of the stored bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw_bytes
    }

    pub fn tamper_bytes(&mut self, new_bytes: Vec<u8>) {
        self.raw_bytes = new_bytes;
    }
}

/// Stable identifier for an event. Currently a thin wrapper around EventId.
/// Future phases will enrich this with additional identity logic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventIdentity {
    pub event_id: EventId,
}
