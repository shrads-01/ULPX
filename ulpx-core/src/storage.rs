//! Evidence store abstraction. Duplicate EventIds are rejected rather than silently overwritten.
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use crate::event::{EventId, RawEvent};

/// Errors that can arise from the evidence storage layer.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The requested EventId does not exist in the store.
    NotFound,
    /// The EventId already exists in the store; insertion is rejected.
    DuplicateId,
    /// Generic internal error (e.g., out‑of‑memory).
    Internal(String),
}

impl Display for StoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::DuplicateId => write!(f, "duplicate event id"),
            StoreError::NotFound => write!(f, "event not found"),
            StoreError::Internal(msg) => write!(f, "storage error: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}

/// Trait defining the loss‑less evidence‑storage contract.
pub trait EvidenceStore {
    /// Store a `RawEvent`. The implementation must not modify the raw bytes
    /// or the associated `EventId`.
    fn store(&mut self, event: RawEvent) -> Result<(), StoreError>;

    /// Retrieve an event by its `EventId`. The returned `RawEvent` must be
    /// identical (byte‑for‑byte) to the one that was stored.
    fn retrieve(&self, id: &EventId) -> Result<RawEvent, StoreError>;
}

/// Simple in‑memory implementation used for the Phase 2 prototype.
#[derive(Default)]
pub struct InMemoryStore {
    map: HashMap<EventId, RawEvent>,
}

impl InMemoryStore {
    /// Create a new empty in‑memory store.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl EvidenceStore for InMemoryStore {
    fn store(&mut self, event: RawEvent) -> Result<(), StoreError> {
        // Reject insertion if the EventId already exists.
        if self.map.contains_key(&event.metadata.event_id) {
            return Err(StoreError::DuplicateId);
        }
        // Insert the new event.
        self.map.insert(event.metadata.event_id.clone(), event);
        Ok(())
    }

    fn retrieve(&self, id: &EventId) -> Result<RawEvent, StoreError> {
        self.map.get(id).cloned().ok_or(StoreError::NotFound)
    }
}
