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

use crate::integrity::{compute_hash, IntegrityMetadata, VerificationResult};

/// Simple in‑memory implementation used for the Phase 2 prototype.
#[derive(Default)]
pub struct InMemoryStore {
    map: HashMap<EventId, RawEvent>,
    last_event_id: Option<EventId>,
}

impl InMemoryStore {
    /// Create a new empty in‑memory store.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            last_event_id: None,
        }
    }

    /// Verifies the integrity of a stored event.
    /// Recomputes the hash from the raw bytes and compares it to the stored metadata.
    /// Also checks that the previous link exists in the store.
    pub fn verify(&self, id: &EventId) -> Result<VerificationResult, StoreError> {
        let event = self.retrieve(id)?;
        let metadata = event
            .metadata
            .integrity
            .as_ref()
            .expect("Event should have integrity metadata");

        let actual_hash = compute_hash(event.as_bytes());
        if actual_hash != metadata.content_hash {
            return Ok(VerificationResult::HashMismatch {
                expected: metadata.content_hash.clone(),
                actual: actual_hash,
            });
        }

        if let Some(prev_id) = &metadata.previous_link {
            if !self.map.contains_key(prev_id) {
                return Ok(VerificationResult::BrokenLink(prev_id.clone()));
            }
        }

        Ok(VerificationResult::Success)
    }

    /// Verifies an entire chain of events, walking backwards via `previous_link`.
    /// Returns `Ok(())` if the whole chain is valid, or the `VerificationResult` that failed.
    pub fn verify_chain(&self, head_id: &EventId) -> Result<VerificationResult, StoreError> {
        let mut current_id = head_id.clone();
        loop {
            let result = self.verify(&current_id)?;
            if !result.is_success() {
                return Ok(result);
            }

            let event = self.retrieve(&current_id)?;
            let metadata = event.metadata.integrity.unwrap();

            match metadata.previous_link {
                Some(prev) => current_id = prev,
                None => break, // Reached the beginning of the chain
            }
        }
        Ok(VerificationResult::Success)
    }

    /// Exposes a way to deliberately tamper with data for testing purposes.
    pub fn tamper_bytes(&mut self, id: &EventId, new_bytes: Vec<u8>) {
        if let Some(event) = self.map.get_mut(id) {
            event.tamper_bytes(new_bytes);
        }
    }

    pub fn remove_for_testing(&mut self, id: &EventId) {
        self.map.remove(id);
    }
}

impl EvidenceStore for InMemoryStore {
    fn store(&mut self, mut event: RawEvent) -> Result<(), StoreError> {
        // Reject insertion if the EventId already exists.
        if self.map.contains_key(&event.metadata.event_id) {
            return Err(StoreError::DuplicateId);
        }

        // Compute integrity hash and link
        let hash = compute_hash(event.as_bytes());
        let integrity = IntegrityMetadata::new(hash, self.last_event_id.clone());
        event.metadata.integrity = Some(integrity);

        self.last_event_id = Some(event.metadata.event_id.clone());

        // Insert the new event.
        self.map.insert(event.metadata.event_id.clone(), event);
        Ok(())
    }

    fn retrieve(&self, id: &EventId) -> Result<RawEvent, StoreError> {
        self.map.get(id).cloned().ok_or(StoreError::NotFound)
    }
}
