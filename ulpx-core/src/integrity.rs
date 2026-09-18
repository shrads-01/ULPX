use crate::event::EventId;
use crate::storage::{EvidenceStore, StoreError};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

/// Represents a SHA-256 hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Computes the SHA-256 hash of a byte slice.
pub fn compute_hash(data: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    ContentHash(hash)
}

/// Metadata about the integrity and lineage of an evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityMetadata {
    pub content_hash: ContentHash,
    pub previous_link: Option<EventId>,
}

impl IntegrityMetadata {
    pub fn new(content_hash: ContentHash, previous_link: Option<EventId>) -> Self {
        Self {
            content_hash,
            previous_link,
        }
    }
}

/// The result of an integrity verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The computed hash matches the stored hash, and linkage rules are satisfied.
    Success,
    /// The computed hash does not match the stored hash.
    HashMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
    /// The previous link is broken (e.g. not found in store, or expected but missing).
    BrokenLink(EventId),
    /// Integrity metadata is missing from the event.
    MissingMetadata(EventId),
    /// A cycle was detected in the previous_link chain.
    CyclicLink(EventId),
}

impl VerificationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, VerificationResult::Success)
    }
}

pub fn verify_event(
    store: &dyn EvidenceStore,
    id: &EventId,
) -> Result<VerificationResult, StoreError> {
    let event = store.retrieve(id)?;
    let metadata = match event.metadata.integrity.as_ref() {
        Some(m) => m,
        None => return Ok(VerificationResult::MissingMetadata(id.clone())),
    };

    let actual_hash = compute_hash(event.as_bytes());
    if actual_hash != metadata.content_hash {
        return Ok(VerificationResult::HashMismatch {
            expected: metadata.content_hash.clone(),
            actual: actual_hash,
        });
    }

    if let Some(prev_id) = &metadata.previous_link {
        if store.retrieve(prev_id).is_err() {
            return Ok(VerificationResult::BrokenLink(prev_id.clone()));
        }
    }

    Ok(VerificationResult::Success)
}

pub fn verify_chain(
    store: &dyn EvidenceStore,
    head_id: &EventId,
) -> Result<VerificationResult, StoreError> {
    let mut current_id = head_id.clone();
    let mut visited = HashSet::new();

    loop {
        if !visited.insert(current_id.clone()) {
            return Ok(VerificationResult::CyclicLink(current_id));
        }

        let result = verify_event(store, &current_id)?;
        if !result.is_success() {
            return Ok(result);
        }

        let event = store.retrieve(&current_id)?;
        let metadata = event.metadata.integrity.unwrap(); // Unwrapping is safe because verify_event succeeded
        match metadata.previous_link {
            Some(prev) => current_id = prev,
            None => break,
        }
    }
    Ok(VerificationResult::Success)
}
