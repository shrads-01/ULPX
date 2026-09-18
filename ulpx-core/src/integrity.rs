use crate::event::EventId;
use sha2::{Digest, Sha256};
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
}

impl VerificationResult {
    pub fn is_success(&self) -> bool {
        matches!(self, VerificationResult::Success)
    }
}
