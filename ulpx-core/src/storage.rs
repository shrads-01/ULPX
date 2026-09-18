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

use crate::integrity::{compute_hash, IntegrityMetadata};

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

use crate::event::{EventMetadata, Source, Timestamp};
use crate::integrity::ContentHash;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

/// Persistent local evidence store implementation.
pub struct LocalEvidenceStore {
    file: Mutex<File>,
    index: HashMap<EventId, u64>,
    last_event_id: Option<EventId>,
}

impl LocalEvidenceStore {
    const MAGIC: &'static [u8; 4] = b"ULPX";

    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut index = HashMap::new();
        let mut last_event_id = None;

        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;

        loop {
            let offset = file.stream_position()?;
            if offset >= file_len {
                break;
            }

            let mut header = [0u8; 8];
            if file.read_exact(&mut header).is_err() {
                break;
            }
            if &header[0..4] != Self::MAGIC {
                break;
            }

            let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as u64;
            if offset + 8 + len > file_len {
                break;
            }

            let mut payload = vec![0u8; len as usize];
            if file.read_exact(&mut payload).is_err() {
                break;
            }

            if let Some(event) = Self::deserialize_event(&payload) {
                index.insert(event.metadata.event_id.clone(), offset);
                last_event_id = Some(event.metadata.event_id);
            } else {
                break;
            }
        }

        let safe_end = file.stream_position()?;
        file.set_len(safe_end)?;

        Ok(Self {
            file: Mutex::new(file),
            index,
            last_event_id,
        })
    }

    fn serialize_event(event: &RawEvent) -> Vec<u8> {
        let mut out = Vec::new();

        let id_bytes = event.metadata.event_id.as_str().as_bytes();
        out.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(id_bytes);

        out.extend_from_slice(&event.metadata.ingestion_timestamp.0.to_be_bytes());

        let src_bytes = event.metadata.source.0.as_bytes();
        out.extend_from_slice(&(src_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(src_bytes);

        if let Some(ref integrity) = event.metadata.integrity {
            out.push(1);
            out.extend_from_slice(&integrity.content_hash.0);
            if let Some(ref prev) = integrity.previous_link {
                out.push(1);
                let prev_bytes = prev.as_str().as_bytes();
                out.extend_from_slice(&(prev_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(prev_bytes);
            } else {
                out.push(0);
            }
        } else {
            out.push(0);
        }

        let raw = event.as_bytes();
        out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        out.extend_from_slice(raw);

        out
    }

    fn deserialize_event(mut data: &[u8]) -> Option<RawEvent> {
        fn read_u32(data: &mut &[u8]) -> Option<u32> {
            if data.len() < 4 {
                return None;
            }
            let val = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            *data = &data[4..];
            Some(val)
        }
        fn read_bytes<'a>(data: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
            if data.len() < len {
                return None;
            }
            let bytes = &data[..len];
            *data = &data[len..];
            Some(bytes)
        }

        let id_len = read_u32(&mut data)?;
        let id_str = std::str::from_utf8(read_bytes(&mut data, id_len as usize)?).ok()?;
        let event_id = EventId::new(id_str).ok()?;

        if data.len() < 16 {
            return None;
        }
        let mut ts_buf = [0u8; 16];
        ts_buf.copy_from_slice(&data[..16]);
        data = &data[16..];
        let timestamp = Timestamp(u128::from_be_bytes(ts_buf));

        let src_len = read_u32(&mut data)?;
        let source = Source(
            std::str::from_utf8(read_bytes(&mut data, src_len as usize)?)
                .ok()?
                .to_owned(),
        );

        if data.is_empty() {
            return None;
        }
        let has_integrity = data[0];
        data = &data[1..];
        if has_integrity != 0 && has_integrity != 1 {
            return None;
        }

        let integrity = if has_integrity == 1 {
            let hash_bytes = read_bytes(&mut data, 32)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(hash_bytes);

            if data.is_empty() {
                return None;
            }
            let has_prev = data[0];
            data = &data[1..];
            if has_prev != 0 && has_prev != 1 {
                return None;
            }

            let previous_link = if has_prev == 1 {
                let prev_len = read_u32(&mut data)?;
                let prev_str =
                    std::str::from_utf8(read_bytes(&mut data, prev_len as usize)?).ok()?;
                Some(EventId::new(prev_str).ok()?)
            } else {
                None
            };
            Some(IntegrityMetadata {
                content_hash: ContentHash(h),
                previous_link,
            })
        } else {
            None
        };

        let raw_len = read_u32(&mut data)?;
        let raw_bytes = read_bytes(&mut data, raw_len as usize)?.to_vec();

        if !data.is_empty() {
            return None;
        }

        let metadata = EventMetadata {
            event_id,
            ingestion_timestamp: timestamp,
            source,
            integrity,
        };

        Some(RawEvent::from_parts(metadata, raw_bytes))
    }
}

impl EvidenceStore for LocalEvidenceStore {
    fn store(&mut self, mut event: RawEvent) -> Result<(), StoreError> {
        if self.index.contains_key(&event.metadata.event_id) {
            return Err(StoreError::DuplicateId);
        }

        let hash = compute_hash(event.as_bytes());
        let integrity = IntegrityMetadata::new(hash, self.last_event_id.clone());
        event.metadata.integrity = Some(integrity);

        let mut file = self
            .file
            .lock()
            .map_err(|_| StoreError::Internal("Lock poisoned".into()))?;
        let offset = file
            .seek(SeekFrom::End(0))
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        let payload = Self::serialize_event(&event);
        let mut record = Vec::with_capacity(8 + payload.len());
        record.extend_from_slice(Self::MAGIC);
        record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        record.extend_from_slice(&payload);

        file.write_all(&record)
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        file.sync_data()
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        self.index.insert(event.metadata.event_id.clone(), offset);
        self.last_event_id = Some(event.metadata.event_id.clone());

        Ok(())
    }

    fn retrieve(&self, id: &EventId) -> Result<RawEvent, StoreError> {
        let offset = self.index.get(id).ok_or(StoreError::NotFound)?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| StoreError::Internal("Lock poisoned".into()))?;

        let file_len = file
            .metadata()
            .map_err(|e| StoreError::Internal(e.to_string()))?
            .len();
        if *offset >= file_len {
            return Err(StoreError::Internal("Offset beyond file bounds".into()));
        }

        file.seek(SeekFrom::Start(*offset))
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        let mut header = [0u8; 8];
        file.read_exact(&mut header)
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        if &header[0..4] != Self::MAGIC {
            return Err(StoreError::Internal("Corrupted record".into()));
        }

        let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as u64;
        if *offset + 8 + len > file_len {
            return Err(StoreError::Internal(
                "Corrupted length exceeds file bounds".into(),
            ));
        }

        let mut payload = vec![0u8; len as usize];
        file.read_exact(&mut payload)
            .map_err(|e| StoreError::Internal(e.to_string()))?;

        Self::deserialize_event(&payload)
            .ok_or_else(|| StoreError::Internal("Malformed record".into()))
    }
}
