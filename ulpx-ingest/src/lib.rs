use sha2::{Digest, Sha256};
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read};
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::framing::{FrameError, Framer};
use ulpx_core::storage::{EvidenceStore, StoreError};

pub mod kafka;

/// Errors that can occur during offline ingestion.
#[derive(Debug)]
pub enum IngestionError {
    /// An I/O error occurred while reading the input stream.
    Io(io::Error),
    /// The framer encountered an error (e.g., malformed or oversized record).
    Framing(FrameError),
    /// The storage layer encountered a critical error.
    /// Ingestion is record-wise (non-transactional). This error includes
    /// the number of records successfully stored before the failure occurred.
    Storage {
        err: StoreError,
        stored_records: usize,
    },
}

impl Display for IngestionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IngestionError::Io(err) => write!(f, "io error: {}", err),
            IngestionError::Framing(err) => write!(f, "framing error: {}", err),
            IngestionError::Storage {
                err,
                stored_records,
            } => write!(
                f,
                "storage error after {} successful stores: {}",
                stored_records, err
            ),
        }
    }
}

impl std::error::Error for IngestionError {}

impl From<io::Error> for IngestionError {
    fn from(err: io::Error) -> Self {
        IngestionError::Io(err)
    }
}

/// Generates a deterministic EventId for local offline ingestion.
///
/// # Policy
/// The EventId is a SHA-256 hash formatted as a hex string over:
/// `source_length (u32, big-endian) + source + index (u64, big-endian) + raw_bytes`
///
/// This policy guarantees stable IDs across identical ingestion runs, enabling
/// duplicate rejection semantics while correctly disambiguating identical records
/// within the same stream.
fn generate_event_id(source: &str, index: u64, raw_bytes: &[u8]) -> EventId {
    let mut hasher = Sha256::new();
    hasher.update((source.len() as u32).to_be_bytes());
    hasher.update(source.as_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(raw_bytes);
    let result = hasher.finalize();

    let mut hex = String::with_capacity(64);
    for byte in result {
        use std::fmt::Write;
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    EventId::new(hex).unwrap()
}

/// Result of a successful ingestion operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestionResult {
    /// Number of records successfully framed and processed.
    pub total_records: usize,
    /// Number of records that were actually appended (not duplicates).
    pub stored_records: usize,
}

/// Ingests a byte stream, frames it into records, and stores them in the provided `EvidenceStore`.
///
/// # Atomicity
/// Ingestion is **record-wise, not transactional**. If the `EvidenceStore` fails
/// mid-stream, the records stored up to that point remain in the store. The returned
/// `IngestionError::Storage` variant indicates how many records were successfully stored.
///
/// # Error Handling
/// The input stream is read entirely into memory and framed. If the framer detects any trailing
/// incomplete or malformed data, ingestion is aborted *before* any records are stored.
/// Duplicate events (where the same record was already ingested) are ignored securely.
pub fn ingest_stream<R: Read>(
    mut stream: R,
    source_name: &str,
    framer: &dyn Framer,
    store: &mut dyn EvidenceStore,
) -> Result<IngestionResult, IngestionError> {
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;
    ingest_buffer(&buffer, source_name, framer, store, 0)
}

/// Ingests an in-memory buffer, frames it into records, and stores them.
/// The `base_index` is used to ensure deterministic EventIds across multiple buffers
/// (e.g. from a streaming source).
pub fn ingest_buffer(
    buffer: &[u8],
    source_name: &str,
    framer: &dyn Framer,
    store: &mut dyn EvidenceStore,
    base_index: u64,
) -> Result<IngestionResult, IngestionError> {
    let (records, trailing_error) = framer.frame_all(buffer);

    // Fail clearly on malformed framing or incomplete records
    if let Some(err) = trailing_error {
        return Err(IngestionError::Framing(err));
    }

    let total_records = records.len();
    let mut stored_records = 0;

    for (i, record) in records.into_iter().enumerate() {
        let index = base_index + i as u64;
        let raw_bytes = if let Some(range) = record.byte_range() {
            match buffer.get(range) {
                Some(slice) => slice.to_vec(),
                None => {
                    return Err(IngestionError::Framing(FrameError::Malformed(format!(
                        "Framer returned out-of-bounds byte range: {:?}",
                        record.byte_range().unwrap()
                    ))));
                }
            }
        } else {
            record.into_bytes()
        };
        let event_id = generate_event_id(source_name, index, &raw_bytes);

        let raw_event = RawEvent::new(event_id, raw_bytes, Source(source_name.to_string()));

        match store.store(raw_event) {
            Ok(_) => {
                stored_records += 1;
            }
            Err(StoreError::DuplicateId) => {
                // Safely ignored, as per duplicate ID semantics.
            }
            Err(err) => {
                return Err(IngestionError::Storage {
                    err,
                    stored_records,
                })
            }
        }
    }

    Ok(IngestionResult {
        total_records,
        stored_records,
    })
}
