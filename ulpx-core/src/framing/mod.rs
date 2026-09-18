//! Universal framing layer for ULPX.
//!
//! # Architectural boundary
//!
//! **Framing** is responsible solely for determining record boundaries within a
//! raw byte stream and preserving the original bytes of each framed record.
//! It does **not** interpret semantic fields; that is the responsibility of the
//! **parsing** layer.
//!
//! # Design
//!
//! The [`Framer`] trait accepts a complete byte slice and returns:
//! - a `Vec<FramedRecord>` containing every complete record found, each
//!   preserving exact frame bytes, and
//! - an `Option<FrameError>` describing any trailing incomplete or malformed
//!   data.  `None` means the entire input was cleanly consumed.
//!
//! Returning the error separately (rather than stopping at the first bad record)
//! allows callers to quarantine trailing garbage while still processing the
//! successfully framed records that preceded it.
//!
//! # Implementations
//!
//! | Module | Strategy |
//! |---|---|
//! | [`newline`] | Newline-delimited records (`\n` or `\r\n`) |
//! | [`length_prefix`] | 4-byte big-endian length-prefixed records |
//! | [`json_object`] | Top-level JSON object boundaries (`{…}`) |

pub mod json_object;
pub mod length_prefix;
pub mod newline;

use std::fmt;
use std::ops::Range;

/// Maximum frame size accepted by all built-in framers (64 MiB).
///
/// Framing a record that exceeds this limit yields
/// [`FrameError::OversizedFrame`].  This limit exists to prevent a single
/// maliciously crafted record from exhausting process memory.
pub const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

// ─────────────────────────────────────────────
// FramedRecord
// ─────────────────────────────────────────────

/// A single framed record with its exact original bytes preserved.
///
/// The bytes stored here are the verbatim octets belonging to this record as
/// they appeared in the input stream, including any framing delimiters that
/// are semantically part of the record (e.g. the length prefix bytes are
/// *not* included; the payload bytes are).  Newline terminators are stripped
/// because the newline is a framing delimiter, not record content — but the
/// choice is documented per-framer.
///
/// The original bytes are intentionally private to ensure they cannot be
/// modified after framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedRecord {
    raw_bytes: Vec<u8>,
    byte_range: Option<Range<usize>>,
}

impl FramedRecord {
    /// Constructs a `FramedRecord` preserving the supplied bytes exactly.
    pub fn new(raw_bytes: Vec<u8>) -> Self {
        FramedRecord {
            raw_bytes,
            byte_range: None,
        }
    }

    /// Creates a new `FramedRecord` while retaining its original slice boundary mapping.
    pub fn with_byte_range(raw_bytes: Vec<u8>, range: Range<usize>) -> Self {
        Self {
            raw_bytes,
            byte_range: Some(range),
        }
    }

    /// Returns a reference to the framed payload representation.
    ///
    /// This represents the logic-specific framing payload (e.g., stripping network
    /// headers or line delimiters) which is passed to parsers. It does NOT always
    /// reflect the exact original source bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Returns the exact original source-buffer byte range, if available.
    ///
    /// When populated, this range corresponds to the exact sequence of bytes in the
    /// `input` slice passed to `Framer::frame_all()`. This enables lossless preservation
    /// of the original telemetry (including delimiters or transport headers).
    pub fn byte_range(&self) -> Option<Range<usize>> {
        self.byte_range.clone()
    }

    /// Consumes the record and returns ownership of the frame bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw_bytes
    }

    /// Number of bytes in this record.
    pub fn len(&self) -> usize {
        self.raw_bytes.len()
    }

    /// Returns `true` if the frame contains zero bytes.
    ///
    /// # Semantics
    ///
    /// Whether an empty frame is valid depends on the framing strategy.
    /// Newline-delimited framing produces empty frames for blank lines; callers
    /// may filter them if desired, but the framer itself does not silently drop
    /// them.
    pub fn is_empty(&self) -> bool {
        self.raw_bytes.is_empty()
    }
}

// ─────────────────────────────────────────────
// FrameError
// ─────────────────────────────────────────────

/// An error produced by a framer when a record boundary cannot be determined
/// cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The input ended before a complete record was found.
    ///
    /// The caller should buffer the remaining bytes and retry with more data,
    /// or treat the remainder as a final partial record.
    Incomplete,

    /// The byte stream contains data that violates the framing format.
    ///
    /// The description explains what was found.  The bytes that caused the
    /// error are not recoverable through this error variant; the caller should
    /// arrange to quarantine or log the raw input before framing.
    Malformed(String),

    /// A single record exceeds [`MAX_FRAME_BYTES`].
    ///
    /// Parsing is refused to prevent resource exhaustion from a maliciously
    /// large record.
    OversizedFrame(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Incomplete => {
                write!(f, "incomplete frame: input ended before record boundary")
            }
            FrameError::Malformed(msg) => write!(f, "malformed frame: {msg}"),
            FrameError::OversizedFrame(size) => write!(
                f,
                "frame too large: {size} bytes exceeds limit of {MAX_FRAME_BYTES}"
            ),
        }
    }
}

impl std::error::Error for FrameError {}

// ─────────────────────────────────────────────
// Framer trait
// ─────────────────────────────────────────────

/// Trait for implementations that split a raw byte slice into framed records.
///
/// # Contract
///
/// - Every byte consumed from `input` must appear in exactly one
///   [`FramedRecord`] or be accounted for by the returned [`FrameError`].
/// - The implementation must never silently discard bytes.
/// - Each [`FramedRecord`] preserves the exact bytes belonging to that record.
/// - When `input` is empty, implementations must return an empty `Vec` and
///   `None`.
pub trait Framer: Send + Sync {
    /// Frame all complete records in `input`.
    ///
    /// Returns:
    /// - all complete [`FramedRecord`]s found in `input`, in order, and
    /// - `Some(FrameError)` if trailing bytes could not form a complete record
    ///   (`Incomplete`) or contained unrecoverable format violations
    ///   (`Malformed` / `OversizedFrame`), or `None` if the input was cleanly
    ///   consumed.
    fn frame_all(&self, input: &[u8]) -> (Vec<FramedRecord>, Option<FrameError>);
}
