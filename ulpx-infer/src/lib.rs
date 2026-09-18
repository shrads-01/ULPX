//! Phase 8 — Unknown-Format Inference for ULPX.
//!
//! This crate provides a deterministic, evidence-based inference subsystem
//! that analyses framed records of unknown format and produces structured
//! candidates and a final inference decision.
//!
//! # Architectural position
//!
//! ```text
//! RawEvent
//!    ↓ Framing
//! FramedRecord  ─── known parser? ──→ ParserResult → ULPX-IR → Mapping
//!    │                   │ no
//!    │                   ↓
//!    │         UnknownFormatInference
//!    │                   ↓
//!    │         InferenceResult (candidates + evidence)
//!    │                   ↓
//!    └─── recommended parser ID or Abstain
//! ```
//!
//! Inference **recommends** a parser; it does not parse.  The recommended
//! parser remains responsible for actually parsing the record.
//!
//! # Guarantees
//!
//! * Inference is **deterministic**: the same input always produces the same
//!   output.
//! * Inference **never modifies** the original framed bytes.
//! * When evidence is insufficient to distinguish candidates the engine
//!   **abstains** rather than guessing.
//! * All evidence is **explicit and inspectable**.

pub mod engine;
pub mod evidence;
pub mod model;
