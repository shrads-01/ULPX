//! ulpx-core library — core primitives.
//!
//! # Module overview
//!
//! - [`event`] — Core event model: `EventId`, `RawEvent`, `Source`, etc.
//! - [`storage`] — Lossless evidence store abstraction.
//! - [`framing`] — Universal framing: splits raw bytes into framed records.
//! - [`parser`] — Parser runtime: registry, traits, and built-in parsers.

pub mod event;
pub mod framing;
pub mod integrity;
pub mod parser;
pub mod storage;
