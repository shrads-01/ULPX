//! Phase 9: Parser Onboarding and Generation.
//!
//! This crate provides a deterministic, offline mechanism for defining and
//! generating real parsers from a declarative specification.
//!
//! # Architecture
//!
//! - **[`ParserSpec`]**: A serializable, declarative specification of how to
//!   extract fields from a framed record.
//! - **[`ParserGenerator`]**: A factory that validates a `ParserSpec` and
//!   produces a boxed [`ulpx_core::parser::Parser`].
//! - **GeneratedParser**: The underlying implementation that honors the
//!   existing `ParserError` semantics (`Unsupported`, `Malformed`, `ResourceLimit`)
//!   and exactly preserves original evidence.
//!
//! Generated parsers are fully compatible with [`ulpx_core::parser::ParserRegistry`].
//!
//! # What is intentionally NOT implemented
//! - AI/LLM parser generation
//! - Network-based schema registries
//! - Persistent database storage for specifications (these are runtime artifacts)
//! - Advanced tree/nested format extraction (JSON is already natively handled, this focuses on flat delim/KV)

pub mod generator;
pub mod inference;
pub mod parser;
pub mod spec;
