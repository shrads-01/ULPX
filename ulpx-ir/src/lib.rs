//! Universal Log Processing Intermediate Representation (ULPX-IR).
//!
//! This crate provides the canonical, typed intermediate representation for ULPX.
//! It acts as the bridge between format-specific parsing (`ulpx_core::parser`)
//! and semantic normalization.

pub mod convert;
pub mod model;
