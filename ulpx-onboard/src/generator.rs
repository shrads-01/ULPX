//! Parser generation entry point.

use crate::parser::GeneratedParser;
use crate::spec::{ParserSpec, SpecValidationError};
use ulpx_core::parser::Parser;

/// Factory for generating real parser implementations from specifications.
pub struct ParserGenerator;

impl ParserGenerator {
    /// Validates the provided specification and produces a boxed parser that
    /// can be registered with `ParserRegistry`.
    pub fn build(spec: ParserSpec) -> Result<Box<dyn Parser + Send + Sync>, SpecValidationError> {
        spec.validate()?;
        Ok(Box::new(GeneratedParser::new(spec)))
    }
}
