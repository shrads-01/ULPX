use crate::lab::ValidationReport;
use ulpx_core::parser::{LifecycleStage, Parser};

/// Represents a parser candidate that has successfully passed all ParserLab tests.
pub struct ValidatedCandidate {
    parser: Box<dyn Parser + Send + Sync>,
    report: ValidationReport,
}

impl ValidatedCandidate {
    /// Constructs a ValidatedCandidate if and only if the validation report is fully successful.
    pub fn new(
        parser: Box<dyn Parser + Send + Sync>,
        report: ValidationReport,
    ) -> Result<Self, &'static str> {
        if !report.is_fully_valid() {
            return Err("Cannot transition to ValidatedCandidate: Validation failed");
        }
        Ok(Self { parser, report })
    }

    /// Explicit human approval transition. Only a ValidatedCandidate can be approved.
    pub fn approve(self) -> PromotedParser {
        PromotedParser {
            parser: self.parser,
            stage: LifecycleStage::Approved,
        }
    }

    pub fn report(&self) -> &ValidationReport {
        &self.report
    }
}

/// A parser that has been validated and explicitly approved for production use.
pub struct PromotedParser {
    pub parser: Box<dyn Parser + Send + Sync>,
    pub stage: LifecycleStage,
}
