//! Integration between inference results and parser generation.
//!
//! A real implementation would parse the evidence payload to dynamically infer schema
//! (e.g. delimiters or field names). In this phase, we map known generic structural
//! candidates directly to their declarative specs.

use crate::spec::{ExtractionSpec, ParserSpec};
use ulpx_core::parser::ParserVersion;
use ulpx_infer::model::{FormatCandidate, InferenceOutcome, InferenceResult};

/// Errors that occur during onboarding from inference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardError {
    /// The inference engine abstained, so no format can be onboarded.
    InferenceAbstained(String),
    /// The candidate format is not one we know how to generate a spec for.
    UnknownCandidate(String),
    /// We know the format, but evidence is missing crucial schema details (future).
    InsufficientSchemaEvidence,
}

impl std::fmt::Display for OnboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnboardError::InferenceAbstained(r) => {
                write!(f, "cannot onboard: inference abstained ({})", r)
            }
            OnboardError::UnknownCandidate(id) => {
                write!(f, "cannot generate spec for candidate: '{}'", id)
            }
            OnboardError::InsufficientSchemaEvidence => {
                write!(f, "candidate lacks schema evidence to generate spec")
            }
        }
    }
}

impl std::error::Error for OnboardError {}

/// Attempts to generate a `ParserSpec` from an `InferenceResult`.
pub fn derive_spec_from_inference(result: &InferenceResult) -> Result<ParserSpec, OnboardError> {
    let candidate = match &result.outcome {
        InferenceOutcome::Recognized { candidate, .. } => candidate,
        InferenceOutcome::Abstained { reason, .. } => {
            return Err(OnboardError::InferenceAbstained(reason.to_string()));
        }
    };

    derive_spec_from_candidate(candidate)
}

/// Attempts to generate a `ParserSpec` from a `FormatCandidate`.
pub fn derive_spec_from_candidate(candidate: &FormatCandidate) -> Result<ParserSpec, OnboardError> {
    // In a future phase, we would parse schema information out of candidate.evidence.
    // For Phase 9, we map specific candidate IDs to specs to demonstrate the pipeline.

    match candidate.parser_id.as_str() {
        "generic-kv-space-eq" => Ok(ParserSpec {
            parser_id: candidate.parser_id.clone(),
            description: "Automatically inferred Space/Equals Key-Value parser".to_string(),
            format_name: "Key-Value".to_string(),
            version: ParserVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            extraction: ExtractionSpec::KeyValue {
                pair_separator: ' ',
                kv_separator: '=',
            },
        }),
        "generic-csv-3col" => Ok(ParserSpec {
            parser_id: candidate.parser_id.clone(),
            description: "Automatically inferred 3-column CSV parser".to_string(),
            format_name: "CSV".to_string(),
            version: ParserVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            extraction: ExtractionSpec::Delimiter {
                separator: ',',
                field_names: vec!["col1".to_string(), "col2".to_string(), "col3".to_string()],
            },
        }),
        _ => Err(OnboardError::UnknownCandidate(candidate.parser_id.clone())),
    }
}
