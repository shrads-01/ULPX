//! The inference engine: aggregates detector output and produces a final
//! [`InferenceResult`].
//!
//! # Dispatch policy
//!
//! 1. Run all registered detectors in deterministic order.
//! 2. Collect every [`FormatCandidate`] returned.
//! 3. Drop candidates whose `net_support` is ≤ 0.
//! 4. Sort remaining candidates: descending confidence, then alphabetical
//!    `parser_id` as tiebreaker (guarantees determinism).
//! 5. If the top-ranked candidate's confidence is `High` and no second
//!    candidate shares that confidence level, select the top candidate.
//! 6. If two or more candidates share the highest confidence level (≥ Medium),
//!    abstain with [`AbstentionReason::AmbiguousCandidates`].
//! 7. If no `High` candidate exists but at least one unambiguous `Medium`
//!    candidate exists, select it.
//! 8. If only `Low` candidates exist, abstain with
//!    [`AbstentionReason::InsufficientEvidence`].
//! 9. If no candidates survive step 3, abstain with
//!    [`AbstentionReason::NoRecognizableStructure`].
//!
//! # Registry integration
//!
//! If a [`ParserRegistry`] is supplied, the engine probes it **before** running
//! structural detectors.  The probe is read-only and does not change the
//! registry or the parser error semantics.
//!
//! * `Ok(result)` — the parser successfully parsed the record.  The exact
//!   parser ID (from `result.parser_id`) is preserved in the candidate, so
//!   provenance is complete even for dynamically registered parsers.
//! * `Err(Malformed | ResourceLimit)` — some parser recognised the format but
//!   the specific record is broken.  The engine falls through to structural
//!   inference so the format can still be identified for the audit trail.  The
//!   caller is responsible for re-running the parser and handling the error.
//! * `Err(Unsupported)` — no registered parser recognised the record.  Fall
//!   through to structural inference.

use crate::evidence::{detect_cef, detect_json, detect_syslog};
use crate::model::{
    AbstentionReason, Evidence, FormatCandidate, InferenceConfidence, InferenceOutcome,
    InferenceResult,
};
use ulpx_core::framing::FramedRecord;
use ulpx_core::parser::{ParserError, ParserRegistry};

// ─────────────────────────────────────────────
// Detector function type
// ─────────────────────────────────────────────

/// A structural detector: a function from bytes to an optional candidate.
///
/// Detectors must be deterministic, non-modifying, independent, and bounded.
pub type DetectorFn = fn(&[u8]) -> Option<FormatCandidate>;

// ─────────────────────────────────────────────
// InferenceEngine
// ─────────────────────────────────────────────

/// The inference engine with its registered detectors.
///
/// Build with [`InferenceEngine::default()`] for the built-in detectors, or
/// [`InferenceEngine::new()`] plus [`InferenceEngine::add_detector()`] for a
/// custom configuration.
pub struct InferenceEngine {
    /// Detectors in deterministic registration order.
    detectors: Vec<(&'static str, DetectorFn)>,
}

impl InferenceEngine {
    /// Create an empty engine (no detectors).
    pub fn new() -> Self {
        InferenceEngine {
            detectors: Vec::new(),
        }
    }

    /// Register a structural detector.
    ///
    /// `id` must be unique within this engine and is used in the audit trail.
    /// Registration order determines the order detectors are consulted, which
    /// affects the `detectors_consulted` field of [`InferenceResult`] but NOT
    /// the final candidate ranking (which is deterministic on confidence).
    pub fn add_detector(&mut self, id: &'static str, f: DetectorFn) {
        self.detectors.push((id, f));
    }

    /// Create an engine with the built-in detectors pre-registered.
    pub fn with_defaults() -> Self {
        let mut e = Self::new();
        e.add_detector("json", detect_json);
        e.add_detector("cef", detect_cef);
        e.add_detector("syslog", detect_syslog);
        e
    }

    /// Run inference on a [`FramedRecord`], optionally consulting a
    /// [`ParserRegistry`] for direct parser feedback first.
    ///
    /// The raw bytes in the returned [`InferenceResult`] are always a copy of
    /// the input bytes and are never modified.
    pub fn infer(
        &self,
        record: &FramedRecord,
        registry: Option<&ParserRegistry>,
    ) -> InferenceResult {
        let bytes = record.as_bytes();

        // detectors_consulted reflects what was *actually* consulted.
        // On the fast-path (registry success) structural detectors are not run,
        // so we build this list lazily.

        // ── Step 0: empty input ──────────────────────────────────────────
        if bytes.is_empty() {
            return InferenceResult {
                raw_bytes: Vec::new(),
                outcome: InferenceOutcome::Abstained {
                    reason: AbstentionReason::EmptyInput,
                    all_candidates: Vec::new(),
                },
                detectors_consulted: Vec::new(),
            };
        }

        // ── Step 1: registry probe (optional) ────────────────────────────
        if let Some(reg) = registry {
            match reg.parse_first(record) {
                Ok(result) => {
                    // A registered parser successfully parsed the record.
                    // Use the exact parser ID from the result — no hardcoded table.
                    let evidence = vec![Evidence::support(
                        "registry-parse-success",
                        format!(
                            "parser '{}' parsed the record successfully",
                            result.parser_id
                        ),
                    )];
                    let candidate = FormatCandidate {
                        parser_id: result.parser_id.clone(),
                        format_name: result.parser_id.clone(), // parser ID is the canonical name
                        confidence: InferenceConfidence::High,
                        evidence,
                    };
                    return InferenceResult {
                        raw_bytes: bytes.to_vec(),
                        outcome: InferenceOutcome::Recognized {
                            all_candidates: vec![candidate.clone()],
                            candidate,
                        },
                        // Only "registry" was consulted; structural detectors were not run.
                        detectors_consulted: vec!["registry"],
                    };
                }
                Err(ParserError::Malformed(_) | ParserError::ResourceLimit(_)) => {
                    // A parser claimed the format but this specific record is broken.
                    // The caller should re-parse and handle the error.
                    // Fall through to structural inference to identify the format
                    // so the audit trail is still complete.
                }
                Err(ParserError::Unsupported) => {
                    // No registered parser recognised this record.
                    // Fall through to structural inference.
                }
            }
        }

        // ── Step 2: run structural detectors ─────────────────────────────
        let detectors_consulted: Vec<&'static str> =
            self.detectors.iter().map(|(id, _)| *id).collect();

        let mut candidates: Vec<FormatCandidate> = self
            .detectors
            .iter()
            .filter_map(|(_, f)| f(bytes))
            .filter(|c| c.net_support() > 0)
            .collect();

        // ── Step 3: sort deterministically ───────────────────────────────
        // Primary: descending confidence; Secondary: ascending parser_id (alpha)
        candidates.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.parser_id.cmp(&b.parser_id))
        });

        // ── Step 4: decide outcome ────────────────────────────────────────
        if candidates.is_empty() {
            return InferenceResult {
                raw_bytes: bytes.to_vec(),
                outcome: InferenceOutcome::Abstained {
                    reason: AbstentionReason::NoRecognizableStructure,
                    all_candidates: Vec::new(),
                },
                detectors_consulted,
            };
        }

        let top_confidence = candidates[0].confidence;

        // Count how many candidates share the top confidence.
        let tie_count = candidates
            .iter()
            .filter(|c| c.confidence == top_confidence)
            .count();

        if tie_count > 1 && top_confidence >= InferenceConfidence::Medium {
            // Ambiguous: multiple candidates at Medium or High confidence.
            return InferenceResult {
                raw_bytes: bytes.to_vec(),
                outcome: InferenceOutcome::Abstained {
                    reason: AbstentionReason::AmbiguousCandidates,
                    all_candidates: candidates,
                },
                detectors_consulted,
            };
        }

        if top_confidence == InferenceConfidence::Low {
            return InferenceResult {
                raw_bytes: bytes.to_vec(),
                outcome: InferenceOutcome::Abstained {
                    reason: AbstentionReason::InsufficientEvidence,
                    all_candidates: candidates,
                },
                detectors_consulted,
            };
        }

        // Single unambiguous winner at Medium or High confidence.
        let winner = candidates[0].clone();
        InferenceResult {
            raw_bytes: bytes.to_vec(),
            outcome: InferenceOutcome::Recognized {
                candidate: winner,
                all_candidates: candidates,
            },
            detectors_consulted,
        }
    }
}

impl Default for InferenceEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}
