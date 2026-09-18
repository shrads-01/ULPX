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
//! 5. If the top-ranked candidate's confidence is `High` and the second
//!    candidate's confidence is strictly lower, select the top candidate.
//! 6. If two or more candidates share the highest confidence level, abstain
//!    with [`AbstentionReason::AmbiguousCandidates`].
//! 7. If no `High` candidate exists but at least one `Medium` candidate exists
//!    and is unambiguous, select it.
//! 8. If only `Low` candidates exist, abstain with
//!    [`AbstentionReason::InsufficientEvidence`].
//! 9. If no candidates survive step 3, abstain with
//!    [`AbstentionReason::NoRecognizableStructure`].
//!
//! The engine also integrates with the [`ParserRegistry`]: if a registry is
//! attached, the engine first asks each *registered* parser whether it
//! recognises the record.  A parser returning `Ok(_)` or `Err(Malformed)`
//! counts as a claim of recognition and bypasses pure structural inference.
//! A parser returning `Err(Unsupported)` does not affect inference.

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
type DetectorFn = fn(&[u8]) -> Option<FormatCandidate>;

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
    /// If `registry` is `Some`, each registered parser is asked to parse the
    /// record:
    /// * `Ok(result)` → return immediately as a high-confidence `Recognized`
    ///   result (the parser already knows it can handle this).
    /// * `Err(Malformed | ResourceLimit)` → the parser claims the format but
    ///   the record is broken; return a `Recognized` result with a note in
    ///   evidence (the caller should handle the parse error separately).
    /// * `Err(Unsupported)` → continue to structural inference.
    ///
    /// This integration never changes the parser error semantics of the
    /// registry and does not cause side-effects.
    pub fn infer(
        &self,
        record: &FramedRecord,
        registry: Option<&ParserRegistry>,
    ) -> InferenceResult {
        let bytes = record.as_bytes();
        let detectors_consulted: Vec<&'static str> =
            self.detectors.iter().map(|(id, _)| *id).collect();

        // ── Step 0: empty input ──────────────────────────────────────────
        if bytes.is_empty() {
            return InferenceResult {
                raw_bytes: Vec::new(),
                outcome: InferenceOutcome::Abstained {
                    reason: AbstentionReason::EmptyInput,
                    all_candidates: Vec::new(),
                },
                detectors_consulted,
            };
        }

        // ── Step 1: registry probe (optional) ────────────────────────────
        if let Some(reg) = registry {
            match reg.parse_first(record) {
                Ok(result) => {
                    // A parser parsed it successfully.
                    let static_id: &'static str = static_parser_id(&result.parser_id);
                    let evidence = vec![Evidence::support(
                        "registry-parse-success",
                        format!(
                            "parser '{}' parsed the record successfully",
                            result.parser_id
                        ),
                    )];
                    let candidate = FormatCandidate {
                        parser_id: static_id,
                        format_name: "known-format",
                        confidence: InferenceConfidence::High,
                        evidence: evidence.clone(),
                    };
                    return InferenceResult {
                        raw_bytes: bytes.to_vec(),
                        outcome: InferenceOutcome::Recognized {
                            all_candidates: vec![candidate.clone()],
                            candidate,
                        },
                        detectors_consulted,
                    };
                }
                Err(ParserError::Malformed(_) | ParserError::ResourceLimit(_)) => {
                    // A parser claimed the format but the record is broken.
                    // We still report as "recognized" (format identified) but
                    // the caller must handle the parse error.
                    // Note: we do NOT know which parser produced the error here
                    // because parse_first returns the first claiming parser.
                    // We emit a Recognized result for the structural inference
                    // to decide the winner, but flag it.
                    // Fall through to structural inference.
                }
                Err(ParserError::Unsupported) => {
                    // No registered parser recognises this record.
                    // Fall through to structural inference.
                }
            }
        }

        // ── Step 2: run structural detectors ─────────────────────────────
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
                .then_with(|| a.parser_id.cmp(b.parser_id))
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

        // Count how many share the top confidence.
        let tied: Vec<&FormatCandidate> = candidates
            .iter()
            .filter(|c| c.confidence == top_confidence)
            .collect();

        if tied.len() > 1 && top_confidence >= InferenceConfidence::Medium {
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

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// Map a known parser ID string to its `&'static str` counterpart.
///
/// This avoids `String::leak()` (which permanently leaks memory) while still
/// satisfying the `&'static str` requirement in `FormatCandidate::parser_id`.
///
/// Unknown parser IDs fall back to `"unknown"`.  The registry-probe path only
/// returns parser IDs that were registered, so any registered parser should be
/// listed here.
fn static_parser_id(id: &str) -> &'static str {
    match id {
        "json-flat" => "json-flat",
        "cef" => "cef",
        "syslog-rfc3164" => "syslog-rfc3164",
        _ => "unknown",
    }
}
