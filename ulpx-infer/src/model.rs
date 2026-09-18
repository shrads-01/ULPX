//! Inference data model — evidence, candidates, results, and abstention.

use std::fmt;

// ─────────────────────────────────────────────
// Evidence
// ─────────────────────────────────────────────

/// A single concrete observation used to support or reject a format candidate.
///
/// Evidence is always tied to a named rule/detector (`detector_id`) so the
/// inference audit trail is reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Short identifier for the detector that produced this evidence,
    /// e.g. `"json-object-delimiters"`, `"cef-header-prefix"`.
    pub detector_id: &'static str,
    /// Human-readable description of what was observed.
    pub description: String,
    /// Whether this observation supports (`true`) or contradicts (`false`)
    /// the associated format candidate.
    pub supports: bool,
}

impl Evidence {
    pub fn support(detector_id: &'static str, description: impl Into<String>) -> Self {
        Evidence {
            detector_id,
            description: description.into(),
            supports: true,
        }
    }

    pub fn contradict(detector_id: &'static str, description: impl Into<String>) -> Self {
        Evidence {
            detector_id,
            description: description.into(),
            supports: false,
        }
    }
}

// ─────────────────────────────────────────────
// InferenceConfidence
// ─────────────────────────────────────────────

/// Categorical confidence in an inference candidate.
///
/// These categories are explicitly designed so that downstream systems can
/// decide whether to attempt parsing without arbitrary numeric thresholds.
///
/// Ordering: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InferenceConfidence {
    /// Weak pattern matches only.  Evidence is insufficient for reliable
    /// parsing.  Human review or an alternate strategy is recommended.
    Low,
    /// The record has characteristics consistent with this format but some
    /// markers are absent or ambiguous.  Parsing should be attempted but
    /// the result must be validated.
    Medium,
    /// Multiple strong structural markers uniquely identify this format.
    /// A registered parser should be tried immediately.
    High,
}

impl fmt::Display for InferenceConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InferenceConfidence::High => write!(f, "High"),
            InferenceConfidence::Medium => write!(f, "Medium"),
            InferenceConfidence::Low => write!(f, "Low"),
        }
    }
}

// ─────────────────────────────────────────────
// FormatCandidate
// ─────────────────────────────────────────────

/// A hypothesis that a framed record belongs to a specific format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatCandidate {
    /// The parser ID this candidate maps to (e.g. `"json-flat"`, `"cef"`).
    pub parser_id: &'static str,
    /// Human-readable format name (e.g. `"JSON"`, `"CEF"`).
    pub format_name: &'static str,
    /// Confidence in this candidate.
    pub confidence: InferenceConfidence,
    /// All evidence observations that led to this candidate, in the order they
    /// were collected.  Deterministic ordering is required.
    pub evidence: Vec<Evidence>,
}

impl FormatCandidate {
    /// Net support score: count of supporting items minus contradicting items.
    pub fn net_support(&self) -> i32 {
        self.evidence
            .iter()
            .fold(0i32, |acc, e| if e.supports { acc + 1 } else { acc - 1 })
    }
}

// ─────────────────────────────────────────────
// AbstentionReason
// ─────────────────────────────────────────────

/// Reason the inference engine declined to select a parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbstentionReason {
    /// The input was empty; no inference is possible.
    EmptyInput,
    /// Multiple candidates share equally strong evidence with no tiebreaker.
    AmbiguousCandidates,
    /// All structural detectors rejected the input; format is genuinely unknown.
    NoRecognizableStructure,
    /// Evidence was found but confidence for every candidate was only `Low`;
    /// the engine refuses to speculate.
    InsufficientEvidence,
}

impl fmt::Display for AbstentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbstentionReason::EmptyInput => write!(f, "empty input"),
            AbstentionReason::AmbiguousCandidates => {
                write!(f, "multiple candidates with equal evidence")
            }
            AbstentionReason::NoRecognizableStructure => {
                write!(f, "no recognizable structure detected")
            }
            AbstentionReason::InsufficientEvidence => {
                write!(f, "insufficient evidence to select a candidate")
            }
        }
    }
}

// ─────────────────────────────────────────────
// InferenceOutcome
// ─────────────────────────────────────────────

/// The final decision produced by the inference engine for a single record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceOutcome {
    /// A single candidate was selected with sufficient confidence.
    Recognized {
        /// The winning candidate.
        candidate: FormatCandidate,
        /// All candidates considered (including the winner), sorted by
        /// descending confidence then alphabetically by parser_id for
        /// determinism.
        all_candidates: Vec<FormatCandidate>,
    },

    /// The engine explicitly abstains; no parser is recommended.
    Abstained {
        reason: AbstentionReason,
        /// Candidates that were evaluated (may be empty).
        all_candidates: Vec<FormatCandidate>,
    },
}

// ─────────────────────────────────────────────
// InferenceResult
// ─────────────────────────────────────────────

/// Full inference result for a framed record, including provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceResult {
    /// The exact bytes that were analysed (never modified).
    pub raw_bytes: Vec<u8>,
    /// The final outcome.
    pub outcome: InferenceOutcome,
    /// Ordered list of detector IDs that were consulted, for auditability.
    pub detectors_consulted: Vec<&'static str>,
}
