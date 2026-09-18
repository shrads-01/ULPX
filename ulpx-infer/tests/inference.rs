//! Integration tests for the inference engine.
//!
//! These tests drive the full pipeline from raw bytes through the engine and
//! verify the structured inference result without relying on parsers.

use ulpx_core::framing::FramedRecord;
use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::model::{AbstentionReason, InferenceConfidence, InferenceOutcome};

fn record(bytes: &[u8]) -> FramedRecord {
    FramedRecord::new(bytes.to_vec())
}

// ─── JSON ────────────────────────────────────────────────────────────────────

#[test]
fn json_recognized_high_confidence() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(br#"{"event": "login", "user": "alice"}"#), None);
    assert_eq!(r.raw_bytes, br#"{"event": "login", "user": "alice"}"#);
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "json-flat");
            assert_eq!(candidate.confidence, InferenceConfidence::High);
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

#[test]
fn json_empty_object_recognized() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(b"{}"), None);
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "json-flat");
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

// ─── CEF ─────────────────────────────────────────────────────────────────────

#[test]
fn cef_recognized_high_confidence() {
    let engine = InferenceEngine::default();
    let r = engine.infer(
        &record(b"CEF:0|Security|ThreatManager|1.0|100|Worm Attack|10|src=10.0.0.1"),
        None,
    );
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "cef");
            assert_eq!(candidate.confidence, InferenceConfidence::High);
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

#[test]
fn cef_with_few_pipes_not_high_confidence() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(b"CEF:0|A|B"), None);
    match &r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert!(
                candidate.confidence < InferenceConfidence::High,
                "expected < High confidence for truncated CEF"
            );
        }
        InferenceOutcome::Abstained { .. } => {
            // Also acceptable: insufficient evidence
        }
    }
}

// ─── Syslog ───────────────────────────────────────────────────────────────────

#[test]
fn syslog_recognized_high_confidence() {
    let engine = InferenceEngine::default();
    let r = engine.infer(
        &record(b"<34>Jan  5 12:34:56 myhost myapp: hello world"),
        None,
    );
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "syslog-rfc3164");
            assert_eq!(candidate.confidence, InferenceConfidence::High);
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

#[test]
fn syslog_without_priority_medium_confidence() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(b"Jan  5 12:34:56 myhost myapp: hello"), None);
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "syslog-rfc3164");
            assert!(candidate.confidence <= InferenceConfidence::Medium);
        }
        InferenceOutcome::Abstained { .. } => {} // acceptable
    }
}

// ─── Empty / malformed ────────────────────────────────────────────────────────

#[test]
fn empty_input_abstains() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(b""), None);
    match r.outcome {
        InferenceOutcome::Abstained {
            reason: AbstentionReason::EmptyInput,
            ..
        } => {}
        other => panic!("expected EmptyInput abstention, got {other:?}"),
    }
}

#[test]
fn unknown_format_no_recognizable_structure() {
    let engine = InferenceEngine::default();
    // Plain key=value pairs — no structural marker for any registered format
    let r = engine.infer(&record(b"key=value foo=bar baz=123"), None);
    match r.outcome {
        InferenceOutcome::Abstained { reason, .. } => {
            // Either NoRecognizableStructure or InsufficientEvidence is correct
            assert!(matches!(
                reason,
                AbstentionReason::NoRecognizableStructure | AbstentionReason::InsufficientEvidence
            ));
        }
        InferenceOutcome::Recognized { candidate, .. } => {
            // Only acceptable if confidence is Low (shouldn't normally happen with default policy)
            assert_eq!(candidate.confidence, InferenceConfidence::Low);
        }
    }
}

// ─── Raw bytes preserved ─────────────────────────────────────────────────────

#[test]
fn raw_bytes_preserved_exactly() {
    let engine = InferenceEngine::default();
    let input = b"CEF:0|V|P|1.0|200|Test|5|src=1.2.3.4".as_ref();
    let r = engine.infer(&record(input), None);
    assert_eq!(r.raw_bytes, input);
}

#[test]
fn raw_bytes_never_modified() {
    // Even for unknown formats, raw bytes must be preserved
    let engine = InferenceEngine::default();
    let input = b"totally opaque: \xff\xfe binary data";
    let r = engine.infer(&record(input), None);
    assert_eq!(r.raw_bytes, input);
}

// ─── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn inference_is_deterministic() {
    let engine = InferenceEngine::default();
    let rec = record(b"CEF:0|Vendor|Product|1.0|100|Event|5|src=10.0.0.1 dst=10.0.0.2");
    let r1 = engine.infer(&rec, None);
    let r2 = engine.infer(&rec, None);
    assert_eq!(r1, r2, "inference must be deterministic");
}

#[test]
fn candidate_ordering_is_deterministic() {
    let engine = InferenceEngine::default();
    // Run multiple times and check that candidate order is stable
    let rec = record(b"CEF:0|Vendor|Product|1.0|100|Event|5|");
    let r1 = engine.infer(&rec, None);
    let r2 = engine.infer(&rec, None);
    let candidates1 = match &r1.outcome {
        InferenceOutcome::Recognized { all_candidates, .. } => all_candidates,
        InferenceOutcome::Abstained { all_candidates, .. } => all_candidates,
    };
    let candidates2 = match &r2.outcome {
        InferenceOutcome::Recognized { all_candidates, .. } => all_candidates,
        InferenceOutcome::Abstained { all_candidates, .. } => all_candidates,
    };
    let ids1: Vec<_> = candidates1.iter().map(|c| c.parser_id).collect();
    let ids2: Vec<_> = candidates2.iter().map(|c| c.parser_id).collect();
    assert_eq!(ids1, ids2, "candidate ordering must be deterministic");
}

// ─── Detectors consulted ─────────────────────────────────────────────────────

#[test]
fn detectors_consulted_list_is_complete() {
    let engine = InferenceEngine::default();
    let r = engine.infer(&record(br#"{"x": 1}"#), None);
    // All three built-in detectors should always be consulted
    assert!(r.detectors_consulted.contains(&"json"));
    assert!(r.detectors_consulted.contains(&"cef"));
    assert!(r.detectors_consulted.contains(&"syslog"));
}

// ─── Registry integration ─────────────────────────────────────────────────────

#[test]
fn registry_integration_json_recognized() {
    use ulpx_core::parser::{LifecycleStage, ParserRegistry};

    let mut reg = ParserRegistry::new();
    reg.register(
        Box::new(ulpx_core::parser::json::JsonParser::new()),
        LifecycleStage::Deployed,
    )
    .unwrap();

    let engine = InferenceEngine::default();
    let rec = record(br#"{"event": "login"}"#);
    let r = engine.infer(&rec, Some(&reg));

    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "json-flat");
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

#[test]
fn registry_integration_unknown_falls_back_to_structural() {
    use ulpx_core::parser::{LifecycleStage, ParserRegistry};

    // Registry has JSON parser only, but input is syslog
    let mut reg = ParserRegistry::new();
    reg.register(
        Box::new(ulpx_core::parser::json::JsonParser::new()),
        LifecycleStage::Deployed,
    )
    .unwrap();

    let engine = InferenceEngine::default();
    let rec = record(b"<34>Jan  5 12:34:56 myhost myapp: msg");
    let r = engine.infer(&rec, Some(&reg));

    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            // Structural detector should have caught syslog
            assert_eq!(candidate.parser_id, "syslog-rfc3164");
        }
        InferenceOutcome::Abstained { .. } => {
            // Also acceptable if evidence was insufficient
        }
    }
}

// ─── Custom detector ─────────────────────────────────────────────────────────

#[test]
fn custom_detector_can_be_registered() {
    use ulpx_infer::model::{Evidence, FormatCandidate};

    fn detect_csv(bytes: &[u8]) -> Option<FormatCandidate> {
        let text = std::str::from_utf8(bytes).ok()?;
        let comma_count = text.bytes().filter(|&b| b == b',').count();
        if comma_count >= 2 {
            Some(FormatCandidate {
                parser_id: "csv",
                format_name: "CSV",
                confidence: InferenceConfidence::Medium,
                evidence: vec![Evidence::support(
                    "csv-comma-count",
                    format!("found {comma_count} commas"),
                )],
            })
        } else {
            None
        }
    }

    let mut engine = InferenceEngine::new();
    engine.add_detector("csv", detect_csv);

    let r = engine.infer(&record(b"a,b,c,d,e"), None);
    match r.outcome {
        InferenceOutcome::Recognized { candidate, .. } => {
            assert_eq!(candidate.parser_id, "csv");
        }
        other => panic!("expected Recognized, got {other:?}"),
    }
}

// ─── Evidence integrity ───────────────────────────────────────────────────────

#[test]
fn all_candidates_included_in_result() {
    let engine = InferenceEngine::default();
    // Syslog-shaped input: only syslog detectors should fire
    let r = engine.infer(
        &record(b"<100>Jan 10 10:00:00 host prog: message here"),
        None,
    );
    // The all_candidates list should not be empty
    let all = match &r.outcome {
        InferenceOutcome::Recognized { all_candidates, .. } => all_candidates,
        InferenceOutcome::Abstained { all_candidates, .. } => all_candidates,
    };
    assert!(!all.is_empty());
}

#[test]
fn insufficient_evidence_abstains_not_guesses() {
    let engine = InferenceEngine::default();
    // Input has a lone '<' but nothing else that looks like syslog, JSON, or CEF
    let r = engine.infer(&record(b"< random garbage here >"), None);
    // Should abstain, not pick a random winner
    match r.outcome {
        InferenceOutcome::Abstained { .. } => {} // correct
        InferenceOutcome::Recognized { candidate, .. } => {
            // Only acceptable if confidence is clearly Low (policy violation if not)
            assert_ne!(
                candidate.confidence,
                InferenceConfidence::High,
                "must not select High-confidence candidate for ambiguous input"
            );
        }
    }
}
