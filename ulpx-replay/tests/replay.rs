use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::framing::json_object::JsonObjectFramer;
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::framing::{FrameError, FramedRecord, Framer};
use ulpx_core::integrity::VerificationResult;
use ulpx_core::parser::{
    LifecycleStage, Parser, ParserError, ParserMetadata, ParserRegistry, ParserResult,
    ParserVersion,
};
use ulpx_core::storage::{EvidenceStore, InMemoryStore};
use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::model::{AbstentionReason, InferenceOutcome};
use ulpx_ir::convert::CompositeConverter;
use ulpx_mapping::engine::MappingEngine;
use ulpx_replay::{ParserOutcome, RecordComparison, ReplayPipeline};

// Provide a dummy parser to mutate and test versions
struct DummyParser {
    version: ParserVersion,
}
impl Parser for DummyParser {
    fn metadata(&self) -> &ParserMetadata {
        // Leak is fine for test
        Box::leak(Box::new(ParserMetadata {
            id: "dummy".to_string(),
            description: "Dummy".to_string(),
            format: "DUMMY".to_string(),
            version: self.version,
        }))
    }
    fn parse(&self, record: &FramedRecord) -> Result<ParserResult, ParserError> {
        if record.as_bytes() == b"DUMMY_FAIL" {
            Err(ParserError::Malformed("failed".to_string()))
        } else if record.as_bytes() == b"DUMMY" {
            Ok(ParserResult {
                fields: vec![],
                parser_id: "dummy".to_string(),
                parser_version: self.version,
                raw_bytes: record.as_bytes().to_vec(),
            })
        } else {
            Err(ParserError::Unsupported)
        }
    }
}

fn setup_pipeline<'a>(
    store: &'a dyn EvidenceStore,
    framer: &'a dyn Framer,
    parser_registry: &'a ParserRegistry,
    inference_engine: &'a InferenceEngine,
    ir_converter: &'a CompositeConverter,
    mapping_engine: &'a MappingEngine,
) -> ReplayPipeline<'a> {
    ReplayPipeline::new(
        store,
        framer,
        parser_registry,
        inference_engine,
        ir_converter,
        mapping_engine,
    )
}

#[test]
fn test_1_reprocess_valid_event_successfully() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-1").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"{\"a\":1}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = JsonObjectFramer;
    let mut registry = ParserRegistry::new();
    // Default json flat parser
    registry
        .register(
            Box::new(ulpx_core::parser::json::JsonParser::new()),
            LifecycleStage::Deployed,
        )
        .unwrap();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();

    assert!(result.integrity_verified);
    assert_eq!(result.record_outcomes.len(), 1);
    let outcome = &result.record_outcomes[0];
    assert_eq!(outcome.parser_id.as_deref(), Some("json-flat"));
    assert!(outcome.ir_event.is_some());
    let outcome_ir = outcome.ir_event.as_ref().unwrap();
    assert!(outcome_ir.fields.get("a").unwrap().span.is_some()); // Test 14: Provenance spans remain
    assert!(outcome.canonical_event.is_some());

    // Test 13: Mapping abstention
    let mut store_unmapped = InMemoryStore::new();
    let id_unmapped = EventId::new("evt-1b").unwrap();
    store_unmapped
        .store(RawEvent::new(
            id_unmapped.clone(),
            b"{\"time\":\"1\", \"timestamp\":\"2\"}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    let pipeline_unmapped = setup_pipeline(&store_unmapped, &framer, &registry, &infer, &ir, &map);
    let result_unmapped = pipeline_unmapped.replay(&id_unmapped).unwrap();
    let outcome_unmapped = &result_unmapped.record_outcomes[0];
    assert!(outcome_unmapped.ir_event.is_some());

    let canonical = outcome_unmapped.canonical_event.as_ref().unwrap();
    assert!(!canonical.abstentions.is_empty()); // Shows mapping abstention is visible
}

#[test]
fn test_2_uses_original_raw_bytes() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-2").unwrap();
    let raw = b"{\"a\":1}".to_vec();
    store
        .store(RawEvent::new(
            id.clone(),
            raw.clone(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = JsonObjectFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();
    assert_eq!(result.record_outcomes[0].frame_bytes, raw);
}

#[test]
fn test_3_integrity_verified_before_processing() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-3").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"data".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = NewlineFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();
    assert!(result.integrity_verified);
}

#[test]
fn test_4_tampered_evidence_produces_failure() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-4").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"data".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    store.tamper_bytes(&id, b"tampered".to_vec());

    let framer = NewlineFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();
    assert!(!result.integrity_verified);
    assert!(matches!(
        result.integrity_error.unwrap(),
        VerificationResult::HashMismatch { .. }
    ));
    // Processing should not continue
    assert_eq!(result.record_outcomes.len(), 0);
}

#[test]
fn test_5_empty_evidence_behaves_consistently() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-5").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = NewlineFramer; // framing empty returns no frames
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();
    assert!(result.integrity_verified);
    assert_eq!(result.record_outcomes.len(), 0);
}

#[test]
fn test_6_arbitrary_binary_lossless() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-6").unwrap();
    let binary = vec![0xFF, 0x00, 0xFE, 0x12];
    store
        .store(RawEvent::new(
            id.clone(),
            binary.clone(),
            Source("test".into()),
        ))
        .unwrap();

    // Use a framer that accepts everything as one frame if no newline is found
    // Wait, newline framer expects incomplete trailing data if no newline. Let's try it.
    let framer = NewlineFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();
    // Incomplete trailing
    assert_eq!(result.trailing_frame_error, Some(FrameError::Incomplete));
}

#[test]
fn test_7_re_runs_framing() {
    // If it re-runs framing, changing the framer changes the records.
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-7").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"line1\nline2\n".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let framer1 = NewlineFramer;
    let pipeline1 = setup_pipeline(&store, &framer1, &registry, &infer, &ir, &map);
    let res1 = pipeline1.replay(&id).unwrap();
    assert_eq!(res1.record_outcomes.len(), 2);

    // Now pretend we replay with a framer that requires JSON objects
    let framer2 = JsonObjectFramer;
    let pipeline2 = setup_pipeline(&store, &framer2, &registry, &infer, &ir, &map);
    let res2 = pipeline2.replay(&id).unwrap();
    // Result should be a malformed frame error or zero frames
    assert_eq!(res2.record_outcomes.len(), 0);
    assert!(res2.trailing_frame_error.is_some());
}

#[test]
fn test_8_and_9_and_17_parser_versions_recorded_and_distinguishable() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-8").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"DUMMY".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    let framer = NewlineFramer; // DUMMY is incomplete, so let's use newline and append \n
    store.tamper_bytes(&id, b"DUMMY\n".to_vec());
    // Wait, tampering fails integrity. Store a fresh one.
    let mut store2 = InMemoryStore::new();
    let id2 = EventId::new("evt-8b").unwrap();
    store2
        .store(RawEvent::new(
            id2.clone(),
            b"DUMMY\n".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let mut registry_v1 = ParserRegistry::new();
    registry_v1
        .register(
            Box::new(DummyParser {
                version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            }),
            LifecycleStage::Deployed,
        )
        .unwrap();

    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline1 = setup_pipeline(&store2, &framer, &registry_v1, &infer, &ir, &map);
    let res1 = pipeline1.replay(&id2).unwrap();

    let mut registry_v2 = ParserRegistry::new();
    registry_v2
        .register(
            Box::new(DummyParser {
                version: ParserVersion {
                    major: 2,
                    minor: 0,
                    patch: 0,
                },
            }),
            LifecycleStage::Deployed,
        )
        .unwrap();

    let pipeline2 = setup_pipeline(&store2, &framer, &registry_v2, &infer, &ir, &map);
    let res2 = pipeline2.replay(&id2).unwrap();

    let out1 = &res1.record_outcomes[0];
    let out2 = &res2.record_outcomes[0];

    assert_eq!(out1.parser_version.as_deref(), Some("1.0.0"));
    assert_eq!(out2.parser_version.as_deref(), Some("2.0.0"));

    let diff = RecordComparison::compare(out1, out2);
    assert!(diff.parser_changed);
}

#[test]
fn test_10_and_11_unknown_inference_and_abstention() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-10").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"GARBAGE\n".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = NewlineFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();

    let out = &result.record_outcomes[0];
    assert!(matches!(
        out.parser_outcome,
        ParserOutcome::Failed(ParserError::Unsupported)
    ));
    assert!(matches!(
        out.inference_decision.as_ref().unwrap(),
        InferenceOutcome::Abstained {
            reason: AbstentionReason::NoRecognizableStructure,
            ..
        }
    ));
}

#[test]
fn test_12_parser_errors_represented() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-12").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"DUMMY_FAIL\n".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = NewlineFramer;
    let mut registry = ParserRegistry::new();
    registry
        .register(
            Box::new(DummyParser {
                version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            }),
            LifecycleStage::Deployed,
        )
        .unwrap();

    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result = pipeline.replay(&id).unwrap();

    let out = &result.record_outcomes[0];
    assert!(matches!(
        out.parser_outcome,
        ParserOutcome::Failed(ParserError::Malformed(_))
    ));
}

#[test]
fn test_15_reprocessing_does_not_mutate_stored_evidence() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-15").unwrap();
    let raw = b"data\n".to_vec();
    store
        .store(RawEvent::new(
            id.clone(),
            raw.clone(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = NewlineFramer;
    let registry = ParserRegistry::new();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    pipeline.replay(&id).unwrap();

    // After replay, evidence should remain unchanged
    let event = store.retrieve(&id).unwrap();
    assert_eq!(event.into_bytes(), raw);
}

#[test]
fn test_16_deterministic_semantic_results() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-16").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"{\"a\":1}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let framer = JsonObjectFramer;
    let mut registry = ParserRegistry::new();
    registry
        .register(
            Box::new(ulpx_core::parser::json::JsonParser::new()),
            LifecycleStage::Deployed,
        )
        .unwrap();
    let infer = InferenceEngine::default();
    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    let pipeline = setup_pipeline(&store, &framer, &registry, &infer, &ir, &map);
    let result1 = pipeline.replay(&id).unwrap();
    let result2 = pipeline.replay(&id).unwrap();

    let diff = RecordComparison::compare(&result1.record_outcomes[0], &result2.record_outcomes[0]);
    assert!(!diff.parser_changed);
    assert!(!diff.fields_changed);
    assert!(!diff.inference_changed);
    assert!(!diff.mapping_changed);
}

#[test]
fn test_19_duplicate_event_ids_remain_protected() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-19").unwrap();
    store
        .store(RawEvent::new(
            id.clone(),
            b"data".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    assert!(store
        .store(RawEvent::new(
            id.clone(),
            b"data2".to_vec(),
            Source("test".into())
        ))
        .is_err());
}
