use std::thread::sleep;
use std::time::Duration;
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::framing::json_object::JsonObjectFramer;
use ulpx_core::parser::json::JsonParser;
use ulpx_core::parser::{LifecycleStage, ParserError, ParserRegistry};
use ulpx_core::storage::{EvidenceStore, InMemoryStore};
use ulpx_infer::engine::InferenceEngine;
use ulpx_ir::convert::CompositeConverter;
use ulpx_mapping::engine::MappingEngine;
use ulpx_replay::interpretation::ComponentConfig;
use ulpx_replay::{diff::InterpretationDiff, ParserOutcome, ReplayPipeline};

fn base_pipeline<'a>(
    store: &'a dyn EvidenceStore,
    registry: &'a ParserRegistry,
    infer: &'a InferenceEngine,
    ir: &'a CompositeConverter,
    map: &'a MappingEngine,
) -> ReplayPipeline<'a> {
    ReplayPipeline::new(
        store,
        &JsonObjectFramer,
        ComponentConfig {
            id: "json-framer".into(),
            version: "1.0".into(),
        },
        registry,
        infer,
        ir,
        map,
        ComponentConfig {
            id: "default-mapper".into(),
            version: "1.0".into(),
        },
    )
}

#[test]
fn test_comprehensive_audit_rules() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-1").unwrap();
    let id2 = EventId::new("evt-2").unwrap();
    let id_drift = EventId::new("evt-drift").unwrap();
    let id_count = EventId::new("evt-count").unwrap();
    let id_malformed = EventId::new("evt-malformed").unwrap();
    let id_resource = EventId::new("evt-resource").unwrap();

    store
        .store(RawEvent::new(
            id1.clone(),
            b"{\"a\":1}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"{\"b\":2}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id_drift.clone(),
            b"{\"a\":999}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id_count.clone(),
            b"{\"a\":1} {\"extra\":2}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id_malformed.clone(),
            b"{\"a\": invalid}".to_vec(),
            Source("test".into()),
        ))
        .unwrap();

    let mut big_json = String::from("{");
    for i in 0..1001 {
        big_json.push_str(&format!("\"k{}\":1,", i));
    }
    big_json.push_str("\"end\":1}");
    store
        .store(RawEvent::new(
            id_resource.clone(),
            big_json.into_bytes(),
            Source("test".into()),
        ))
        .unwrap();

    let mut registry = ParserRegistry::new();
    registry
        .register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();

    let infer_empty = InferenceEngine::new();
    let infer_defaults = InferenceEngine::with_defaults();

    let ir = CompositeConverter::default_registry();
    let map = MappingEngine::default_registry();

    // -- Rule 1 & Rule 2: Same EventId + same config => same ID; created_at does not affect ID --
    let p_base = base_pipeline(&store, &registry, &infer_defaults, &ir, &map);
    let r1a = p_base.replay(&id1).unwrap();
    sleep(Duration::from_millis(5));
    let r1b = p_base.replay(&id1).unwrap();

    assert_eq!(r1a.id, r1b.id, "Rule 1 & 2 failed");
    assert_ne!(
        r1a.created_at, r1b.created_at,
        "Rule 2 failed: created_at must differ in test"
    );

    // -- Rule 3: Different EventId => different InterpretationId --
    let r2 = p_base.replay(&id2).unwrap();
    assert_ne!(r1a.id, r2.id, "Rule 3 failed");

    // -- Rule 4 & 5: Different framer/mapper config => different ID --
    let p_diff_framer = ReplayPipeline::new(
        &store,
        &JsonObjectFramer,
        ComponentConfig {
            id: "other-framer".into(),
            version: "1.0".into(),
        },
        &registry,
        &infer_defaults,
        &ir,
        &map,
        ComponentConfig {
            id: "default-mapper".into(),
            version: "1.0".into(),
        },
    );
    let r_diff_framer = p_diff_framer.replay(&id1).unwrap();
    assert_ne!(r1a.id, r_diff_framer.id, "Rule 4 failed");

    let p_diff_mapper = ReplayPipeline::new(
        &store,
        &JsonObjectFramer,
        ComponentConfig {
            id: "json-framer".into(),
            version: "1.0".into(),
        },
        &registry,
        &infer_defaults,
        &ir,
        &map,
        ComponentConfig {
            id: "other-mapper".into(),
            version: "1.0".into(),
        },
    );
    let r_diff_mapper = p_diff_mapper.replay(&id1).unwrap();
    assert_ne!(r1a.id, r_diff_mapper.id, "Rule 5 failed");

    // -- Rule 6 & 23: Different inference detector configuration/order => different ID --
    let p_infer_empty = base_pipeline(&store, &registry, &infer_empty, &ir, &map);
    let r_infer_empty = p_infer_empty.replay(&id1).unwrap();
    assert_ne!(r1a.id, r_infer_empty.id, "Rule 6 failed");
    // Ensure identity is strings, not function ptrs (checked in engine.rs)

    // -- Rule 7: Parser configuration differences affect identity --
    let empty_registry = ParserRegistry::new(); // empty
    let p_empty_reg = base_pipeline(&store, &empty_registry, &infer_defaults, &ir, &map);
    let r_empty_reg = p_empty_reg.replay(&id1).unwrap();
    assert_ne!(
        r1a.id, r_empty_reg.id,
        "Rule 7 failed: parser config change must change ID"
    );

    // -- Rule 8 & 17: Same index + exact identical bytes => diffed, diff is deterministic --
    let diff_identical = InterpretationDiff::compare(&r1a, &r1b);
    assert!(
        diff_identical.frame_structure.identical_structure,
        "Rule 8 failed"
    );
    assert_eq!(diff_identical.frame_diffs.len(), 1); // We did a field-level diff
    assert!(diff_identical.frame_diffs[0].fields_changed.is_empty());

    // -- Rule 9 & 11: Same index + different bytes => NO field-level comparison --
    let diff_drift = InterpretationDiff::compare(&r1a, &r2);
    assert!(!diff_drift.frame_structure.identical_structure);
    assert_eq!(
        diff_drift.frame_diffs.len(),
        0,
        "Rule 9 failed: Should not compute field diffs for divergent bytes"
    );
    assert_eq!(diff_drift.frame_structure.removed_frame_indices, vec![0]);
    assert_eq!(diff_drift.frame_structure.added_frame_indices, vec![0]);

    // -- Rule 10: Different frame counts still allow independently exact-byte-matched frames to be compared --
    // id_count produces 2 frames if we use NewlineFramer. Wait, JsonObjectFramer fails on trailing?
    let r_count = p_base.replay(&id_count).unwrap();
    let r_single = p_base.replay(&id1).unwrap();

    let diff_count = InterpretationDiff::compare(&r_single, &r_count);
    assert!(!diff_count.frame_structure.identical_structure);
    assert_eq!(diff_count.frame_diffs.len(), 1, "Rule 10 failed");
    assert_eq!(diff_count.frame_structure.added_frame_indices, vec![1]);

    // -- Rule 21 & 22: Malformed and ResourceLimit do NOT fall through to inference --
    let p_malformed = base_pipeline(&store, &registry, &infer_defaults, &ir, &map);

    let r_malformed = p_malformed.replay(&id_malformed).unwrap();

    assert_eq!(r_malformed.frames.len(), 1);
    let frame_malformed = &r_malformed.frames[0];
    assert!(
        matches!(
            frame_malformed.parser_outcome,
            ParserOutcome::Failed(ParserError::Malformed(_))
        ),
        "Rule 21 failed"
    );
    assert!(
        frame_malformed.inference_decision.is_none(),
        "Rule 21 failed: Inference was invoked on Malformed"
    );

    // -- Rule 22: ResourceLimit does NOT fall through to inference --
    // Setup done above
    let r_resource = p_base.replay(&id_resource).unwrap();

    let frame_resource = &r_resource.frames[0];
    assert!(
        matches!(
            frame_resource.parser_outcome,
            ParserOutcome::Failed(ParserError::ResourceLimit(_))
        ),
        "Rule 22 failed"
    );
    assert!(
        frame_resource.inference_decision.is_none(),
        "Rule 22 failed: Inference was invoked on ResourceLimit"
    );
}
