use ulpx_core::parser::{LifecycleStage, ParserRegistry, ParserVersion};
use ulpx_mapping::engine::MappingEngine;
use ulpx_onboard::generator::ParserGenerator;
use ulpx_onboard::lab::{LabSuite, ParserLab};
use ulpx_onboard::lifecycle::ValidatedCandidate;
use ulpx_onboard::spec::{ExtractionSpec, ParserSpec};

fn build_dummy_spec() -> ParserSpec {
    ParserSpec {
        parser_id: "json-flat".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        format_name: "kv-flat".to_string(),
        description: "Test".to_string(),
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    }
}

#[test]
fn test_parser_lab_lifecycle() {
    let spec = build_dummy_spec();
    let parser = ParserGenerator::build(spec).expect("Should build parser");
    let mapper = MappingEngine::default_registry();

    fn semantic_validator(event: &ulpx_mapping::model::CanonicalEvent) -> bool {
        event.message.as_ref().map(|f| f.value.as_str()) == Some("hello")
    }

    let suite = LabSuite {
        syntax_inputs: vec![b"msg=hello".to_vec()],
        semantic_inputs: vec![(b"msg=hello".to_vec(), semantic_validator)],
        golden_tests: vec![(
            b"msg=hello".to_vec(),
            vec![("msg".to_string(), "hello".to_string())],
        )],
        negative_inputs: vec![b" ".to_vec()],
        security_inputs: vec![b"msg=hello".to_vec()],
        performance_inputs: vec![b"msg=hello".to_vec()],
    };

    let report = ParserLab::evaluate(parser.as_ref(), &mapper, &suite);

    assert!(report.syntax_passed, "Syntax should pass");
    assert!(report.semantic_passed, "Semantic should pass");
    assert!(report.golden_passed, "Golden should pass");
    assert!(report.negative_passed, "Negative should pass");
    assert!(report.mutation_passed, "Mutation should pass");
    assert!(report.security_passed, "Security should pass");
    assert!(report.performance_passed, "Performance should pass");
    assert!(report.is_fully_valid());

    // Transition 1: Candidate -> Validated
    let validated = ValidatedCandidate::new(parser, report.clone())
        .expect("Should transition to ValidatedCandidate");

    // Transition 2: Validated -> Approved (Promoted)
    let promoted = validated.approve();
    assert_eq!(promoted.stage, LifecycleStage::Approved);

    // Register approved parser
    let mut registry = ParserRegistry::new();
    registry
        .register(promoted.parser, promoted.stage)
        .expect("Should register");

    assert_eq!(registry.stage("json-flat"), Some(LifecycleStage::Approved));
}

#[test]
fn test_parser_lab_failed_validation() {
    let spec = build_dummy_spec();
    let parser = ParserGenerator::build(spec).expect("Should build parser");
    let mapper = MappingEngine::default_registry();

    fn semantic_validator(event: &ulpx_mapping::model::CanonicalEvent) -> bool {
        event.message.as_ref().map(|f| f.value.as_str()) == Some("hello")
    }

    // A suite that will fail negative tests by providing valid JSON to a negative test
    let bad_suite = LabSuite {
        syntax_inputs: vec![b"msg=hello".to_vec()],
        semantic_inputs: vec![(b"msg=hello".to_vec(), semantic_validator)],
        golden_tests: vec![(
            b"msg=hello".to_vec(),
            vec![("msg".to_string(), "hello".to_string())],
        )],
        negative_inputs: vec![b"valid=kv".to_vec()], // This should parse successfully, failing the negative test
        security_inputs: vec![b"msg=hello".to_vec()],
        performance_inputs: vec![b"msg=hello".to_vec()],
    };

    let report = ParserLab::evaluate(parser.as_ref(), &mapper, &bad_suite);
    assert!(!report.negative_passed, "Negative test should fail");
    assert!(!report.is_fully_valid());

    match ValidatedCandidate::new(parser, report) {
        Err(e) => assert_eq!(
            e,
            "Cannot transition to ValidatedCandidate: Validation failed"
        ),
        Ok(_) => panic!("Should have failed validation"),
    }
}

#[test]
fn test_versioned_promotion_preserves_history() {
    let mut spec1 = build_dummy_spec();
    spec1.parser_id = "my-parser_v1.0.0".to_string();
    spec1.version = ParserVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };

    let mut spec2 = build_dummy_spec();
    spec2.parser_id = "my-parser_v2.0.0".to_string();
    spec2.version = ParserVersion {
        major: 2,
        minor: 0,
        patch: 0,
    };

    let parser1 = ParserGenerator::build(spec1).unwrap();
    let parser2 = ParserGenerator::build(spec2).unwrap();

    let mut mapper = MappingEngine::default_registry();

    struct MockMapper;
    impl ulpx_mapping::engine::SemanticMapper for MockMapper {
        fn map(&self, ir: &ulpx_ir::model::EventIr) -> Option<ulpx_mapping::model::CanonicalEvent> {
            if ir.parser_id.starts_with("my-parser") {
                Some(ulpx_mapping::model::CanonicalEvent {
                    event_id: ir.event_id.clone(),
                    parser_id: ir.parser_id.clone(),
                    parser_version: ir.parser_version,
                    raw_bytes: ir.raw_bytes.clone(),
                    timestamp: None,
                    source_ip: None,
                    source_hostname: None,
                    dest_ip: None,
                    dest_hostname: None,
                    severity: None,
                    message: Some(ulpx_mapping::model::CanonicalField {
                        value: "hello".to_string(),
                        provenance: ulpx_mapping::model::FieldProvenance {
                            parser_id: ir.parser_id.clone(),
                            parser_version: ir.parser_version,
                            source_field: "msg".to_string(),
                            span: None,
                            transformations: vec![],
                            rule_id: "mock".to_string(),
                            confidence: ulpx_mapping::model::Confidence::Probable,
                        },
                    }),
                    action: None,
                    unmapped: std::collections::BTreeMap::new(),
                    abstentions: vec![],
                })
            } else {
                None
            }
        }
    }
    mapper.register(MockMapper);

    fn semantic_validator(event: &ulpx_mapping::model::CanonicalEvent) -> bool {
        event.message.as_ref().map(|f| f.value.as_str()) == Some("hello")
    }

    let suite = LabSuite {
        syntax_inputs: vec![b"msg=hello".to_vec()],
        semantic_inputs: vec![(b"msg=hello".to_vec(), semantic_validator)],
        golden_tests: vec![(
            b"msg=hello".to_vec(),
            vec![("msg".to_string(), "hello".to_string())],
        )],
        negative_inputs: vec![b" ".to_vec()],
        security_inputs: vec![b"msg=hello".to_vec()],
        performance_inputs: vec![b"msg=hello".to_vec()],
    };

    // Candidate 1 -> Validation -> ValidatedCandidate -> Approval -> Promoted
    let report1 = ParserLab::evaluate(parser1.as_ref(), &mapper, &suite);
    let validated1 = ValidatedCandidate::new(parser1, report1).expect("v1 should pass validation");
    // Proof that validation does not equal approval: validated1 is NOT Approved yet.
    // Explicit human approval transition:
    let promoted1 = validated1.approve();

    // Candidate 2 -> Validation -> ValidatedCandidate -> Approval -> Promoted
    let report2 = ParserLab::evaluate(parser2.as_ref(), &mapper, &suite);
    let validated2 = ValidatedCandidate::new(parser2, report2).expect("v2 should pass validation");
    let promoted2 = validated2.approve();

    let mut registry = ParserRegistry::new();

    // Registering via the PromotedParser ensures the explicitly approved stage is used
    registry
        .register(promoted1.parser, promoted1.stage)
        .unwrap();
    registry
        .register(promoted2.parser, promoted2.stage)
        .unwrap();

    // Both versions exist concurrently. A is preserved, B has distinct version.
    // Explicitly proving that historical v1 remains retrievable and unchanged after v2 is approved.
    assert_eq!(
        registry.stage("my-parser_v1.0.0"),
        Some(LifecycleStage::Approved)
    );
    assert_eq!(
        registry.stage("my-parser_v2.0.0"),
        Some(LifecycleStage::Approved)
    );

    let p1_retrieved = registry
        .get("my-parser_v1.0.0")
        .expect("v1 should be retrievable");
    assert_eq!(p1_retrieved.metadata().version.major, 1);

    let p2_retrieved = registry
        .get("my-parser_v2.0.0")
        .expect("v2 should be retrievable");
    assert_eq!(p2_retrieved.metadata().version.major, 2);
}
