use ulpx_core::framing::FramedRecord;
use ulpx_core::parser::{LifecycleStage, ParserError, ParserRegistry, ParserVersion};
use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::model::{Evidence, FormatCandidate, InferenceConfidence};

use ulpx_onboard::generator::ParserGenerator;
use ulpx_onboard::spec::{ExtractionSpec, ParserSpec, SpecValidationError};

fn record(bytes: &[u8]) -> FramedRecord {
    FramedRecord::new(bytes.to_vec())
}

#[test]
fn reject_invalid_specifications() {
    let mut spec = ParserSpec {
        parser_id: "".to_string(),
        description: "Desc".to_string(),
        format_name: "Format".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    };

    assert_eq!(spec.validate(), Err(SpecValidationError::EmptyParserId));
    spec.parser_id = "id".to_string();

    spec.format_name = "   ".to_string();
    assert_eq!(spec.validate(), Err(SpecValidationError::EmptyFormatName));
    spec.format_name = "Fmt".to_string();

    spec.extraction = ExtractionSpec::Delimiter {
        separator: ',',
        field_names: vec![],
    };
    assert_eq!(spec.validate(), Err(SpecValidationError::EmptyFieldNames));

    spec.extraction = ExtractionSpec::Delimiter {
        separator: ',',
        field_names: vec!["a".to_string(), "a".to_string()],
    };
    assert_eq!(
        spec.validate(),
        Err(SpecValidationError::DuplicateField("a".to_string()))
    );

    spec.extraction = ExtractionSpec::KeyValue {
        pair_separator: '=',
        kv_separator: '=',
    };
    assert_eq!(
        spec.validate(),
        Err(SpecValidationError::ContradictorySeparators)
    );

    // Test generator build failure
    assert!(ParserGenerator::build(spec).is_err());
}

#[test]
fn deterministic_generation_and_provenance() {
    let spec = ParserSpec {
        parser_id: "kv-test".to_string(),
        description: "Test KV".to_string(),
        format_name: "KV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 2,
            patch: 3,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    };

    let parser1 = ParserGenerator::build(spec.clone()).unwrap();
    let parser2 = ParserGenerator::build(spec.clone()).unwrap();

    assert_eq!(parser1.metadata().id, "kv-test");
    assert_eq!(
        parser1.metadata().version,
        ParserVersion {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
    assert_eq!(parser2.metadata().id, "kv-test");

    // Both parsers should behave identically on the same input
    let rec = record(b"a=1 b=2");
    let res1 = parser1.parse(&rec).unwrap();
    let res2 = parser2.parse(&rec).unwrap();

    assert_eq!(res1, res2);
    assert_eq!(res1.parser_id, "kv-test");
    assert_eq!(
        res1.parser_version,
        ParserVersion {
            major: 1,
            minor: 2,
            patch: 3
        }
    );
}

#[test]
fn parses_valid_input_and_preserves_bytes() {
    let spec = ParserSpec {
        parser_id: "csv-test".to_string(),
        description: "Test CSV".to_string(),
        format_name: "CSV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::Delimiter {
            separator: ',',
            field_names: vec!["col1".into(), "col2".into()],
        },
    };

    let parser = ParserGenerator::build(spec).unwrap();
    let input = b"val1, val2 ";
    let rec = record(input);

    let res = parser.parse(&rec).unwrap();
    assert_eq!(res.raw_bytes, input);
    assert_eq!(res.fields.len(), 2);
    assert_eq!(res.fields[0].name, "col1");
    assert_eq!(res.fields[0].raw_value, "val1");
    assert_eq!(res.fields[1].name, "col2");
    assert_eq!(res.fields[1].raw_value, "val2");
}

#[test]
fn unsupported_and_malformed_input() {
    let spec = ParserSpec {
        parser_id: "kv-test".to_string(),
        description: "".to_string(),
        format_name: "KV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    };
    let parser = ParserGenerator::build(spec).unwrap();

    // Unsupported: empty bytes
    assert_eq!(parser.parse(&record(b"")), Err(ParserError::Unsupported));

    // Unsupported: no kv separator at all
    assert_eq!(
        parser.parse(&record(b"just some random text")),
        Err(ParserError::Unsupported)
    );

    // Malformed: has kv separator but some pair is missing it
    let res = parser.parse(&record(b"a=1 brokenpair b=2"));
    assert!(matches!(res, Err(ParserError::Malformed(_))));

    // Malformed: has kv separator but key is empty
    let res = parser.parse(&record(b"a=1 =2 b=3"));
    assert!(matches!(res, Err(ParserError::Malformed(_))));
}

#[test]
fn resource_limits() {
    let mut big_input = String::new();
    for i in 0..1001 {
        big_input.push_str(&format!("k{}={} ", i, i));
    }

    let spec = ParserSpec {
        parser_id: "kv-test".to_string(),
        description: "".to_string(),
        format_name: "KV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    };
    let parser = ParserGenerator::build(spec).unwrap();

    let res = parser.parse(&record(big_input.as_bytes()));
    assert!(matches!(res, Err(ParserError::ResourceLimit(_))));
}

#[test]
fn registry_integration_and_precedence() {
    let spec1 = ParserSpec {
        parser_id: "kv-1".to_string(),
        description: "".to_string(),
        format_name: "KV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ',',
            kv_separator: ':',
        },
    };

    let spec2 = ParserSpec {
        parser_id: "kv-2".to_string(),
        description: "".to_string(),
        format_name: "KV".to_string(),
        version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        extraction: ExtractionSpec::KeyValue {
            pair_separator: ' ',
            kv_separator: '=',
        },
    };

    let parser1 = ParserGenerator::build(spec1).unwrap();
    let parser2 = ParserGenerator::build(spec2).unwrap();

    let mut reg = ParserRegistry::new();
    reg.register(parser1, LifecycleStage::Candidate).unwrap();
    reg.register(parser2, LifecycleStage::Candidate).unwrap();

    // Should be parsed by kv-2 since kv-1 expects `:` but it's not present (will return Unsupported)
    let res = reg.parse_first(&record(b"a=1 b=2")).unwrap();
    assert_eq!(res.parser_id, "kv-2");
    assert_eq!(res.fields.len(), 2);
    assert_eq!(res.fields[0].name, "a");
    assert_eq!(res.fields[0].raw_value, "1");
    assert_eq!(res.fields[1].name, "b");
    assert_eq!(res.fields[1].raw_value, "2");

    // Should be parsed by kv-1
    let res = reg.parse_first(&record(b"a:1,b:2")).unwrap();
    assert_eq!(res.parser_id, "kv-1");
}

#[test]
fn inference_to_onboarding_pipeline() {
    // 1. Emulate a structural detector in the inference engine
    fn detect_generic_kv(bytes: &[u8]) -> Option<FormatCandidate> {
        let text = std::str::from_utf8(bytes).ok()?;
        if text.contains('=') && text.contains(' ') {
            Some(FormatCandidate {
                parser_id: "generic-kv-space-eq".to_string(),
                format_name: "Key-Value".to_string(),
                confidence: InferenceConfidence::High,
                evidence: vec![Evidence::support("test-kv", "Found = and space")],
            })
        } else {
            None
        }
    }

    let mut infer_engine = InferenceEngine::new();
    infer_engine.add_detector("generic-kv", detect_generic_kv);

    // 2. Perform inference on an unknown format
    let input = b"src_ip=1.1.1.1 dst_ip=2.2.2.2 action=allow";
    let rec = record(input);
    let infer_res = infer_engine.infer(&rec, None);

    // 3. Onboard (derive spec)
    let spec = ulpx_onboard::inference::derive_spec_from_inference(&infer_res).unwrap();
    assert_eq!(spec.parser_id, "generic-kv-space-eq");

    // 4. Generate Parser
    let parser = ParserGenerator::build(spec).unwrap();

    // 5. Register in Registry
    let mut reg = ParserRegistry::new();
    reg.register(parser, LifecycleStage::Candidate).unwrap();

    // 6. Use the registry to parse the original record!
    let parse_res = reg.parse_first(&rec).unwrap();
    assert_eq!(parse_res.parser_id, "generic-kv-space-eq");
    assert_eq!(parse_res.raw_bytes, input);
    assert_eq!(parse_res.fields.len(), 3);
    assert_eq!(parse_res.fields[0].name, "src_ip");
    assert_eq!(parse_res.fields[0].raw_value, "1.1.1.1");
    assert_eq!(parse_res.fields[1].name, "dst_ip");
    assert_eq!(parse_res.fields[1].raw_value, "2.2.2.2");
    assert_eq!(parse_res.fields[2].name, "action");
    assert_eq!(parse_res.fields[2].raw_value, "allow");
}
