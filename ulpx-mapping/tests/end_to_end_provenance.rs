use ulpx_core::event::EventId;
use ulpx_core::framing::FramedRecord;
use ulpx_core::parser::json::JsonParser;
use ulpx_core::parser::{LifecycleStage, ParserRegistry};
use ulpx_ir::convert::{IrConverter, JsonConverter};
use ulpx_mapping::engine::MappingEngine;

#[test]
fn test_end_to_end_provenance() {
    let input = b"{\"level\": \"error\", \"message\": \"system failure\"}\n".to_vec();

    // 1. Framing
    let record = FramedRecord::new(input.clone());

    // 2. Parsing
    let mut registry = ParserRegistry::new();
    registry
        .register(Box::new(JsonParser::default()), LifecycleStage::Approved)
        .unwrap();
    let parsed = registry.parse_first(&record).unwrap();

    // 3. IR Conversion
    let event_id = EventId::new("evt-1").unwrap();
    let converter = JsonConverter;
    let ir = converter.convert(event_id, &parsed).unwrap();

    // 4. Semantic Mapping
    let engine = MappingEngine::default_registry();
    let canonical = engine.map(&ir).unwrap();

    // 5. Verify Provenance
    // "level" -> severity mapping
    let sev_field = canonical.severity.expect("severity should be mapped");
    assert_eq!(sev_field.provenance.source_field, "level");
    assert_eq!(
        sev_field.provenance.transformations,
        vec!["identity".to_string(), "lowercase".to_string()]
    );

    // Verify EXACT byte span matches the raw input
    let span = sev_field.provenance.span.expect("should have a span");
    let original_bytes = &input[span.start..span.end];
    assert_eq!(original_bytes, b"error");
}
