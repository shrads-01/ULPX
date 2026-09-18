use std::collections::BTreeMap;
use ulpx_core::event::EventId;
use ulpx_core::parser::ParserVersion;
use ulpx_ir::model::{EventIr, IrValue};
use ulpx_mapping::engine::MappingEngine;
use ulpx_mapping::model::{AbstentionReason, Confidence, Severity};

fn dummy_ir(parser_id: &str, fields_input: &[(&str, &str)]) -> EventIr {
    let mut fields = BTreeMap::new();
    for (k, v) in fields_input {
        fields.insert(k.to_string(), IrValue::String(v.to_string()));
    }

    let mut ir = EventIr::new(
        EventId::new("test").unwrap(),
        parser_id.to_string(),
        ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        vec![],
    );
    ir.fields = fields;
    ir
}

#[test]
fn syslog_mapping_success() {
    let ir = dummy_ir(
        "syslog-rfc3164",
        &[
            ("syslog.timestamp", "Oct 11 22:14:15"),
            ("syslog.hostname", "srv01"),
            ("syslog.severity", "3"),
            ("syslog.message", "failed login"),
            ("extra_field", "value"),
        ],
    );

    let engine = MappingEngine::default_registry();
    let canonical = engine.map(&ir).unwrap();

    // Field-level provenance and value verification
    let ts = canonical.timestamp.as_ref().unwrap();
    assert_eq!(ts.value, "Oct 11 22:14:15");
    assert_eq!(ts.provenance.confidence, Confidence::Certain);
    assert_eq!(ts.provenance.source_field, "syslog.timestamp");
    assert_eq!(ts.provenance.rule_id, "syslog-ts-1");

    let sev = canonical.severity.as_ref().unwrap();
    assert_eq!(sev.value, Severity::Error);

    let msg = canonical.message.as_ref().unwrap();
    assert_eq!(msg.value, "failed login");

    let host = canonical.source_hostname.as_ref().unwrap();
    assert_eq!(host.value, "srv01");

    // Unmapped field preservation
    assert_eq!(canonical.unmapped.len(), 1);
    assert!(canonical.unmapped.contains_key("extra_field"));
}

#[test]
fn cef_mapping_success() {
    let ir = dummy_ir(
        "cef",
        &[
            ("rt", "1600000000"),
            ("src", "10.0.0.1"),
            ("shost", "client1"),
            ("cef.severity", "High"),
            ("cef.name", "Suspicious Activity"),
            ("cs1", "custom_data"),
        ],
    );

    let engine = MappingEngine::default_registry();
    let canonical = engine.map(&ir).unwrap();

    assert_eq!(canonical.timestamp.unwrap().value, "1600000000");
    assert_eq!(canonical.source_ip.unwrap().value, "10.0.0.1");
    assert_eq!(canonical.source_hostname.unwrap().value, "client1");
    assert_eq!(canonical.severity.unwrap().value, Severity::Error);
    assert_eq!(canonical.message.unwrap().value, "Suspicious Activity");
    assert!(canonical.unmapped.contains_key("cs1"));
}

#[test]
fn json_ambiguous_abstention() {
    // Both 'timestamp' and '@timestamp' are present, making heuristic mapping ambiguous.
    let ir = dummy_ir(
        "json-flat",
        &[
            ("timestamp", "time1"),
            ("@timestamp", "time2"),
            ("level", "info"),
        ],
    );

    let engine = MappingEngine::default_registry();
    let canonical = engine.map(&ir).unwrap();

    // Timestamp should NOT be mapped due to ambiguity
    assert!(canonical.timestamp.is_none());

    // Severity should be mapped
    assert_eq!(canonical.severity.unwrap().value, Severity::Info);

    // Both ambiguous fields should be perfectly preserved in unmapped
    assert!(canonical.unmapped.contains_key("timestamp"));
    assert!(canonical.unmapped.contains_key("@timestamp"));

    // We should have an audit trail for the abstention
    assert_eq!(canonical.abstentions.len(), 1);
    let abstention = &canonical.abstentions[0];
    assert_eq!(abstention.canonical_target, "timestamp");
    assert_eq!(abstention.reason, AbstentionReason::Ambiguous);
    assert!(abstention
        .involved_source_fields
        .contains(&"timestamp".to_string()));
    assert!(abstention
        .involved_source_fields
        .contains(&"@timestamp".to_string()));
}

#[test]
fn json_type_mismatch_abstention() {
    // "level" is a number instead of a string or standard string format
    let ir = dummy_ir("json-flat", &[("level", "12345")]);

    let engine = MappingEngine::default_registry();
    let canonical = engine.map(&ir).unwrap();

    assert!(canonical.severity.is_none());
    assert!(canonical.unmapped.contains_key("level"));

    assert_eq!(canonical.abstentions.len(), 1);
    assert_eq!(
        canonical.abstentions[0].reason,
        AbstentionReason::TypeMismatch
    );
}
