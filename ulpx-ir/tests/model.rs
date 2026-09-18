use ulpx_core::event::EventId;
use ulpx_core::parser::ParserVersion;
use ulpx_ir::model::{EventIr, IrValue};

#[test]
fn construct_and_validate_ir() {
    let id = EventId::new("test-id").unwrap();
    let raw = b"test bytes".to_vec();
    let version = ParserVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };

    let mut ir = EventIr::new(id.clone(), "test-parser".to_string(), version, raw.clone());

    // Provenance is preserved exactly
    assert_eq!(ir.event_id, id);
    assert_eq!(ir.parser_id, "test-parser");
    assert_eq!(ir.parser_version.major, 1);
    assert_eq!(ir.raw_bytes, raw);

    // Default is empty
    assert!(ir.fields.is_empty());

    // Test mutability / structure
    ir.fields
        .insert("test_key".to_string(), IrValue::String("val".to_string()));
    assert_eq!(
        ir.fields.get("test_key"),
        Some(&IrValue::String("val".to_string()))
    );
}

#[test]
fn fields_iterate_deterministically() {
    let mut ir = EventIr::new(
        EventId::new("test").unwrap(),
        "test".to_string(),
        ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        vec![],
    );
    ir.fields.insert("z".to_string(), IrValue::Null);
    ir.fields.insert("a".to_string(), IrValue::Null);
    ir.fields.insert("m".to_string(), IrValue::Null);

    // BTreeMap guarantees alphabetical iteration
    let keys: Vec<&String> = ir.fields.keys().collect();
    assert_eq!(
        keys,
        vec![&"a".to_string(), &"m".to_string(), &"z".to_string()]
    );
}
