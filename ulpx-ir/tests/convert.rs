use ulpx_core::event::EventId;
use ulpx_core::parser::{ParsedField, ParserResult, ParserVersion};
use ulpx_ir::convert::{
    CefConverter, CompositeConverter, IrConverter, JsonConverter, SyslogConverter,
};
use ulpx_ir::model::IrValue;

fn dummy_event_id() -> EventId {
    EventId::new("test-event-id").unwrap()
}

#[test]
fn syslog_converter_basic() {
    let result = ParserResult {
        parser_id: "syslog-rfc3164".to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: b"<34>Jan  5 12:34:56 myhost myapp: hello world".to_vec(),
        fields: vec![
            ParsedField::new("syslog.priority", "34"),
            ParsedField::new("syslog.severity", "2"),
            ParsedField::new("syslog.timestamp", "Jan  5 12:34:56"),
            ParsedField::new("syslog.hostname", "myhost"),
            ParsedField::new("syslog.message", "hello world"),
        ],
    };

    let id = dummy_event_id();
    let converter = SyslogConverter;
    let ir = converter.convert(id, &result).unwrap();

    // Ensure all original fields are retained losslessly
    assert_eq!(
        ir.fields.get("syslog.message"),
        Some(&IrValue::String("hello world".to_string()))
    );
    assert_eq!(
        ir.fields.get("syslog.severity"),
        Some(&IrValue::String("2".to_string()))
    );
    assert_eq!(
        ir.fields.get("syslog.timestamp"),
        Some(&IrValue::String("Jan  5 12:34:56".to_string()))
    );
}

#[test]
fn cef_converter_basic() {
    let result = ParserResult {
        parser_id: "cef".to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: b"CEF:0|V|P|1.0|200|Test|3|src=1.2.3.4".to_vec(),
        fields: vec![
            ParsedField::new("cef.severity", "3"),
            ParsedField::new("src", "1.2.3.4"),
            ParsedField::new("cef.device_vendor", "V"),
        ],
    };

    let id = dummy_event_id();
    let converter = CefConverter;
    let ir = converter.convert(id, &result).unwrap();

    // Fields preserved
    assert_eq!(
        ir.fields.get("cef.device_vendor"),
        Some(&IrValue::String("V".to_string()))
    );
    assert_eq!(
        ir.fields.get("src"),
        Some(&IrValue::String("1.2.3.4".to_string()))
    );
}

#[test]
fn json_converter_basic() {
    let result = ParserResult {
        parser_id: "json-flat".to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: br#"{"timestamp":"2023","level":"error","count":42,"active":true}"#.to_vec(),
        fields: vec![
            ParsedField::new("timestamp", "2023"),
            ParsedField::new("level", "error"),
            ParsedField::new("count", "042"), // Leading zero
            ParsedField::new("active", "true"),
            ParsedField::new("missing", "null"),
        ],
    };

    let id = dummy_event_id();
    let converter = JsonConverter;
    let ir = converter.convert(id, &result).unwrap();

    // "042" stays "042" as a string to prevent silent type corruption
    assert_eq!(
        ir.fields.get("count"),
        Some(&IrValue::String("042".to_string()))
    );
    // true and null are safely mapped
    assert_eq!(ir.fields.get("active"), Some(&IrValue::Boolean(true)));
    assert_eq!(ir.fields.get("missing"), Some(&IrValue::Null));
}

#[test]
fn composite_converter_matches_correctly() {
    let result = ParserResult {
        parser_id: "json-flat".to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: br#"{"host":"srv1"}"#.to_vec(),
        fields: vec![ParsedField::new("host", "srv1")],
    };

    let id = dummy_event_id();
    let converter = CompositeConverter::default_registry();
    let ir = converter.convert(id, &result).unwrap();

    assert_eq!(ir.parser_id, "json-flat");
}
