//! Integration tests for the parser runtime.
//!
//! Tests cover:
//! - ParserRegistry: registration, duplicate rejection, lookup
//! - JsonParser, CefParser, SyslogParser: real parsing behavior
//! - End-to-end: raw bytes → NewlineFramer → ParserRegistry → ParserResult

use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::framing::{FramedRecord, Framer};
use ulpx_core::parser::cef::{CefParser, PARSER_ID as CEF_ID};
use ulpx_core::parser::json::{JsonParser, PARSER_ID as JSON_ID};
use ulpx_core::parser::syslog::{SyslogParser, PARSER_ID as SYSLOG_ID};
use ulpx_core::parser::{LifecycleStage, Parser, ParserError, ParserRegistry, ParserResult};

// ─── Registry ────────────────────────────────────────────────────────────────

#[test]
fn registry_register_and_get() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    assert!(reg.get(JSON_ID).is_some());
    assert_eq!(reg.len(), 1);
}

#[test]
fn registry_duplicate_rejected() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    let result = reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed);
    assert!(result.is_err());
    // Error message should mention the duplicate ID.
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains(JSON_ID));
}

#[test]
fn registry_not_found_returns_none() {
    let reg = ParserRegistry::new();
    assert!(reg.get("no-such-parser").is_none());
}

#[test]
fn registry_lifecycle_stage_accessible() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(CefParser::new()), LifecycleStage::Candidate)
        .unwrap();
    assert_eq!(reg.stage(CEF_ID), Some(LifecycleStage::Candidate));
}

#[test]
fn registry_is_empty_and_len() {
    let mut reg = ParserRegistry::new();
    assert!(reg.is_empty());
    reg.register(Box::new(SyslogParser::new()), LifecycleStage::Deployed)
        .unwrap();
    assert!(!reg.is_empty());
    assert_eq!(reg.len(), 1);
}

// ─── JsonParser ──────────────────────────────────────────────────────────────

#[test]
fn json_parser_flat_object() {
    let record = FramedRecord::new(br#"{"host":"srv1","port":"9200"}"#.to_vec());
    let result = JsonParser::new().parse(&record).unwrap();
    assert_eq!(find_field(&result, "host"), Some("srv1"));
    assert_eq!(find_field(&result, "port"), Some("9200"));
}

#[test]
fn json_parser_unsupported_for_non_json() {
    let record = FramedRecord::new(b"not json".to_vec());
    assert_eq!(
        JsonParser::new().parse(&record),
        Err(ParserError::Unsupported)
    );
}

#[test]
fn json_parser_raw_bytes_preserved() {
    let input = br#"{"k":"v"}"#;
    let record = FramedRecord::new(input.to_vec());
    let result = JsonParser::new().parse(&record).unwrap();
    assert_eq!(result.raw_bytes, input);
}

#[test]
fn json_parser_metadata_correct() {
    let p = JsonParser::new();
    assert_eq!(p.metadata().id, JSON_ID);
    assert_eq!(p.metadata().format, "JSON");
}

#[test]
fn json_parser_nested_as_raw_text() {
    let record = FramedRecord::new(br#"{"meta":{"version":2}}"#.to_vec());
    let result = JsonParser::new().parse(&record).unwrap();
    let meta_val = find_field(&result, "meta").unwrap();
    assert!(meta_val.contains("version"));
}

// ─── CefParser ───────────────────────────────────────────────────────────────

#[test]
fn cef_parser_basic() {
    let input = b"CEF:0|Acme|Widget|1.0|100|Login|5|";
    let record = FramedRecord::new(input.to_vec());
    let result = CefParser::new().parse(&record).unwrap();
    assert_eq!(find_field(&result, "cef.device_vendor"), Some("Acme"));
    assert_eq!(find_field(&result, "cef.severity"), Some("5"));
}

#[test]
fn cef_parser_extensions() {
    let input = b"CEF:0|V|P|1.0|200|Test|3|src=1.2.3.4 dst=5.6.7.8";
    let record = FramedRecord::new(input.to_vec());
    let result = CefParser::new().parse(&record).unwrap();
    assert_eq!(find_field(&result, "src"), Some("1.2.3.4"));
    assert_eq!(find_field(&result, "dst"), Some("5.6.7.8"));
}

#[test]
fn cef_parser_unsupported_for_non_cef() {
    let record = FramedRecord::new(b"not CEF".to_vec());
    assert_eq!(
        CefParser::new().parse(&record),
        Err(ParserError::Unsupported)
    );
}

#[test]
fn cef_parser_raw_bytes_preserved() {
    let input = b"CEF:0|V|P|1|1|N|5|";
    let record = FramedRecord::new(input.to_vec());
    let result = CefParser::new().parse(&record).unwrap();
    assert_eq!(result.raw_bytes, input);
}

// ─── SyslogParser ────────────────────────────────────────────────────────────

#[test]
fn syslog_parser_with_priority() {
    let input = b"<34>Jan  5 12:34:56 myhost myapp: hello world";
    let record = FramedRecord::new(input.to_vec());
    let result = SyslogParser::new().parse(&record).unwrap();
    assert_eq!(find_field(&result, "syslog.priority"), Some("34"));
    assert_eq!(find_field(&result, "syslog.hostname"), Some("myhost"));
    assert_eq!(find_field(&result, "syslog.tag"), Some("myapp"));
    assert_eq!(find_field(&result, "syslog.message"), Some("hello world"));
}

#[test]
fn syslog_parser_without_priority() {
    let input = b"Feb 14 08:00:00 server1 kernel: something happened";
    let record = FramedRecord::new(input.to_vec());
    let result = SyslogParser::new().parse(&record).unwrap();
    assert!(find_field(&result, "syslog.priority").is_none());
    assert_eq!(find_field(&result, "syslog.tag"), Some("kernel"));
}

#[test]
fn syslog_parser_raw_bytes_preserved() {
    let input = b"<13>Mar  1 00:00:01 host tag: msg";
    let record = FramedRecord::new(input.to_vec());
    let result = SyslogParser::new().parse(&record).unwrap();
    assert_eq!(result.raw_bytes, input);
}

#[test]
fn syslog_parser_rfc5424_unsupported() {
    let input = b"<165>1 2023-01-01T00:00:00Z host app - - - message";
    let record = FramedRecord::new(input.to_vec());
    assert_eq!(
        SyslogParser::new().parse(&record),
        Err(ParserError::Unsupported)
    );
}

// ─── End-to-end: framing → registry dispatch ─────────────────────────────────

#[test]
fn end_to_end_json_via_registry() {
    // Build registry.
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    reg.register(Box::new(CefParser::new()), LifecycleStage::Deployed)
        .unwrap();
    reg.register(Box::new(SyslogParser::new()), LifecycleStage::Deployed)
        .unwrap();

    // Frame a newline-delimited JSON record.
    let raw = b"{\"event\":\"login\",\"user\":\"alice\"}\n";
    let (frames, err) = NewlineFramer.frame_all(raw);
    assert_eq!(err, None);
    assert_eq!(frames.len(), 1);

    // Dispatch through registry.
    let result = reg.parse_first(&frames[0]).unwrap();
    assert_eq!(result.parser_id, JSON_ID);
    assert_eq!(find_field(&result, "event"), Some("login"));
    assert_eq!(find_field(&result, "user"), Some("alice"));
    // Original bytes preserved.
    assert_eq!(result.raw_bytes, br#"{"event":"login","user":"alice"}"#);
}

#[test]
fn end_to_end_cef_via_registry() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    reg.register(Box::new(CefParser::new()), LifecycleStage::Deployed)
        .unwrap();

    let raw = b"CEF:0|Vendor|Product|1.0|100|TestEvent|7|\n";
    let (frames, _) = NewlineFramer.frame_all(raw);
    let result = reg.parse_first(&frames[0]).unwrap();
    assert_eq!(result.parser_id, CEF_ID);
    assert_eq!(find_field(&result, "cef.device_vendor"), Some("Vendor"));
}

#[test]
fn end_to_end_syslog_via_registry() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    reg.register(Box::new(CefParser::new()), LifecycleStage::Deployed)
        .unwrap();
    reg.register(Box::new(SyslogParser::new()), LifecycleStage::Deployed)
        .unwrap();

    let raw = b"<34>Jan  5 12:34:56 myhost myapp: hello world\n";
    let (frames, _) = NewlineFramer.frame_all(raw);
    let result = reg.parse_first(&frames[0]).unwrap();
    assert_eq!(result.parser_id, SYSLOG_ID);
    assert_eq!(find_field(&result, "syslog.hostname"), Some("myhost"));
}

#[test]
fn end_to_end_no_parser_matches() {
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();

    // A CEF record without the CEF parser registered.
    let raw = b"CEF:0|V|P|1|1|N|5|\n";
    let (frames, _) = NewlineFramer.frame_all(raw);
    let result = reg.parse_first(&frames[0]);
    assert_eq!(result, Err(ParserError::Unsupported));
}

#[test]
fn end_to_end_original_evidence_not_modified() {
    // Verify that the raw bytes in ParserResult match the FramedRecord bytes
    // exactly, not the original newline-terminated line.
    let mut reg = ParserRegistry::new();
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();

    let raw_line = b"{\"k\":\"v\"}\n";
    let (frames, _) = NewlineFramer.frame_all(raw_line);
    // After newline framing the newline is stripped from the frame.
    assert_eq!(frames[0].as_bytes(), br#"{"k":"v"}"#);

    let result = reg.parse_first(&frames[0]).unwrap();
    // raw_bytes in the result preserves the framed record bytes (without newline).
    assert_eq!(result.raw_bytes, br#"{"k":"v"}"#);
}

// ─── Helper ──────────────────────────────────────────────────────────────────

fn find_field<'a>(result: &'a ParserResult, name: &str) -> Option<&'a str> {
    result
        .fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.raw_value.as_str())
}
#[test]
fn end_to_end_malformed_bubbles_up() {
    let mut reg = ParserRegistry::new();
    // JSON parser is registered first.
    reg.register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();

    // Valid JSON outer structure but malformed inside.
    let raw = b"{\"event\": }\n";
    let (frames, _) = NewlineFramer.frame_all(raw);
    let result = reg.parse_first(&frames[0]);
    // It should NOT swallow the Malformed error and return Unsupported.
    assert!(matches!(result, Err(ParserError::Malformed(_))));
}
