//! Integration tests for the universal framing layer.
//!
//! Tests cover the complete relationship: raw bytes → framer → FramedRecords,
//! plus error/incomplete handling.

use ulpx_core::framing::json_object::JsonObjectFramer;
use ulpx_core::framing::length_prefix::LengthPrefixFramer;
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::framing::{FrameError, FramedRecord, Framer, MAX_FRAME_BYTES};

// ─── NewlineFramer ───────────────────────────────────────────────────────────

#[test]
fn newline_ordinary_records() {
    let (records, err) = NewlineFramer.frame_all(b"alpha\nbeta\ngamma\n");
    assert_eq!(err, None);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].as_bytes(), b"alpha");
    assert_eq!(records[1].as_bytes(), b"beta");
    assert_eq!(records[2].as_bytes(), b"gamma");
}

#[test]
fn newline_crlf_stripped() {
    let (records, err) = NewlineFramer.frame_all(b"line1\r\nline2\r\n");
    assert_eq!(err, None);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].as_bytes(), b"line1");
    assert_eq!(records[1].as_bytes(), b"line2");
}

#[test]
fn newline_empty_input() {
    let (records, err) = NewlineFramer.frame_all(b"");
    assert_eq!(err, None);
    assert!(records.is_empty());
}

#[test]
fn newline_blank_line_produces_empty_record() {
    let (records, _) = NewlineFramer.frame_all(b"a\n\nb\n");
    assert_eq!(records.len(), 3);
    assert!(records[1].is_empty());
}

#[test]
fn newline_incomplete_trailing() {
    let (records, err) = NewlineFramer.frame_all(b"done\nnot yet");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].as_bytes(), b"done");
    assert_eq!(err, Some(FrameError::Incomplete));
}

#[test]
fn newline_binary_bytes_preserved() {
    let input = b"binary\x00\x01\x7f\xff\n";
    let (records, err) = NewlineFramer.frame_all(input);
    assert_eq!(err, None);
    assert_eq!(records[0].as_bytes(), b"binary\x00\x01\x7f\xff");
}

#[test]
fn newline_multiple_records_no_cross_contamination() {
    let (records, _) = NewlineFramer.frame_all(b"aaa\nbbb\nccc\n");
    assert_eq!(records[0].as_bytes(), b"aaa");
    assert_eq!(records[1].as_bytes(), b"bbb");
    assert_eq!(records[2].as_bytes(), b"ccc");
}

#[test]
fn newline_framed_record_bytes_preserved_exactly() {
    let raw = b"exact bytes preserved\n";
    let (records, _) = NewlineFramer.frame_all(raw);
    assert_eq!(records[0].as_bytes(), b"exact bytes preserved");
}

// ─── LengthPrefixFramer ──────────────────────────────────────────────────────

fn lp_encode(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn lp_ordinary_record() {
    let input = lp_encode(b"hello");
    let (records, err) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(err, None);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].as_bytes(), b"hello");
}

#[test]
fn lp_multiple_records() {
    let mut input = lp_encode(b"first");
    input.extend_from_slice(&lp_encode(b"second"));
    let (records, err) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(err, None);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].as_bytes(), b"first");
    assert_eq!(records[1].as_bytes(), b"second");
}

#[test]
fn lp_empty_payload() {
    let input = lp_encode(b"");
    let (records, err) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(err, None);
    assert_eq!(records.len(), 1);
    assert!(records[0].is_empty());
}

#[test]
fn lp_empty_input() {
    let (records, err) = LengthPrefixFramer.frame_all(b"");
    assert_eq!(err, None);
    assert!(records.is_empty());
}

#[test]
fn lp_incomplete_prefix() {
    let (_, err) = LengthPrefixFramer.frame_all(b"\x00\x00");
    assert_eq!(err, Some(FrameError::Incomplete));
}

#[test]
fn lp_incomplete_payload() {
    // Declare 5 bytes, supply only 3.
    let input = vec![0x00, 0x00, 0x00, 0x05, b'a', b'b', b'c'];
    let (_, err) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(err, Some(FrameError::Incomplete));
}

#[test]
fn lp_oversized_frame() {
    let size = (MAX_FRAME_BYTES + 1) as u32;
    let input = size.to_be_bytes().to_vec();
    let (_, err) = LengthPrefixFramer.frame_all(&input);
    assert!(matches!(err, Some(FrameError::OversizedFrame(_))));
}

#[test]
fn lp_binary_bytes_preserved() {
    let payload = vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
    let input = lp_encode(&payload);
    let (records, _) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(records[0].as_bytes(), payload.as_slice());
}

#[test]
fn lp_multiple_records_no_cross_contamination() {
    let mut input = lp_encode(b"aaa");
    input.extend_from_slice(&lp_encode(b"bbb"));
    let (records, _) = LengthPrefixFramer.frame_all(&input);
    assert_eq!(records[0].as_bytes(), b"aaa");
    assert_eq!(records[1].as_bytes(), b"bbb");
}

// ─── JsonObjectFramer ────────────────────────────────────────────────────────

#[test]
fn json_single_object() {
    let (records, err) = JsonObjectFramer.frame_all(br#"{"a":1}"#);
    assert_eq!(err, None);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].as_bytes(), br#"{"a":1}"#);
}

#[test]
fn json_multiple_objects() {
    let (records, err) = JsonObjectFramer.frame_all(br#"{"x":1}{"y":2}"#);
    assert_eq!(err, None);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].as_bytes(), br#"{"x":1}"#);
    assert_eq!(records[1].as_bytes(), br#"{"y":2}"#);
}

#[test]
fn json_empty_input() {
    let (records, err) = JsonObjectFramer.frame_all(b"");
    assert_eq!(err, None);
    assert!(records.is_empty());
}

#[test]
fn json_nested_object_preserved() {
    let input = br#"{"outer":{"inner":42}}"#;
    let (records, _) = JsonObjectFramer.frame_all(input);
    assert_eq!(records[0].as_bytes(), input);
}

#[test]
fn json_incomplete_object() {
    let (_, err) = JsonObjectFramer.frame_all(br#"{"key":"value""#);
    assert_eq!(err, Some(FrameError::Incomplete));
}

#[test]
fn json_non_object_malformed() {
    let (_, err) = JsonObjectFramer.frame_all(b"[1,2,3]");
    assert!(matches!(err, Some(FrameError::Malformed(_))));
}

#[test]
fn json_invalid_utf8() {
    let (_, err) = JsonObjectFramer.frame_all(b"\xff\xfe");
    assert!(matches!(err, Some(FrameError::Malformed(_))));
}

#[test]
fn json_bytes_preserved_exactly() {
    let raw = br#"{"k":"v","n":42}"#;
    let (records, _) = JsonObjectFramer.frame_all(raw);
    assert_eq!(records[0].as_bytes(), raw);
}

#[test]
fn json_multiple_records_no_cross_contamination() {
    let (records, _) = JsonObjectFramer.frame_all(br#"{"a":1}{"b":2}{"c":3}"#);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].as_bytes(), br#"{"a":1}"#);
    assert_eq!(records[1].as_bytes(), br#"{"b":2}"#);
    assert_eq!(records[2].as_bytes(), br#"{"c":3}"#);
}

// ─── FramedRecord API ────────────────────────────────────────────────────────

#[test]
fn framed_record_into_bytes() {
    let record = FramedRecord::new(b"data".to_vec());
    assert_eq!(record.clone().into_bytes(), b"data");
}

#[test]
fn framed_record_len_and_is_empty() {
    let empty = FramedRecord::new(vec![]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);

    let non_empty = FramedRecord::new(b"x".to_vec());
    assert!(!non_empty.is_empty());
    assert_eq!(non_empty.len(), 1);
}
