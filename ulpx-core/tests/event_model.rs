use ulpx_core::event::{EventError, EventId, RawEvent, Source, Timestamp};

#[test]
fn event_id_validation() {
    assert!(matches!(EventId::new(""), Err(EventError::EmptyEventId)));

    let id = EventId::new("valid-id").unwrap();
    assert_eq!(id.as_str(), "valid-id");
}

#[test]
fn raw_event_round_trip_arbitrary_bytes() {
    let payload = vec![0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff];

    let id = EventId::new("event1").unwrap();
    let source = Source("unit-test".to_owned());

    let raw = RawEvent::new(id, payload.clone(), source);

    assert_eq!(raw.as_bytes(), payload.as_slice());
    assert_eq!(raw.into_bytes(), payload);
}

#[test]
fn raw_event_allows_empty_bytes() {
    let id = EventId::new("empty-payload").unwrap();
    let source = Source("unit-test".to_owned());

    let raw = RawEvent::new(id, Vec::new(), source);

    assert!(raw.as_bytes().is_empty());

    let clone = raw.clone();
    assert!(clone.as_bytes().is_empty());
}

#[test]
fn metadata_preservation() {
    let id = EventId::new("meta-id").unwrap();
    let source = Source("source-a".to_owned());

    let raw = RawEvent::new(id.clone(), b"foo".to_vec(), source.clone());

    assert_eq!(raw.metadata.event_id, id);
    assert_eq!(raw.metadata.source, source);
    assert!(raw.metadata.ingestion_timestamp.0 > 0);
}

#[test]
fn timestamp_ordering() {
    let timestamp_1 = Timestamp::now();

    std::thread::sleep(std::time::Duration::from_millis(1));

    let timestamp_2 = Timestamp::now();

    assert!(timestamp_1 < timestamp_2);
}

#[test]
fn raw_event_clone_preserves_bytes_and_metadata() {
    let id = EventId::new("clone-test").unwrap();
    let source = Source("unit-test".to_owned());
    let payload = vec![0x00, 0x10, 0x80, 0xff];

    let raw = RawEvent::new(id, payload.clone(), source);
    let clone = raw.clone();

    assert_eq!(clone.as_bytes(), payload.as_slice());
    assert_eq!(clone.metadata, raw.metadata);
}

#[test]
fn raw_event_as_bytes_is_read_only() {
    let id = EventId::new("immutability").unwrap();
    let source = Source("unit-test".to_owned());

    let raw = RawEvent::new(id, b"data".to_vec(), source);

    assert_eq!(raw.as_bytes(), b"data");
}
