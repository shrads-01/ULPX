use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::storage::{EvidenceStore, InMemoryStore, StoreError};

#[test]
fn round_trip_arbitrary_bytes() {
    let payload = vec![0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff];
    let id = EventId::new("event1").unwrap();
    let src = Source("unit-test".to_owned());
    let raw = RawEvent::new(id.clone(), payload.clone(), src);

    let mut store = InMemoryStore::new();
    store.store(raw.clone()).unwrap();
    let retrieved = store.retrieve(&id).unwrap();

    assert_eq!(retrieved.as_bytes(), payload.as_slice());
    assert_eq!(retrieved.metadata.event_id, id);
}

#[test]
fn empty_payload_allowed() {
    let id = EventId::new("empty-payload").unwrap();
    let src = Source("unit-test".to_owned());
    let raw = RawEvent::new(id.clone(), Vec::new(), src);

    let mut store = InMemoryStore::new();
    store.store(raw.clone()).unwrap();
    let retrieved = store.retrieve(&id).unwrap();

    assert!(retrieved.as_bytes().is_empty());
    assert_eq!(retrieved.metadata.event_id, id);
}

#[test]
fn not_found_error() {
    let store = InMemoryStore::new();
    let missing_id = EventId::new("missing").unwrap();

    match store.retrieve(&missing_id) {
        Err(StoreError::NotFound) => {}
        _ => panic!("expected StoreError::NotFound"),
    }
}

#[test]
fn multiple_events_isolation() {
    let mut store = InMemoryStore::new();

    let id_a = EventId::new("a").unwrap();
    let id_b = EventId::new("b").unwrap();

    let raw_a = RawEvent::new(id_a.clone(), b"data-a".to_vec(), Source("src-a".to_owned()));
    let raw_b = RawEvent::new(id_b.clone(), b"data-b".to_vec(), Source("src-b".to_owned()));

    store.store(raw_a.clone()).unwrap();
    store.store(raw_b.clone()).unwrap();

    let got_a = store.retrieve(&id_a).unwrap();
    let got_b = store.retrieve(&id_b).unwrap();

    assert_eq!(got_a.as_bytes(), b"data-a");
    assert_eq!(got_b.as_bytes(), b"data-b");
    assert_ne!(got_a.metadata.event_id, got_b.metadata.event_id);
}
#[test]
fn duplicate_id_rejected() {
    let id = EventId::new("dup-id").unwrap();
    let src = Source("dup-test".to_owned());
    let raw1 = RawEvent::new(id.clone(), b"first".to_vec(), src.clone());
    let raw2 = RawEvent::new(id.clone(), b"second".to_vec(), src);
    let mut store = InMemoryStore::new();
    // First insertion succeeds.
    assert!(store.store(raw1.clone()).is_ok());
    // Second insertion with same ID must be rejected.
    match store.store(raw2) {
        Err(StoreError::DuplicateId) => {}
        _ => panic!("expected DuplicateId error"),
    }
    // Original event remains unchanged.
    let retrieved = store.retrieve(&id).unwrap();
    assert_eq!(retrieved.as_bytes(), b"first");
}
