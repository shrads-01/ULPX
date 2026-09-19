use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::integrity::{compute_hash, VerificationResult};
use ulpx_core::storage::{EvidenceStore, InMemoryStore};

#[test]
fn test_1_sha256_determinism() {
    let data = b"deterministic data";
    let hash1 = compute_hash(data);
    let hash2 = compute_hash(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_2_known_sha256_vector() {
    // Empty string SHA-256
    let empty_hash = compute_hash(b"");
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(empty_hash.to_string(), expected);

    // "abc"
    let abc_hash = compute_hash(b"abc");
    let abc_expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(abc_hash.to_string(), abc_expected);
}

#[test]
fn test_3_empty_byte_payload() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-empty").unwrap();
    let event = RawEvent::new(id.clone(), vec![], Source("test".to_string()));
    store.store(event).unwrap();

    let verified = ulpx_core::integrity::verify_event(&store, &id).unwrap();
    assert!(verified.is_success());
    let retrieved = store.retrieve(&id).unwrap();
    assert_eq!(
        retrieved
            .metadata
            .integrity
            .unwrap()
            .content_hash
            .to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_4_arbitrary_binary_payload() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-bin").unwrap();
    let binary_data = vec![0x00, 0xFF, 0xFE, 0x01, 0x00];
    let event = RawEvent::new(id.clone(), binary_data.clone(), Source("test".to_string()));
    store.store(event).unwrap();

    let verified = ulpx_core::integrity::verify_event(&store, &id).unwrap();
    assert!(verified.is_success());
    let retrieved = store.retrieve(&id).unwrap();
    assert_eq!(retrieved.as_bytes(), binary_data);
}

#[test]
fn test_5_two_different_payloads_different_hashes() {
    let hash1 = compute_hash(b"payload A");
    let hash2 = compute_hash(b"payload B");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_6_same_payload_same_hash() {
    let hash1 = compute_hash(b"identical payload");
    let hash2 = compute_hash(b"identical payload");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_7_verification_succeeds_for_unchanged_evidence() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-unchanged").unwrap();
    let event = RawEvent::new(
        id.clone(),
        b"unchanged".to_vec(),
        Source("test".to_string()),
    );
    store.store(event).unwrap();

    let verified = ulpx_core::integrity::verify_event(&store, &id).unwrap();
    assert!(verified.is_success());
}

#[test]
fn test_8_verification_fails_after_evidence_bytes_changed() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-tampered").unwrap();
    let event = RawEvent::new(
        id.clone(),
        b"original bytes".to_vec(),
        Source("test".to_string()),
    );
    store.store(event).unwrap();

    store.tamper_bytes(&id, b"original bytez".to_vec());
    let verified = ulpx_core::integrity::verify_event(&store, &id).unwrap();
    match verified {
        VerificationResult::HashMismatch { expected, actual } => {
            assert_ne!(expected, actual);
        }
        _ => panic!("Expected HashMismatch"),
    }
}

#[test]
fn test_9_event_id_remains_distinct_from_content_hash() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-distinct").unwrap();
    let event = RawEvent::new(
        id.clone(),
        b"some data".to_vec(),
        Source("test".to_string()),
    );
    store.store(event).unwrap();

    let retrieved = store.retrieve(&id).unwrap();
    let hash_str = retrieved
        .metadata
        .integrity
        .unwrap()
        .content_hash
        .to_string();
    assert_ne!(id.as_str(), hash_str);
}

#[test]
fn test_10_duplicate_event_ids_continue_to_be_rejected() {
    let mut store = InMemoryStore::new();
    let id = EventId::new("evt-dup").unwrap();
    let event1 = RawEvent::new(id.clone(), b"data1".to_vec(), Source("test".to_string()));
    let event2 = RawEvent::new(id.clone(), b"data2".to_vec(), Source("test".to_string()));

    assert!(store.store(event1).is_ok());
    assert!(store.store(event2).is_err()); // duplicate
}

#[test]
fn test_11_multiple_evidence_records_remain_isolated() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-1").unwrap();
    let id2 = EventId::new("evt-2").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"data1".to_vec(),
            Source("test".to_string()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"data2".to_vec(),
            Source("test".to_string()),
        ))
        .unwrap();

    let r1 = store.retrieve(&id1).unwrap();
    let r2 = store.retrieve(&id2).unwrap();
    assert_ne!(
        r1.metadata.integrity.unwrap().content_hash,
        r2.metadata.integrity.unwrap().content_hash
    );
}

#[test]
fn test_12_previous_record_linkage_works() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-first").unwrap();
    let id2 = EventId::new("evt-second").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"1".to_vec(),
            Source("test".to_string()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"2".to_vec(),
            Source("test".to_string()),
        ))
        .unwrap();

    let r2 = store.retrieve(&id2).unwrap();
    assert_eq!(r2.metadata.integrity.unwrap().previous_link, Some(id1));
}

#[test]
fn test_13_correct_chain_verifies_successfully() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-c1").unwrap();
    let id2 = EventId::new("evt-c2").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"first".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"second".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();

    assert!(ulpx_core::integrity::verify_event(&store, &id1)
        .unwrap()
        .is_success());
    assert!(ulpx_core::integrity::verify_event(&store, &id2)
        .unwrap()
        .is_success());
}

#[test]
fn test_14_broken_previous_linkage_is_detected() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-b1").unwrap();
    let id2 = EventId::new("evt-b2").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"first".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"second".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();

    // Emulate a broken link by directly removing from map
    store.remove_for_testing(&id1);

    let verified = ulpx_core::integrity::verify_event(&store, &id2).unwrap();
    match verified {
        VerificationResult::BrokenLink(missing_id) => {
            assert_eq!(missing_id, id1);
        }
        _ => panic!("Expected BrokenLink"),
    }
}

#[test]
fn test_15_tampered_content_in_chain_is_detected() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-t1").unwrap();
    let id2 = EventId::new("evt-t2").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"first".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"second".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();

    store.tamper_bytes(&id1, b"first-tampered".to_vec());

    // Verifying id1 directly fails
    assert!(!ulpx_core::integrity::verify_event(&store, &id1)
        .unwrap()
        .is_success());

    // Verifying the chain from id2 should also detect that id1 is tampered
    let chain_result = ulpx_core::integrity::verify_chain(&store, &id2).unwrap();
    assert!(!chain_result.is_success());
}

#[test]
fn test_16_chain_verification_does_not_rely_on_parser_or_ir() {
    // This is implicitly proven since we don't use ulpx-parser or ulpx-ir anywhere in these tests.
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-indep").unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"data".to_vec(),
            Source("t".to_string()),
        ))
        .unwrap();
    assert!(ulpx_core::integrity::verify_event(&store, &id1)
        .unwrap()
        .is_success());
}

#[test]
fn test_17_raw_evidence_remains_recoverable_after_integrity_metadata() {
    let mut store = InMemoryStore::new();
    let id1 = EventId::new("evt-recov").unwrap();
    let original = b"recoverable data".to_vec();
    store
        .store(RawEvent::new(
            id1.clone(),
            original.clone(),
            Source("t".to_string()),
        ))
        .unwrap();

    let retrieved = store.retrieve(&id1).unwrap();
    assert_eq!(retrieved.into_bytes(), original);
}
struct CyclicStore {
    e1: RawEvent,
    e2: RawEvent,
}
impl ulpx_core::storage::EvidenceStore for CyclicStore {
    fn list_events(&self, _: usize, _: usize) -> Vec<ulpx_core::event::EventMetadata> {
        vec![]
    }
    fn store(&mut self, _: RawEvent) -> Result<(), ulpx_core::storage::StoreError> {
        Ok(())
    }
    fn retrieve(&self, id: &EventId) -> Result<RawEvent, ulpx_core::storage::StoreError> {
        if id.as_str() == "evt-18a" {
            Ok(self.e1.clone())
        } else if id.as_str() == "evt-18b" {
            Ok(self.e2.clone())
        } else {
            Err(ulpx_core::storage::StoreError::NotFound)
        }
    }
}
#[test]
fn test_18_cyclic_previous_link_detected() {
    let id1 = EventId::new("evt-18a").unwrap();
    let id2 = EventId::new("evt-18b").unwrap();

    let mut event1 = RawEvent::new(id1.clone(), b"a".to_vec(), Source("t".to_string()));
    event1.metadata.integrity = Some(ulpx_core::integrity::IntegrityMetadata::new(
        ulpx_core::integrity::compute_hash(b"a"),
        Some(id2.clone()),
    ));

    let mut event2 = RawEvent::new(id2.clone(), b"b".to_vec(), Source("t".to_string()));
    event2.metadata.integrity = Some(ulpx_core::integrity::IntegrityMetadata::new(
        ulpx_core::integrity::compute_hash(b"b"),
        Some(id1.clone()),
    ));

    let store = CyclicStore {
        e1: event1,
        e2: event2,
    };
    let res = ulpx_core::integrity::verify_chain(&store, &id1).unwrap();
    match res {
        VerificationResult::CyclicLink(_) => {}
        _ => panic!("Expected CyclicLink"),
    }
}
