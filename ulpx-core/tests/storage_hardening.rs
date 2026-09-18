use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::integrity::verify_chain;
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore, StoreError};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_temp_path() -> PathBuf {
    let mut path = env::temp_dir();
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    path.push(format!(
        "ulpx_test_store_hardening_v3_{}_{}",
        std::process::id(),
        count
    ));
    path
}

fn append_bytes(path: &PathBuf, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

#[test]
fn test_reopen_preserves_exact_semantics() {
    let path = get_temp_path();
    let id1 = EventId::new("evt1").unwrap();
    let raw1 = RawEvent::new(
        id1.clone(),
        b"binary\x00\x01\x02data".to_vec(),
        Source("src1".into()),
    );

    let id2 = EventId::new("evt2").unwrap();
    let raw2 = RawEvent::new(id2.clone(), vec![], Source("src2".into()));

    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        store.store(raw1.clone()).unwrap();
        store.store(raw2.clone()).unwrap();
    }

    {
        let store = LocalEvidenceStore::new(&path).unwrap();
        let r1 = store.retrieve(&id1).unwrap();
        assert_eq!(r1.as_bytes(), raw1.as_bytes());
        assert_eq!(r1.metadata.source, raw1.metadata.source);
        assert_eq!(
            r1.metadata.ingestion_timestamp,
            raw1.metadata.ingestion_timestamp
        );
        assert_eq!(r1.metadata.event_id, raw1.metadata.event_id);

        let r2 = store.retrieve(&id2).unwrap();
        assert!(r2.as_bytes().is_empty());
        assert_eq!(
            r2.metadata
                .integrity
                .as_ref()
                .unwrap()
                .previous_link
                .as_ref(),
            Some(&id1)
        );

        assert!(verify_chain(&store, &id2).unwrap().is_success());
    }
    let _ = fs::remove_file(path);
}

#[test]
fn test_duplicate_failure_does_not_corrupt_log() {
    let path = get_temp_path();
    let id1 = EventId::new("evt1").unwrap();
    let id2 = EventId::new("evt2").unwrap();
    let mut store = LocalEvidenceStore::new(&path).unwrap();
    store
        .store(RawEvent::new(
            id1.clone(),
            b"data1".to_vec(),
            Source("src1".into()),
        ))
        .unwrap();

    let orig_len = fs::metadata(&path).unwrap().len();

    // Duplicate insertion fails
    let err = store
        .store(RawEvent::new(
            id1.clone(),
            b"data1-changed".to_vec(),
            Source("src1".into()),
        ))
        .unwrap_err();
    assert_eq!(err, StoreError::DuplicateId);

    // Verify original event untouched
    let r1 = store.retrieve(&id1).unwrap();
    assert_eq!(r1.as_bytes(), b"data1");

    // File length uncorrupted
    assert_eq!(fs::metadata(&path).unwrap().len(), orig_len);

    // Next insert works
    store
        .store(RawEvent::new(
            id2.clone(),
            b"data2".to_vec(),
            Source("src2".into()),
        ))
        .unwrap();

    // Reopen and check
    let store2 = LocalEvidenceStore::new(&path).unwrap();
    let r2 = store2.retrieve(&id2).unwrap();
    assert_eq!(r2.metadata.integrity.unwrap().previous_link, Some(id1));

    let _ = fs::remove_file(path);
}

#[test]
fn test_crash_recovery_depth() {
    let path = get_temp_path();
    let id1 = EventId::new("evt1").unwrap();

    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        store
            .store(RawEvent::new(
                id1.clone(),
                b"data1".to_vec(),
                Source("src1".into()),
            ))
            .unwrap();
    }

    // Case 1: truncated magic/header
    append_bytes(&path, b"ULP");
    {
        let store = LocalEvidenceStore::new(&path).unwrap();
        assert!(store.retrieve(&id1).is_ok()); // Survives
    }

    // Case 2: valid header, but payload truncated exactly in the middle
    let id_fail = EventId::new("fail").unwrap();
    {
        let temp_path = get_temp_path();
        {
            let mut tmp_store = LocalEvidenceStore::new(&temp_path).unwrap();
            tmp_store
                .store(RawEvent::new(
                    id_fail.clone(),
                    b"long_payload_here".to_vec(),
                    Source("src".into()),
                ))
                .unwrap();
        }
        let mut data = fs::read(&temp_path).unwrap();
        data.truncate(data.len() - 5); // cut off the last 5 bytes
        append_bytes(&path, &data);
        let _ = fs::remove_file(temp_path);
    }

    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        assert!(store.retrieve(&id1).is_ok());
        assert!(store.retrieve(&id_fail).is_err()); // partial record not indexed

        let id2 = EventId::new("evt2").unwrap();
        store
            .store(RawEvent::new(
                id2.clone(),
                b"data2".to_vec(),
                Source("src2".into()),
            ))
            .unwrap();
        assert!(verify_chain(&store, &id2).unwrap().is_success());
    }
    let _ = fs::remove_file(path);
}

#[test]
fn test_corruption_matrix() {
    let path = get_temp_path();
    let id0 = EventId::new("evt0").unwrap();
    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        store
            .store(RawEvent::new(
                id0.clone(),
                b"data0".to_vec(),
                Source("src0".into()),
            ))
            .unwrap();
    }

    // Base structure of a valid record for our matrix baseline
    let valid_id = EventId::new("evt_bad").unwrap();
    let valid_raw = RawEvent::new(valid_id.clone(), b"bad_data".to_vec(), Source("src".into()));
    let temp_path = get_temp_path();
    {
        let mut tmp = LocalEvidenceStore::new(&temp_path).unwrap();
        tmp.store(valid_raw).unwrap();
    }
    let valid_record = fs::read(&temp_path).unwrap();
    let _ = fs::remove_file(temp_path);

    let mut counter = 1;

    // Test helper to apply a specific corruption and verify recovery semantics
    let mut append_and_recover = |corrupt_bytes: Vec<u8>| {
        // We append the corrupted record to the store containing id0
        append_bytes(&path, &corrupt_bytes);

        // Ensure the store handles it during init
        let mut store = LocalEvidenceStore::new(&path).unwrap();

        // 1. The known-good prior event MUST remain retrievable
        assert!(store.retrieve(&id0).is_ok());

        // 2. The malformed event MUST NOT be indexed
        assert!(store.retrieve(&valid_id).is_err());

        // 3. A subsequent valid append MUST work and be verifiable
        let id_new = EventId::new(format!("evt_new_{}", counter)).unwrap();
        store
            .store(RawEvent::new(
                id_new.clone(),
                b"data_new".to_vec(),
                Source("src".into()),
            ))
            .unwrap();
        assert!(verify_chain(&store, &id_new).unwrap().is_success());

        counter += 1;
    };

    // --- CORRUPTION SCENARIOS ---

    // 1. Invalid magic
    let mut corrupt = valid_record.clone();
    corrupt[0..4].copy_from_slice(b"BADX");
    append_and_recover(corrupt);

    // 2. Invalid total record length (too small / inconsistent)
    let mut corrupt = valid_record.clone();
    let small_len = 5u32.to_le_bytes();
    corrupt[4..8].copy_from_slice(&small_len);
    append_and_recover(corrupt);

    // 3. Invalid EventId UTF-8 (e.g. 0xff)
    let mut corrupt = valid_record.clone();
    corrupt[12] = 0xff; // First byte of event ID string
    append_and_recover(corrupt);

    // 4. Invalid Source UTF-8
    // Find source offset: Magic(4)+Len(4)+IdLen(4)+Id(7)+Timestamp(8)+SrcLen(4)
    // evt_bad len = 7. 4+4+4+7+8+4 = 31
    let mut corrupt = valid_record.clone();
    corrupt[31] = 0xff;
    append_and_recover(corrupt);

    // 5. Invalid integrity flag (must be 0 or 1, we set it to 2)
    // Source 'src' len = 3. offset = 31 + 3 = 34
    let mut corrupt = valid_record.clone();
    corrupt[34] = 0x02;
    append_and_recover(corrupt);

    // 6. Invalid previous-link flag (set to 2)
    // Assuming integrity exists (it's the first record in its chain, but wait, evt_bad has id0 as prev link!)
    // integrity flag = 1 (1 byte). hash = 32 bytes. prev_link flag = 1 (1 byte).
    // offset = 34 + 1 + 32 = 67
    let mut corrupt = valid_record.clone();
    corrupt[67] = 0x02;
    append_and_recover(corrupt);

    // 7. Truncated integrity hash
    let mut corrupt = valid_record.clone();
    corrupt.truncate(34 + 1 + 10); // Cut in the middle of the 32 byte hash
    append_and_recover(corrupt);

    // 8. Truncated previous-link / EventId data
    let mut corrupt = valid_record.clone();
    corrupt.truncate(67 + 1 + 2); // Cut in the middle of prev link event id
    append_and_recover(corrupt);

    // 9. Invalid raw-length field (larger than remaining bytes)
    let mut corrupt = valid_record.clone();
    let raw_len_idx = corrupt.len() - 8 - 4; // 'bad_data' is 8 bytes. raw_len is 4 bytes before it.
    let huge_len = 100u32.to_le_bytes();
    corrupt[raw_len_idx..raw_len_idx + 4].copy_from_slice(&huge_len);
    append_and_recover(corrupt);

    // 10. Trailing bytes / structurally inconsistent bytes after an otherwise complete record
    let mut corrupt = valid_record.clone();
    corrupt.extend_from_slice(b"trailing_garbage");
    // We adjust the total length so the reader sees the trailing bytes as part of this record payload
    let new_len = (corrupt.len() - 8) as u32; // Magic+Len is 8 bytes
    corrupt[4..8].copy_from_slice(&new_len.to_le_bytes());
    append_and_recover(corrupt);

    // 11. Mid-payload truncation
    let mut corrupt = valid_record.clone();
    corrupt.truncate(corrupt.len() - 4); // missing last 4 bytes of 'bad_data'
    append_and_recover(corrupt);

    let _ = fs::remove_file(path);
}

#[test]
fn test_resource_safety_malicious_length() {
    let path = get_temp_path();
    let id1 = EventId::new("evt1").unwrap();
    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        store
            .store(RawEvent::new(
                id1.clone(),
                b"data1".to_vec(),
                Source("src1".into()),
            ))
            .unwrap();
    }

    // Append a record with a maliciously large EventId length (e.g. 2GB)
    // The parser MUST NOT allocate 2GB before checking the file bounds.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ULPX");
    payload.extend_from_slice(&2000000000u32.to_le_bytes()); // total len
    payload.extend_from_slice(&2000000000u32.to_le_bytes()); // event id len

    append_bytes(&path, &payload);

    let mut store = LocalEvidenceStore::new(&path).unwrap();
    assert!(store.retrieve(&id1).is_ok()); // known-good prior event survives

    // Subsequent valid append works
    let id2 = EventId::new("evt2").unwrap();
    store
        .store(RawEvent::new(
            id2.clone(),
            b"data2".to_vec(),
            Source("src2".into()),
        ))
        .unwrap();

    assert!(verify_chain(&store, &id2).unwrap().is_success()); // verifiable

    let _ = fs::remove_file(path);
}

#[test]
fn test_file_lifecycle_empty_and_repeated() {
    let path = get_temp_path();
    {
        let store = LocalEvidenceStore::new(&path).unwrap();
        assert!(store.retrieve(&EventId::new("none").unwrap()).is_err());
    }
    {
        let store = LocalEvidenceStore::new(&path).unwrap();
        assert!(store.retrieve(&EventId::new("none").unwrap()).is_err());
    }
    let _ = fs::remove_file(path);
}
