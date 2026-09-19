use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use ulpx_core::event::{EventId, RawEvent};
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::integrity::verify_chain;
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore, StoreError};
use ulpx_ingest::{ingest_stream, IngestionError};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_temp_path() -> PathBuf {
    let mut path = env::temp_dir();
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    path.push(format!("ulpx_test_ingest_{}_{}", std::process::id(), count));
    path
}

fn with_store<F>(f: F)
where
    F: FnOnce(&PathBuf, &mut LocalEvidenceStore),
{
    let path = get_temp_path();
    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        f(&path, &mut store);
    }
    let _ = fs::remove_file(path);
}

fn gen_id(src: &str, idx: u64, raw: &[u8]) -> ulpx_core::event::EventId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((src.len() as u32).to_be_bytes());
    hasher.update(src.as_bytes());
    hasher.update(idx.to_be_bytes());
    hasher.update(raw);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        use std::fmt::Write;
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    ulpx_core::event::EventId::new(hex).unwrap()
}

#[test]
fn test_ingest_crlf_byte_preservation() {
    with_store(|_path, store| {
        let input = b"record\r\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_crlf", &framer, store).unwrap();

        assert_eq!(res.total_records, 1);
        assert_eq!(res.stored_records, 1);

        // Assert exact byte preservation
        let id = gen_id("test_crlf", 0, b"record\r\n");
        let evt = store.retrieve(&id).unwrap();
        assert_eq!(evt.as_bytes(), b"record\r\n");
    });
}

#[test]
fn test_ingest_multiple_crlf_byte_preservation() {
    with_store(|_path, store| {
        let input = b"one\r\ntwo\r\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_multi_crlf", &framer, store).unwrap();

        assert_eq!(res.total_records, 2);

        let id1 = gen_id("test_multi_crlf", 0, b"one\r\n");
        let evt1 = store.retrieve(&id1).unwrap();
        assert_eq!(evt1.as_bytes(), b"one\r\n");

        let id2 = gen_id("test_multi_crlf", 1, b"two\r\n");
        let evt2 = store.retrieve(&id2).unwrap();
        assert_eq!(evt2.as_bytes(), b"two\r\n");
    });
}

#[test]
fn test_ingest_lf_byte_preservation() {
    with_store(|_path, store| {
        let input = b"record\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_lf", &framer, store).unwrap();

        assert_eq!(res.total_records, 1);
        let id = gen_id("test_lf", 0, b"record\n");
        let evt = store.retrieve(&id).unwrap();
        assert_eq!(evt.as_bytes(), b"record\n");
    });
}

#[test]
fn test_ingest_single_record() {
    with_store(|_path, store| {
        let input = b"single record payload\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_src", &framer, store).unwrap();
        assert_eq!(res.total_records, 1);
    });
}

#[test]
fn test_ingest_multiple_records() {
    with_store(|_path, store| {
        let input = b"record 1\nrecord 2\nrecord 3\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_src", &framer, store).unwrap();
        assert_eq!(res.total_records, 3);
    });
}

#[test]
fn test_ingest_empty_input() {
    with_store(|_path, store| {
        let input = b"";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_empty", &framer, store).unwrap();
        assert_eq!(res.total_records, 0);
    });
}

#[test]
fn test_ingest_binary_bytes() {
    with_store(|_path, store| {
        let input = b"binary\x00\x01\x7f\xff\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_bin", &framer, store).unwrap();
        assert_eq!(res.total_records, 1);

        let id = gen_id("test_bin", 0, b"binary\x00\x01\x7f\xff\n");
        let evt = store.retrieve(&id).unwrap();
        assert_eq!(evt.as_bytes(), b"binary\x00\x01\x7f\xff\n");
    });
}

#[test]
fn test_ingest_incomplete_record_fails() {
    with_store(|_path, store| {
        let input = b"missing newline at the end";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "test_inc", &framer, store);
        assert!(matches!(
            res,
            Err(IngestionError::Framing(
                ulpx_core::framing::FrameError::Incomplete
            ))
        ));
    });
}

#[test]
fn test_ingest_duplicate_semantics() {
    with_store(|_path, store| {
        let input = b"duplicate content\n";
        let framer = NewlineFramer;
        let res1 = ingest_stream(&input[..], "dup_src", &framer, store).unwrap();
        assert_eq!(res1.stored_records, 1);

        let res2 = ingest_stream(&input[..], "dup_src", &framer, store).unwrap();
        assert_eq!(res2.stored_records, 0);
    });
}

#[test]
fn test_ingest_identical_records_in_same_stream_do_not_collapse() {
    with_store(|_path, store| {
        let input = b"same\nsame\n";
        let framer = NewlineFramer;
        let res = ingest_stream(&input[..], "same_src", &framer, store).unwrap();
        assert_eq!(res.stored_records, 2);
    });
}

#[test]
fn test_reopen_and_verify_chain() {
    let path = get_temp_path();
    {
        let mut store = LocalEvidenceStore::new(&path).unwrap();
        let input = b"event A\nevent B\n";
        let framer = NewlineFramer;
        ingest_stream(&input[..], "persist_src", &framer, &mut store).unwrap();
    }
    {
        let store = LocalEvidenceStore::new(&path).unwrap();
        let id_b = gen_id("persist_src", 1, b"event B\n");
        assert!(verify_chain(&store, &id_b).unwrap().is_success());
    }
    let _ = fs::remove_file(path);
}

struct FailingStore {
    fail_after: usize,
    stored: usize,
}
impl EvidenceStore for FailingStore {
    fn list_events(&self, _: usize, _: usize) -> Vec<ulpx_core::event::EventMetadata> {
        vec![]
    }
    fn store(&mut self, _event: RawEvent) -> Result<(), StoreError> {
        if self.stored >= self.fail_after {
            return Err(StoreError::Internal("mock failure".into()));
        }
        self.stored += 1;
        Ok(())
    }
    fn retrieve(&self, _id: &EventId) -> Result<RawEvent, StoreError> {
        Err(StoreError::NotFound)
    }
}

#[test]
fn test_ingest_partial_write_atomicity() {
    let mut store = FailingStore {
        fail_after: 2,
        stored: 0,
    };
    let input = b"one\ntwo\nthree\nfour\n";
    let framer = NewlineFramer;

    let res = ingest_stream(&input[..], "fail_src", &framer, &mut store);
    match res {
        Err(IngestionError::Storage {
            err,
            stored_records,
        }) => {
            assert_eq!(stored_records, 2);
            assert!(matches!(err, StoreError::Internal(_)));
        }
        _ => panic!("Expected Storage error with 2 stored_records"),
    }
}
