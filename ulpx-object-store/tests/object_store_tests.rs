use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use ulpx_object_store::{LocalObjectStore, ObjectStore, ObjectStoreError};

fn get_temp_dir() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "ulpx_obj_store_test_{}_{}",
        std::process::id(),
        count
    ));
    let _ = fs::remove_dir_all(&path);
    path
}

#[test]
fn test_put_get_round_trip() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "test/obj1";
    let data = b"hello object store";

    store.put(key, data).unwrap();
    assert!(store.exists(key).unwrap());

    let retrieved = store.get(key).unwrap();
    assert_eq!(retrieved, data);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_arbitrary_binary_bytes() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "binary_obj";
    let data = vec![0x00, 0xFF, 0x12, 0x89, 0x00];

    store.put(key, &data).unwrap();
    let retrieved = store.get(key).unwrap();
    assert_eq!(retrieved, data);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_empty_object() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "empty";
    let data: Vec<u8> = vec![];

    store.put(key, &data).unwrap();
    assert_eq!(store.get(key).unwrap(), data);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_nested_object_key() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "deeply/nested/key/file.bin";

    store.put(key, b"nested").unwrap();
    assert_eq!(store.get(key).unwrap(), b"nested");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_missing_object() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();

    assert!(!store.exists("missing").unwrap());
    match store.get("missing") {
        Err(ObjectStoreError::NotFound(_)) => {}
        _ => panic!("Expected NotFound error"),
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_duplicate_overwrite_behavior() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "overwrite_me";

    store.put(key, b"first").unwrap();
    assert_eq!(store.get(key).unwrap(), b"first");

    store.put(key, b"second").unwrap();
    assert_eq!(store.get(key).unwrap(), b"second");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_persistence_drop_reopen() {
    let dir = get_temp_dir();
    let key = "persist";
    let data = b"data";

    {
        let store = LocalObjectStore::new(&dir).unwrap();
        store.put(key, data).unwrap();
    }

    {
        let store2 = LocalObjectStore::new(&dir).unwrap();
        assert_eq!(store2.get(key).unwrap(), data);
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_path_traversal_rejection() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();

    let bad_keys = vec!["../outside", "nested/../../outside", r"..\outside"];

    for key in bad_keys {
        match store.put(key, b"hack") {
            Err(ObjectStoreError::InvalidKey(_)) => {}
            _ => panic!("Expected InvalidKey for traversal: {}", key),
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_absolute_path_rejection() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();

    let bad_keys = if cfg!(windows) {
        vec!["C:\\Windows\\System32\\config", "/absolute/path"]
    } else {
        vec!["/etc/passwd"]
    };

    for key in bad_keys {
        match store.put(key, b"hack") {
            Err(ObjectStoreError::InvalidKey(_)) => {}
            _ => panic!("Expected InvalidKey for absolute path: {}", key),
        }
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_multiple_isolated_objects() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();

    store.put("a", b"A").unwrap();
    store.put("b", b"B").unwrap();

    assert_eq!(store.get("a").unwrap(), b"A");
    assert_eq!(store.get("b").unwrap(), b"B");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_unicode_safe_keys() {
    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();
    let key = "tenant-1/✓/file.parquet";
    let data = b"unicode";

    store.put(key, data).unwrap();
    assert_eq!(store.get(key).unwrap(), data);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_concurrent_writes_do_not_corrupt() {
    let dir = get_temp_dir();
    let store = Arc::new(LocalObjectStore::new(&dir).unwrap());
    let key = "concurrent_obj";

    let mut handles = vec![];
    for i in 0..10 {
        let store_clone = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            let data = format!("data_{}", i).into_bytes();
            store_clone.put(key, &data).unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let data = store.get(key).unwrap();
    let s = String::from_utf8(data).unwrap();
    assert!(s.starts_with("data_")); // One of them won

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_parquet_integration() {
    use std::time::SystemTime;
    use ulpx_core::event::EventId;
    use ulpx_core::integrity::ContentHash;
    use ulpx_replay::interpretation::{
        ComponentConfig, Interpretation, InterpretationId, PipelineConfiguration,
    };

    let dir = get_temp_dir();
    let store = LocalObjectStore::new(&dir).unwrap();

    let interp = Interpretation {
        id: InterpretationId(ContentHash([0u8; 32])),
        source_event_id: EventId::new("test-parquet-obj").unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        integrity_verified: true,
        frames: vec![],
        trailing_frame_error: None,
        integrity_error: None,
        pipeline_config: PipelineConfiguration {
            framer: ComponentConfig {
                id: "f".into(),
                version: "1".into(),
            },
            mapper: ComponentConfig {
                id: "m".into(),
                version: "1".into(),
            },
            parser_registry: vec![],
            inference_detectors: vec![],
        },
    };

    let mut parquet_bytes = Vec::new();
    ulpx_parquet::export_interpretation(&mut parquet_bytes, &interp).unwrap();

    let key = "exports/test-parquet-obj.parquet";
    store.put(key, &parquet_bytes).unwrap();

    let retrieved = store.get(key).unwrap();
    assert_eq!(retrieved, parquet_bytes);

    let _ = fs::remove_dir_all(dir);
}
