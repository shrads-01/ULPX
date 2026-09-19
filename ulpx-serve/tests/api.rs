use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::Engine;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore};
use ulpx_serve::create_router;

fn get_temp_path() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("test_serve_{}.ulpx", count)
}

#[tokio::test]
async fn test_get_evidence_success() {
    let path = get_temp_path();
    let mut store = LocalEvidenceStore::new(&path).unwrap();
    let id = EventId::new("test-evt").unwrap();

    store
        .store(RawEvent::new(
            id.clone(),
            b"Hello API \x00\xFF".to_vec(),
            Source("api-test".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence/test-evt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["event_id"], "test-evt");
    assert_eq!(body_json["source"], "api-test");

    let base64_payload = body_json["payload_base64"].as_str().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(base64_payload)
        .unwrap();
    assert_eq!(decoded, b"Hello API \x00\xFF");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_get_evidence_not_found() {
    let path = get_temp_path();
    let store = LocalEvidenceStore::new(&path).unwrap();
    let app = create_router(Arc::new(store));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence/missing-evt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_get_interpretation_success() {
    let path = get_temp_path();
    let mut store = LocalEvidenceStore::new(&path).unwrap();
    let id = EventId::new("test-json").unwrap();

    // Proper JSON structure that ends in newline to trigger a single frame matching JSON parser exactly
    store
        .store(RawEvent::new(
            id.clone(),
            b"{\"message\":\"hello\"}\n".to_vec(),
            Source("api-test".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/interpretation/test-json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["source_event_id"], "test-json");
    assert_eq!(body_json["integrity_verified"], true);

    let frames = body_json["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 1);

    let frame = &frames[0];

    // Stricter assertions per acceptance criteria
    assert_eq!(frame["parser_outcome"], "json-flat");
    assert_eq!(frame["has_ir_event"], true);
    assert_eq!(frame["has_canonical_event"], true);

    // Prove that Debug representation is not exposed.
    assert!(frame.get("ir_event_debug").is_none());
    assert!(frame.get("canonical_event_debug").is_none());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_get_interpretation_integrity_failure() {
    let path = get_temp_path();
    let mut store = LocalEvidenceStore::new(&path).unwrap();
    let id = EventId::new("test-corrupt").unwrap();

    store
        .store(RawEvent::new(
            id.clone(),
            b"test".to_vec(),
            Source("api-test".into()),
        ))
        .unwrap();

    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.seek(SeekFrom::End(-2)).unwrap();
    file.write_all(b"xx").unwrap();

    let store_reloaded = LocalEvidenceStore::new(&path).unwrap();

    let app = create_router(Arc::new(store_reloaded));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/interpretation/test-corrupt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let _ = std::fs::remove_file(path);
}
