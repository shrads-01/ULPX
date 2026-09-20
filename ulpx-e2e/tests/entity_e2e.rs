use axum::http::StatusCode;
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore};
use ulpx_serve::create_router;

#[tokio::test]
async fn test_entity_resolution_e2e_local() {
    let temp_dir = tempfile::tempdir().unwrap();
    let store_path = temp_dir.path().join("ulpx_store");
    let mut store = LocalEvidenceStore::new(store_path.to_str().unwrap()).unwrap();

    let fw_payload = "{\"src\":\"10.1.1.5\"}\n".as_bytes().to_vec();
    store
        .store(RawEvent::new(
            EventId::new("fw1").unwrap(),
            fw_payload,
            Source("fw".to_string()),
        ))
        .unwrap();

    let ids_payload = "{\"source_ip\":\"10.1.1.5\"}\n".as_bytes().to_vec();
    store
        .store(RawEvent::new(
            EventId::new("ids1").unwrap(),
            ids_payload,
            Source("ids".to_string()),
        ))
        .unwrap();

    let vpn_payload = "{\"client\":\"10.1.1.5\"}\n".as_bytes().to_vec();
    store
        .store(RawEvent::new(
            EventId::new("vpn1").unwrap(),
            vpn_payload,
            Source("vpn".to_string()),
        ))
        .unwrap();

    let fa_payload = "{\"app_version\":\"10.1.1.5\"}\n".as_bytes().to_vec();
    store
        .store(RawEvent::new(
            EventId::new("fa1").unwrap(),
            fa_payload,
            Source("fa".to_string()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store), store_path.to_string_lossy().to_string());

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/entity/ip/10.1.1.5")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let results: Vec<String> = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        results.len(),
        3,
        "Expected exactly 3 interpretations to link to 10.1.1.5"
    );
}
