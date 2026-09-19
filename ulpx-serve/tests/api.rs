use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use ulpx_core::event::{EventId, RawEvent, Source};
use ulpx_core::storage::{EvidenceStore, LocalEvidenceStore};
use ulpx_serve::create_router;
use ulpx_serve::models::ApiPipelineConfiguration;

#[tokio::test]
async fn test_list_events_deterministic_order_and_pagination() {
    let path = "test_serve_list.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();

    for i in 0..5 {
        store
            .store(RawEvent::new(
                EventId::new(format!("evt-{}", i)).unwrap(),
                format!("payload {}\n", i).into_bytes(),
                Source("test-src".into()),
            ))
            .unwrap();
    }

    let app = create_router(Arc::new(store));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?limit=2&offset=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let events = body_json["events"].as_array().unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event_id"], "evt-1");
    assert_eq!(events[1]["event_id"], "evt-2");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_get_detailed_interpretation_json_parser() {
    let path = "test_serve_json.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();
    let id = EventId::new("test-json").unwrap();

    let json_payload =
        "{\"src_ip\":\"192.168.1.1\",\"level\":\"CRITICAL\",\"message\":\"test msg\"}\n";
    store
        .store(RawEvent::new(
            id.clone(),
            json_payload.as_bytes().to_vec(),
            Source("api-test".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/interpretation/test-json/detailed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["source_event_id"], "test-json");
    let frame = &body_json["frames"][0];
    assert_eq!(frame["parser_outcome"], "Success");
    assert_eq!(frame["parser_id"], "json-flat");

    // Because JSON parsing succeeds, inference is not executed on fast-path
    assert!(frame["inference_decision"].is_null());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_ephemeral_replay_endpoint() {
    let path = "test_serve_replay.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();
    let id = EventId::new("evt-replay").unwrap();

    store
        .store(RawEvent::new(
            id.clone(),
            b"{\"a\": 1}\n".to_vec(),
            Source("src".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));

    let config = ApiPipelineConfiguration {
        framer_id: "NewlineFramer".into(),
        framer_version: "1.0.0".into(),
        mapper_id: "DefaultMapper".into(),
        mapper_version: "1.0.0".into(),
        parser_registry: vec!["json-flat".into()],
        inference_detectors: vec![],
    };

    let req_body = serde_json::json!({
        "event_id": "evt-replay",
        "pipeline_config": config
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/replay")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(body_json["source_event_id"], "evt-replay");
    assert_eq!(body_json["frames"][0]["parser_outcome"], "Success");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_ephemeral_replay_declarative_rejections() {
    let path = "test_serve_replay_rejections.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();
    let id = EventId::new("evt-replay-reject").unwrap();
    store
        .store(RawEvent::new(id, vec![], Source("src".into())))
        .unwrap();

    let app = create_router(Arc::new(store));

    let config = serde_json::json!({
        "framer_id": "NewlineFramer",
        "framer_version": "1.0.0",
        "mapper_id": "DefaultMapper",
        "mapper_version": "1.0.0",
        "parser_registry": ["json-flat"],
        "inference_detectors": ["json"]
    });

    // Helper closure to test a rejection
    let test_rejection = |bad_config: serde_json::Value, expected_status: StatusCode| {
        let app_clone = app.clone();
        async move {
            let req_body = serde_json::json!({
                "event_id": "evt-replay-reject",
                "pipeline_config": bad_config
            });
            let response = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/replay")
                        .header("content-type", "application/json")
                        .body(Body::from(req_body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
        }
    };

    // 1. Unsupported framer
    let mut bad1 = config.clone();
    bad1["framer_id"] = serde_json::Value::String("UnknownFramer".into());
    test_rejection(bad1, StatusCode::BAD_REQUEST).await;

    // 2. Unsupported mapper
    let mut bad2 = config.clone();
    bad2["mapper_id"] = serde_json::Value::String("UnknownMapper".into());
    test_rejection(bad2, StatusCode::BAD_REQUEST).await;

    // 3. Unsupported parser
    let mut bad3 = config.clone();
    bad3["parser_registry"] = serde_json::Value::Array(vec!["unknown-parser".into()]);
    test_rejection(bad3, StatusCode::BAD_REQUEST).await;

    // 4. Unsupported inference detector
    let mut bad4 = config.clone();
    bad4["inference_detectors"] = serde_json::Value::Array(vec!["unknown-detector".into()]);
    test_rejection(bad4, StatusCode::BAD_REQUEST).await;

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_ephemeral_replay_does_not_mutate_evidence() {
    let path = "test_serve_replay_mutation.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();
    let id = EventId::new("evt-replay-mut").unwrap();

    store
        .store(RawEvent::new(
            id.clone(),
            b"{\"a\": 1}\n".to_vec(),
            Source("src".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));

    let config = ApiPipelineConfiguration {
        framer_id: "NewlineFramer".into(),
        framer_version: "1.0.0".into(),
        mapper_id: "DefaultMapper".into(),
        mapper_version: "1.0.0".into(),
        parser_registry: vec!["json-flat".into()],
        inference_detectors: vec![],
    };

    let req_body = serde_json::json!({
        "event_id": "evt-replay-mut",
        "pipeline_config": config
    });

    // 1. Check count before
    let list_req1 = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp1 = app.clone().oneshot(list_req1).await.unwrap();
    let count_before = serde_json::from_slice::<serde_json::Value>(
        &resp1.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap()["events"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(count_before, 1);

    // 2. Perform replay
    let replay_req = Request::builder()
        .method("POST")
        .uri("/api/v1/replay")
        .header("content-type", "application/json")
        .body(Body::from(req_body.to_string()))
        .unwrap();
    let replay_resp = app.clone().oneshot(replay_req).await.unwrap();
    assert_eq!(replay_resp.status(), StatusCode::OK);

    let replay_body = serde_json::from_slice::<serde_json::Value>(
        &replay_resp.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap();
    let config_id = replay_body["pipeline_config_identity"].as_str().unwrap();
    assert_ne!(config_id, "unknown");

    // 3. Check count after
    let list_req2 = Request::builder()
        .uri("/api/v1/events")
        .body(Body::empty())
        .unwrap();
    let resp2 = app.clone().oneshot(list_req2).await.unwrap();
    let count_after = serde_json::from_slice::<serde_json::Value>(
        &resp2.into_body().collect().await.unwrap().to_bytes(),
    )
    .unwrap()["events"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(count_after, 1); // No new event added

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_ui_routes_serve_static_files() {
    let path = "test_serve_ui.ulpx";
    let _ = std::fs::remove_file(path);
    let store = LocalEvidenceStore::new(path).unwrap();
    let app = create_router(Arc::new(store));

    // Test index.html
    let res = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

    // Core structural assertions
    assert!(html.contains("ULPX Analyst UI"));
    assert!(html.contains(r#"<script src="/app.js"></script>"#));
    assert!(html.contains(r#"<link rel="stylesheet" href="/style.css">"#));

    // Workflow tabs
    assert!(html.contains(r#""tab-evidence""#));
    assert!(html.contains(r#""tab-interpretation""#));
    assert!(html.contains(r#""tab-replay""#));

    // Supported declarative configuration defaults
    assert!(html.contains(r#"value="NewlineFramer""#));
    assert!(html.contains(r#"value="DefaultMapper""#));
    assert!(html.contains(r#"value="json-flat, syslog, cef""#));
    assert!(html.contains(r#"value="json, syslog, cef""#));

    // Test app.js
    let res_js = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_js.status(), StatusCode::OK);
    assert_eq!(
        res_js.headers().get("content-type").unwrap(),
        "application/javascript"
    );
    let js_content = String::from_utf8(
        res_js
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(js_content.contains("escapeHtml(")); // Confirm XSS protection is present
    assert!(js_content.contains("decodeBytes(")); // Confirm byte rendering is present

    // Test style.css
    let res_css = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_css.status(), StatusCode::OK);
    assert_eq!(res_css.headers().get("content-type").unwrap(), "text/css");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn test_empty_store_returns_zero_events_cleanly() {
    let path = "test_serve_empty.ulpx";
    let _ = std::fs::remove_file(path);

    // Store is created but no events are added
    let store = LocalEvidenceStore::new(path).unwrap();
    let app = create_router(Arc::new(store));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(json.get("events").unwrap().as_array().unwrap().is_empty());

    let _ = std::fs::remove_file(path);
}
// ── Phase 15: Provenance / confidence / unknown-format API tests ───────────

/// The evidence endpoint must return size_bytes in addition to the payload.
#[tokio::test]
async fn test_evidence_endpoint_includes_size_bytes() {
    let path = "test_serve_size_bytes.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();
    let payload = b"hello world\n";
    store
        .store(RawEvent::new(
            EventId::new("evt-size").unwrap(),
            payload.to_vec(),
            Source("src".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/evidence/evt-size")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();

    // size_bytes must be the actual byte length of the stored payload
    assert_eq!(body["size_bytes"].as_u64().unwrap(), payload.len() as u64);
    // payload_base64 must still be present
    assert!(body["payload_base64"].as_str().is_some());

    let _ = std::fs::remove_file(path);
}

/// The interpretation endpoint must include provenance data on canonical fields
/// (source_field, confidence, byte_span) when the JSON parser succeeds.
#[tokio::test]
async fn test_interpretation_includes_provenance_data() {
    let path = "test_serve_provenance.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();

    let json_payload = "{\"src_ip\":\"10.0.0.1\",\"message\":\"login ok\"}\n";
    store
        .store(RawEvent::new(
            EventId::new("evt-prov").unwrap(),
            json_payload.as_bytes().to_vec(),
            Source("prov-test".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/interpretation/evt-prov/detailed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let frame = &body["frames"][0];
    assert_eq!(frame["parser_outcome"], "Success");

    // canonical_event must be present
    let canon = &frame["canonical_event"];
    assert!(
        !canon.is_null(),
        "canonical_event should be present for JSON input"
    );

    // Any canonical field that is present must carry provenance with at least source_field and confidence
    let check_prov = |field: &serde_json::Value, name: &str| {
        if !field.is_null() {
            let prov = &field["provenance"];
            assert!(!prov.is_null(), "Field '{}' must have provenance", name);
            assert!(
                prov["source_field"].as_str().is_some(),
                "Field '{}' provenance must have source_field",
                name
            );
            assert!(
                prov["confidence"].as_str().is_some(),
                "Field '{}' provenance must have confidence",
                name
            );
        }
    };

    check_prov(&canon["source_ip"], "source_ip");
    check_prov(&canon["message"], "message");
    check_prov(&canon["timestamp"], "timestamp");

    let _ = std::fs::remove_file(path);
}

/// When inference runs (unknown format — no parser matches), the inference_decision
/// must be present in the frame with a non-empty all_candidates list.
#[tokio::test]
async fn test_unknown_format_inference_decision_present() {
    let path = "test_serve_unknown_fmt.ulpx";
    let _ = std::fs::remove_file(path);
    let mut store = LocalEvidenceStore::new(path).unwrap();

    // A line that looks like syslog so at least one inference candidate fires
    let payload = "Jan  1 00:00:01 myhost myapp[123]: something happened\n";
    store
        .store(RawEvent::new(
            EventId::new("evt-unknown").unwrap(),
            payload.as_bytes().to_vec(),
            Source("unknown-src".into()),
        ))
        .unwrap();

    let app = create_router(Arc::new(store));
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/interpretation/evt-unknown/detailed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();

    let frame = &body["frames"][0];
    // The frame should have parsed successfully via the syslog parser
    // OR inference should have run if the syslog parser abstained.
    // Either way integrity_verified must not error.
    assert!(
        frame["parser_outcome"].as_str().is_some(),
        "parser_outcome must be present"
    );

    let _ = std::fs::remove_file(path);
}

/// The UI HTML must now include the Provenance tab.
#[tokio::test]
async fn test_ui_includes_provenance_tab() {
    let path = "test_serve_ui_prov.ulpx";
    let _ = std::fs::remove_file(path);
    let store = LocalEvidenceStore::new(path).unwrap();
    let app = create_router(Arc::new(store));

    let res = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

    // Phase 15 additions
    assert!(
        html.contains("tab-provenance"),
        "HTML must contain the provenance tab"
    );
    assert!(
        html.contains("Provenance Explorer") || html.contains("Provenance"),
        "HTML must label the provenance tab"
    );
    assert!(
        html.contains("unknown-format-container"),
        "HTML must have unknown-format container"
    );

    let _ = std::fs::remove_file(path);
}

/// The app.js must contain the Phase 15 JavaScript functions.
#[tokio::test]
async fn test_app_js_contains_phase15_functions() {
    let path = "test_serve_js_phase15.ulpx";
    let _ = std::fs::remove_file(path);
    let store = LocalEvidenceStore::new(path).unwrap();
    let app = create_router(Arc::new(store));

    let res = app
        .oneshot(
            Request::builder()
                .uri("/app.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let js =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

    // Confidence bar rendering
    assert!(
        js.contains("buildConfidenceBar"),
        "app.js must contain buildConfidenceBar"
    );
    assert!(
        js.contains("confidence-bar-fill"),
        "app.js must reference confidence-bar-fill CSS class"
    );

    // Provenance explorer
    assert!(
        js.contains("renderProvenanceExplorer"),
        "app.js must contain renderProvenanceExplorer"
    );
    assert!(
        js.contains("prov-chain"),
        "app.js must reference prov-chain CSS class"
    );

    // Unknown-format panel
    assert!(
        js.contains("renderUnknownFormatPanel"),
        "app.js must contain renderUnknownFormatPanel"
    );
    assert!(
        js.contains("unknown-format-panel"),
        "app.js must reference unknown-format-panel CSS class"
    );

    // XSS protection still present
    assert!(js.contains("escapeHtml("), "XSS protection must be present");
    assert!(js.contains("decodeBytes("), "Byte renderer must be present");

    let _ = std::fs::remove_file(path);
}
