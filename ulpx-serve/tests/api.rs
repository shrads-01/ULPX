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
