use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use ulpx_core::event::EventId;
use ulpx_core::parser::{ParserResult, ParserVersion};
use ulpx_ir::model::{EventIr, IrType, IrValue};
use ulpx_mapping::model::{CanonicalEvent, CanonicalField, Confidence, FieldProvenance, Severity};
use ulpx_opensearch::{OpenSearchClient, OpenSearchDocument, OpenSearchError};
use ulpx_replay::interpretation::{
    ComponentConfig, FrameExecution, FrameInterpretation, InferenceExecution, Interpretation,
    InterpretationId, PipelineConfiguration,
};
use ulpx_replay::ParserOutcome;

fn is_docker_running() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn create_dummy_doc() -> OpenSearchDocument {
    OpenSearchDocument {
        id: "1".into(),
        index_name: "test".into(),
        source_event_id: "evt".into(),
        interpretation_id: "interp".into(),
        frame_index: 0,
        timestamp: "2024-01-01T00:00:00Z".into(),
        integrity_verified: true,
        raw_evidence_id: "evt".into(),
        parser: ulpx_opensearch::ParserProjection {
            id: None,
            version: None,
            outcome: "Success".into(),
        },
        inference: ulpx_opensearch::InferenceProjection {
            invoked: false,
            decision: "NotInvoked".into(),
            detector_id: None,
            abstention_reason: None,
        },
        canonical: None,
        ir: None,
    }
}

async fn run_mock_server_test(response_body: &str) -> Result<(), OpenSearchError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let resp = response_body.to_string();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = socket.read(&mut buf).await;
            let full_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                resp
            );
            let _ = socket.write_all(full_response.as_bytes()).await;
        }
    });

    let client = OpenSearchClient::new(&format!("http://127.0.0.1:{}", port));
    client.bulk_index(&[create_dummy_doc()]).await
}

#[tokio::test]
async fn test_mock_errors_true() {
    let json = "{\"errors\":true,\"items\":[{\"index\":{\"status\":400,\"error\":{\"type\":\"mapper_parsing_exception\"}}}]}";
    match run_mock_server_test(json).await {
        Err(OpenSearchError::BulkErrors(diag)) => {
            assert!(
                diag.contains("mapper_parsing_exception"),
                "Must extract diagnostic from items array"
            );
        }
        other => panic!("Expected BulkErrors, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mock_errors_false() {
    let json = "{\"errors\":false,\"items\":[]}";
    match run_mock_server_test(json).await {
        Ok(_) => {}
        other => panic!("Expected Ok, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mock_empty_body() {
    match run_mock_server_test("").await {
        Err(OpenSearchError::InvalidBulkResponse(msg)) => {
            assert!(msg.contains("Empty response body"));
        }
        other => panic!(
            "Expected InvalidBulkResponse(Empty response body), got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_mock_empty_json_object() {
    match run_mock_server_test("{}").await {
        Err(OpenSearchError::InvalidBulkResponse(msg)) => {
            assert!(
                msg.contains("missing field `errors`"),
                "Actual msg: {}",
                msg
            );
        }
        other => panic!(
            "Expected InvalidBulkResponse due to missing errors field, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_mock_non_boolean_errors() {
    let json = "{\"errors\":\"false\"}";
    match run_mock_server_test(json).await {
        Err(OpenSearchError::InvalidBulkResponse(msg)) => {
            assert!(msg.contains("invalid type"));
        }
        other => panic!(
            "Expected InvalidBulkResponse due to non-boolean errors field, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_projection_validation() {
    let event_id = EventId::new("evt-val").unwrap();
    let config = PipelineConfiguration {
        framer: ComponentConfig {
            id: "framer".into(),
            version: "1.0".into(),
        },
        mapper: ComponentConfig {
            id: "mapper".into(),
            version: "2.0".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec![],
    };
    let interp_id = InterpretationId::generate(&event_id, &config).unwrap();

    // 1. Test Duplicate Frame Index
    let mut interp_dup = Interpretation {
        id: interp_id.clone(),
        source_event_id: event_id.clone(),
        pipeline_config: config.clone(),
        frames: vec![
            FrameInterpretation {
                frame_index: 0,
                frame_bytes: vec![],
                execution: FrameExecution {
                    parser_used: None,
                    inference: InferenceExecution::NotInvoked,
                },
                parser_outcome: ParserOutcome::Abstained,
                inference_decision: None,
                canonical_event: None,
                ir_event: None,
            },
            FrameInterpretation {
                frame_index: 0, // DUPLICATE
                frame_bytes: vec![],
                execution: FrameExecution {
                    parser_used: None,
                    inference: InferenceExecution::NotInvoked,
                },
                parser_outcome: ParserOutcome::Abstained,
                inference_decision: None,
                canonical_event: None,
                ir_event: None,
            },
        ],
        trailing_frame_error: None,
        created_at: SystemTime::now(),
        integrity_verified: true,
        integrity_error: None,
    };

    match OpenSearchDocument::generate_from_interpretation(&interp_dup, "test") {
        Err(OpenSearchError::DuplicateFrameIndex(idx)) => assert_eq!(idx, 0),
        other => panic!("Expected DuplicateFrameIndex, got {:?}", other),
    }

    // 2. Test Invalid Index Name
    interp_dup.frames.pop();
    match OpenSearchDocument::generate_from_interpretation(&interp_dup, "invalid*name") {
        Err(OpenSearchError::InvalidIndexName(_)) => {}
        other => panic!("Expected InvalidIndexName, got {:?}", other),
    }

    // 3. Test Non-finite Float
    let mut ir_event = EventIr::new(
        event_id.clone(),
        "parser1".to_string(),
        ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        vec![],
    );
    ir_event.fields.insert(
        "bad_float".to_string(),
        IrValue {
            ty: IrType::Float(f64::NAN),
            span: None,
        },
    );
    interp_dup.frames[0].ir_event = Some(ir_event);

    match OpenSearchDocument::generate_from_interpretation(&interp_dup, "test") {
        Err(OpenSearchError::NonFiniteFloat) => {}
        other => panic!("Expected NonFiniteFloat, got {:?}", other),
    }
}

#[tokio::test]
async fn test_projection_logic_offline() {
    let event_id = EventId::new("evt-offline-deep").unwrap();
    let config = PipelineConfiguration {
        framer: ComponentConfig {
            id: "framer".into(),
            version: "1.0".into(),
        },
        mapper: ComponentConfig {
            id: "mapper".into(),
            version: "2.0".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec!["detect1".into()],
    };

    let interp_id = InterpretationId::generate(&event_id, &config).unwrap();

    let mut ir_event = EventIr::new(
        event_id.clone(),
        "parser1".to_string(),
        ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        vec![],
    );
    ir_event.fields.insert(
        "test_key".to_string(),
        IrValue {
            ty: IrType::String("test_val".to_string()),
            span: None,
        },
    );

    let canonical_event = CanonicalEvent {
        event_id: event_id.clone(),
        parser_id: "parser1".to_string(),
        parser_version: ParserVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        raw_bytes: vec![],
        timestamp: None,
        source_ip: Some(CanonicalField {
            value: "192.168.1.1".to_string(),
            provenance: FieldProvenance {
                source_field: "src".to_string(),
                span: None,
                transformations: vec![],
                rule_id: "rule1".to_string(),
                confidence: Confidence::Probable,
                parser_id: "parser1".to_string(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
        }),
        source_hostname: None,
        dest_ip: None,
        dest_hostname: None,
        severity: Some(CanonicalField {
            value: Severity::Critical,
            provenance: FieldProvenance {
                source_field: "sev".to_string(),
                span: None,
                transformations: vec![],
                rule_id: "rule2".to_string(),
                confidence: Confidence::Probable,
                parser_id: "parser1".to_string(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
        }),
        message: None,
        action: None,
        unmapped: BTreeMap::new(),
        abstentions: vec![],
    };

    let interp = Interpretation {
        id: interp_id.clone(),
        source_event_id: event_id.clone(),
        pipeline_config: config.clone(),
        frames: vec![FrameInterpretation {
            frame_index: 0,
            frame_bytes: b"raw_data_0".to_vec(),
            execution: FrameExecution {
                parser_used: Some(ComponentConfig {
                    id: "parser1".into(),
                    version: "1.0".into(),
                }),
                inference: InferenceExecution::NotInvoked,
            },
            parser_outcome: ParserOutcome::Success(ParserResult {
                fields: vec![],
                parser_id: "parser1".into(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                raw_bytes: vec![],
            }),
            inference_decision: None,
            canonical_event: Some(canonical_event),
            ir_event: Some(ir_event),
        }],
        trailing_frame_error: None,
        created_at: SystemTime::now(),
        integrity_verified: true,
        integrity_error: None,
    };

    let docs = OpenSearchDocument::generate_from_interpretation(&interp, "ulpx_events").unwrap();
    assert_eq!(docs.len(), 1);

    let doc0 = &docs[0];
    assert_eq!(doc0.id, format!("{}_0", interp_id.0));
    assert_eq!(doc0.source_event_id, "evt-offline-deep");
    assert_eq!(doc0.frame_index, 0);
    assert_eq!(
        doc0.raw_evidence_id, "evt-offline-deep",
        "Must reference raw evidence ID"
    );

    let ir_proj = doc0.ir.as_ref().expect("IR projection must be present");
    assert_eq!(
        ir_proj.fields.get("test_key").unwrap().as_str().unwrap(),
        "test_val"
    );

    let canonical_proj = doc0
        .canonical
        .as_ref()
        .expect("Canonical projection must be present");
    assert_eq!(canonical_proj.source_ip.as_deref(), Some("192.168.1.1"));
    assert_eq!(canonical_proj.severity.as_deref(), Some("Critical"));

    let serialized_doc = serde_json::to_string(&doc0).unwrap();
    assert!(
        !serialized_doc.contains("raw_bytes"),
        "Raw bytes payload MUST NOT be present in projection JSON"
    );
    assert!(
        !serialized_doc.contains("frame_bytes"),
        "Frame bytes payload MUST NOT be present in projection JSON"
    );

    let docs_again =
        OpenSearchDocument::generate_from_interpretation(&interp, "ulpx_events").unwrap();
    assert_eq!(docs[0].id, docs_again[0].id);
    let json1 = serde_json::to_string(&docs).unwrap();
    let json2 = serde_json::to_string(&docs_again).unwrap();
    assert_eq!(
        json1, json2,
        "Multiple identical generation runs must produce byte-for-byte identical JSON"
    );
}

#[tokio::test]
async fn test_opensearch_integration() {
    if !is_docker_running() {
        println!("OPENSEARCH_INTEGRATION_TEST_SKIPPED_DUE_TO_NO_DOCKER");
        return;
    }

    println!("OPENSEARCH_INTEGRATION_TEST_EXECUTED");

    use testcontainers::clients;
    use testcontainers::GenericImage;

    let docker = clients::Cli::default();

    let image = GenericImage::new("opensearchproject/opensearch", "2.11.0")
        .with_env_var("discovery.type", "single-node")
        .with_env_var("DISABLE_SECURITY_PLUGIN", "true")
        .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
            "recovered [0] indices into cluster_state",
        ));

    let node = docker.run(image);
    let port = node.get_host_port_ipv4(9200);
    let url = format!("http://127.0.0.1:{}", port);

    let client = OpenSearchClient::new(&url);

    tokio::time::sleep(Duration::from_secs(10)).await;

    let event_id = EventId::new("evt-integration").unwrap();
    let config = PipelineConfiguration {
        framer: ComponentConfig {
            id: "framer".into(),
            version: "1.0".into(),
        },
        mapper: ComponentConfig {
            id: "mapper".into(),
            version: "2.0".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec![],
    };

    let interp_id = InterpretationId::generate(&event_id, &config).unwrap();
    let interp = Interpretation {
        id: interp_id.clone(),
        source_event_id: event_id.clone(),
        pipeline_config: config.clone(),
        frames: vec![FrameInterpretation {
            frame_index: 0,
            frame_bytes: vec![],
            execution: FrameExecution {
                parser_used: Some(ComponentConfig {
                    id: "parser1".into(),
                    version: "1.0".into(),
                }),
                inference: InferenceExecution::NotInvoked,
            },
            parser_outcome: ParserOutcome::Success(ParserResult {
                fields: vec![],
                parser_id: "parser1".into(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                raw_bytes: vec![],
            }),
            inference_decision: None,
            canonical_event: None,
            ir_event: None,
        }],
        trailing_frame_error: None,
        created_at: SystemTime::now(),
        integrity_verified: true,
        integrity_error: None,
    };

    let docs = OpenSearchDocument::generate_from_interpretation(&interp, "ulpx_events").unwrap();
    client
        .bulk_index(&docs)
        .await
        .expect("Failed to bulk index to OpenSearch");
}
