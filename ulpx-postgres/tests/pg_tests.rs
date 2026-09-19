use sqlx::{PgPool, Row};
use std::process::Command;
use std::time::{Duration, SystemTime};
use testcontainers::clients;
use testcontainers_modules::postgres::Postgres;
use ulpx_core::event::EventId;
use ulpx_postgres::{InterpretationRepository, PostgresInterpretationRepository};
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

#[tokio::test]
async fn test_schema_and_idempotent_persistence() {
    if !is_docker_running() {
        // Output explicit message for skipped integration test
        println!("POSTGRES_INTEGRATION_TEST_SKIPPED_DUE_TO_NO_DOCKER");
        return;
    }
    println!("POSTGRES_INTEGRATION_TEST_EXECUTED");

    let docker = clients::Cli::default();
    let pg_node = docker.run(Postgres::default());

    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg_node.get_host_port_ipv4(5432)
    );

    let pool = PgPool::connect(&connection_string)
        .await
        .expect("Failed to connect");
    let repo = PostgresInterpretationRepository::new(pool.clone());
    repo.initialize_schema()
        .await
        .expect("Failed to init schema");

    let event_id = EventId::new("evt-123").unwrap();
    let config = PipelineConfiguration {
        framer: ComponentConfig {
            id: "framer".into(),
            version: "1.0".into(),
        },
        mapper: ComponentConfig {
            id: "mapper".into(),
            version: "2.0".into(),
        },
        parser_registry: vec![ComponentConfig {
            id: "parser1".into(),
            version: "1.0".into(),
        }],
        inference_detectors: vec!["detect1".into()],
    };

    let interp_id = InterpretationId::generate(&event_id, &config).unwrap();
    let initial_time = SystemTime::now();
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
            parser_outcome: ParserOutcome::Abstained,
            inference_decision: None,
            canonical_event: None,
            ir_event: None,
        }],
        trailing_frame_error: None,
        created_at: initial_time,
        integrity_verified: true,
        integrity_error: None,
    };

    // 1. Initial Save
    repo.save_interpretation(&interp)
        .await
        .expect("Failed to save");
    assert!(repo.has_interpretation(&interp_id).await.unwrap());

    // 2. Real Same-ID Idempotency Conflict Test
    let mut interp_conflict = interp.clone();
    // Change a persisted field (created_at) but keep the exact same InterpretationId
    interp_conflict.created_at = initial_time - Duration::from_secs(100);
    repo.save_interpretation(&interp_conflict)
        .await
        .expect("Failed to save conflict");

    // Query the database to prove the ORIGINAL persisted metadata remains unchanged.
    let row = sqlx::query("SELECT created_at_ns FROM interpretations WHERE interpretation_id = $1")
        .bind(interp_id.0.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    let stored_created_at: String = row.get(0);
    let expected_created_at = initial_time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    assert_eq!(
        stored_created_at, expected_created_at,
        "Same-ID idempotency must not overwrite original row"
    );

    // 3. Test Configuration Historical Preservation
    // We attempt to insert the same config identity but altered data via raw SQL to simulate a conflict,
    // proving ON CONFLICT DO NOTHING preserves the original historical row. (Not claiming DB prevents arbitrary UPDATEs).
    let config_hash = config.configuration_identity().unwrap().to_string();
    sqlx::query(r#"
        INSERT INTO pipeline_configurations (config_hash, framer_id, framer_version, mapper_id, mapper_version, parser_registry_json, inference_detectors_json)
        VALUES ($1, 'fake_framer', '9.9', 'fake_mapper', '9.9', '[]', '[]')
        ON CONFLICT (config_hash) DO NOTHING
    "#).bind(&config_hash).execute(&pool).await.unwrap();

    let framer_id: String =
        sqlx::query("SELECT framer_id FROM pipeline_configurations WHERE config_hash = $1")
            .bind(&config_hash)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get(0);
    assert_eq!(
        framer_id, "framer",
        "Configuration historical preservation must reject conflict inserts"
    );

    // 4. Test Multiple Interpretations of One Event
    let config2 = PipelineConfiguration {
        framer: ComponentConfig {
            id: "framer2".into(),
            version: "2.0".into(),
        },
        mapper: ComponentConfig {
            id: "mapper".into(),
            version: "2.0".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec![],
    };
    let interp_id2 = InterpretationId::generate(&event_id, &config2).unwrap();
    let mut interp2 = interp.clone();
    interp2.id = interp_id2.clone();
    interp2.pipeline_config = config2.clone();
    repo.save_interpretation(&interp2)
        .await
        .expect("Failed save second config");

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM interpretations WHERE event_id = $1")
        .bind(event_id.as_str())
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2, "Both interpretations must coexist for same event");

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM pipeline_configurations")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2, "Configuration rows must be distinct");

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM events")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "EventId must be represented exactly once");

    // 5. Test Complete Rollback Assertions
    let event_id3 = EventId::new("evt-fail").unwrap();
    let config3 = PipelineConfiguration {
        framer: ComponentConfig {
            id: "rollback_framer".into(),
            version: "1.0".into(),
        },
        mapper: ComponentConfig {
            id: "rollback_mapper".into(),
            version: "1.0".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec![],
    };
    let interp_id3 = InterpretationId::generate(&event_id3, &config3).unwrap();
    let mut interp3 = interp.clone();
    interp3.id = interp_id3.clone();
    interp3.source_event_id = event_id3.clone();
    interp3.pipeline_config = config3.clone();
    interp3.frames.push(FrameInterpretation {
        frame_index: 0, // Duplicate frame index to trigger intentional DB constraint failure!
        frame_bytes: vec![],
        execution: interp.frames[0].execution.clone(),
        parser_outcome: ParserOutcome::Abstained,
        inference_decision: None,
        canonical_event: None,
        ir_event: None,
    });

    let result = repo.save_interpretation(&interp3).await;
    assert!(
        result.is_err(),
        "Save should fail due to unique constraint on interpretation_frames"
    );

    // Assert complete rollback across all tables
    let exists = repo.has_interpretation(&interp_id3).await.unwrap();
    assert!(!exists, "interpretation row must be rolled back");

    let count: i64 = sqlx::query("SELECT COUNT(*) FROM events WHERE event_id = $1")
        .bind(event_id3.as_str())
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "event projection must be rolled back");

    let config_hash3 = config3.configuration_identity().unwrap().to_string();
    let count: i64 =
        sqlx::query("SELECT COUNT(*) FROM pipeline_configurations WHERE config_hash = $1")
            .bind(&config_hash3)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get(0);
    assert_eq!(count, 0, "pipeline_configurations must be rolled back");

    let count: i64 =
        sqlx::query("SELECT COUNT(*) FROM interpretation_frames WHERE interpretation_id = $1")
            .bind(interp_id3.0.to_string())
            .fetch_one(&pool)
            .await
            .unwrap()
            .get(0);
    assert_eq!(count, 0, "interpretation_frames must be rolled back");
}
#[tokio::test]
async fn test_entity_graph_persistence() {
    if !is_docker_running() {
        return;
    }

    let docker = clients::Cli::default();
    let pg_node = docker.run(Postgres::default());
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        pg_node.get_host_port_ipv4(5432)
    );
    let pool = PgPool::connect(&connection_string).await.expect("connect");
    let repo = PostgresInterpretationRepository::new(pool.clone());
    repo.initialize_schema().await.expect("schema");

    let event_id = EventId::new("evt-ent-1").unwrap();
    let config = PipelineConfiguration {
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
    };
    let interp_id = InterpretationId::generate(&event_id, &config).unwrap();

    use ulpx_core::parser::ParserVersion;
    use ulpx_mapping::model::{CanonicalEvent, CanonicalField, Confidence, FieldProvenance};

    let interp = Interpretation {
        id: interp_id.clone(),
        source_event_id: event_id.clone(),
        pipeline_config: config.clone(),
        frames: vec![FrameInterpretation {
            frame_index: 0,
            frame_bytes: vec![],
            execution: FrameExecution {
                parser_used: None,
                inference: InferenceExecution::NotInvoked,
            },
            parser_outcome: ParserOutcome::Abstained,
            inference_decision: None,
            ir_event: None,
            canonical_event: Some(CanonicalEvent {
                event_id: event_id.clone(),
                parser_id: "p".into(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                raw_bytes: vec![],
                timestamp: None,
                source_ip: Some(CanonicalField {
                    value: "10.1.1.5".into(),
                    provenance: FieldProvenance {
                        source_field: "src".to_string(),
                        span: None,
                        transformations: vec![],
                        rule_id: "r1".into(),
                        confidence: Confidence::Certain,
                        parser_id: "p".into(),
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
                severity: None,
                message: None,
                action: None,
                unmapped: std::collections::BTreeMap::new(),
                abstentions: vec![],
            }),
        }],
        trailing_frame_error: None,
        created_at: SystemTime::now(),
        integrity_verified: true,
        integrity_error: None,
    };

    repo.save_interpretation(&interp).await.unwrap();

    let ids = repo
        .query_entity_interpretations("IPv4", "10.1.1.5")
        .await
        .unwrap();
    assert_eq!(ids, vec![interp_id.0.to_string()]);

    let event_id2 = EventId::new("evt-ent-2").unwrap();
    let interp_id2 = InterpretationId::generate(&event_id2, &config).unwrap();
    let mut interp2 = interp.clone();
    interp2.id = interp_id2.clone();
    interp2.source_event_id = event_id2.clone();
    repo.save_interpretation(&interp2).await.unwrap();

    let ids2 = repo
        .query_entity_interpretations("IPv4", "10.1.1.5")
        .await
        .unwrap();
    assert_eq!(ids2.len(), 2);

    repo.save_interpretation(&interp).await.unwrap();
    let count: i64 = sqlx::query("SELECT COUNT(*) FROM entity_edges WHERE interpretation_id = $1")
        .bind(interp_id.0.to_string())
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "Idempotent save should not duplicate edges");

    let row = sqlx::query(
        "SELECT confidence, provenance_json FROM entity_edges WHERE interpretation_id = $1",
    )
    .bind(interp_id.0.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    let conf: String = row.get(0);
    let prov: serde_json::Value = row.get(1);
    assert_eq!(conf, "Certain");
    assert_eq!(prov.get("rule_id").unwrap().as_str().unwrap(), "r1");

    let config3 = PipelineConfiguration {
        framer: ComponentConfig {
            id: "f2".into(),
            version: "1".into(),
        },
        mapper: ComponentConfig {
            id: "m2".into(),
            version: "1".into(),
        },
        parser_registry: vec![],
        inference_detectors: vec![],
    };
    let interp_id3 = InterpretationId::generate(&event_id, &config3).unwrap();
    let mut interp3 = interp.clone();
    interp3.id = interp_id3.clone();
    interp3.pipeline_config = config3.clone();
    interp3.frames[0].canonical_event = None;
    repo.save_interpretation(&interp3).await.unwrap();

    let ids3 = repo
        .query_entity_interpretations("IPv4", "10.1.1.5")
        .await
        .unwrap();
    assert!(
        ids3.contains(&interp_id.0.to_string()),
        "Historical entity edge must survive later reprocessing"
    );
    assert!(!ids3.contains(&interp_id3.0.to_string()));
}
