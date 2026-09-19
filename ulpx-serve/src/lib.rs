pub mod models;

use crate::models::{ApiDetailedInterpretation, ApiEventSummary, ApiRawEvent, ReplayRequest};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ulpx_core::event::EventId;
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::parser::cef::CefParser;
use ulpx_core::parser::json::JsonParser;
use ulpx_core::parser::syslog::SyslogParser;
use ulpx_core::parser::{LifecycleStage, ParserRegistry};
use ulpx_core::storage::{EvidenceStore, StoreError};
use ulpx_infer::engine::InferenceEngine;
use ulpx_ir::convert::CompositeConverter;
use ulpx_mapping::engine::MappingEngine;
use ulpx_replay::{interpretation::ComponentConfig, ReplayPipeline};

pub struct AppState {
    pub store: Arc<dyn EvidenceStore + Send + Sync>,
}

pub fn create_router(store: Arc<dyn EvidenceStore + Send + Sync>) -> Router {
    let state = Arc::new(AppState { store });
    Router::new()
        .route(
            "/",
            get(|| async { axum::response::Html(include_str!("../static/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/javascript")],
                    include_str!("../static/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/css")],
                    include_str!("../static/style.css"),
                )
            }),
        )
        .route("/api/v1/events", get(list_events))
        .route("/api/v1/entity/:type/:value", get(get_entity))
        .route("/api/v1/evidence/:event_id", get(get_evidence))
        .route(
            "/api/v1/interpretation/:event_id/detailed",
            get(get_interpretation_detailed),
        )
        .route("/api/v1/replay", post(ephemeral_replay))
        .with_state(state)
}

#[derive(Deserialize)]
pub struct ListEventsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize)]
pub struct ListEventsResponse {
    pub events: Vec<ApiEventSummary>,
}

async fn list_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListEventsQuery>,
) -> Result<Json<ListEventsResponse>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0);
    let events = state.store.list_events(offset, limit);
    let dtos = events.iter().map(ApiEventSummary::from).collect();
    Ok(Json(ListEventsResponse { events: dtos }))
}

async fn get_evidence(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> Result<Json<ApiRawEvent>, (StatusCode, String)> {
    let id = EventId::new(event_id.clone()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid EventId format".to_string(),
        )
    })?;

    let event = state.store.retrieve(&id).map_err(|e| match e {
        StoreError::NotFound => (StatusCode::NOT_FOUND, "Event not found".to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal store error".to_string(),
        ),
    })?;

    Ok(Json(ApiRawEvent::from(&event)))
}

async fn get_interpretation_detailed(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> Result<Json<ApiDetailedInterpretation>, (StatusCode, String)> {
    let id = EventId::new(event_id.clone()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid EventId format".to_string(),
        )
    })?;

    let framer = NewlineFramer;

    let mut parser_registry = ParserRegistry::new();
    let _ = parser_registry.register(Box::new(JsonParser::new()), LifecycleStage::Deployed);
    let _ = parser_registry.register(Box::new(SyslogParser::new()), LifecycleStage::Deployed);
    let _ = parser_registry.register(Box::new(CefParser::new()), LifecycleStage::Deployed);

    let inference_engine = InferenceEngine::default();
    let ir_converter = CompositeConverter::default_registry();
    let mapping_engine = MappingEngine::default_registry();

    let pipeline = ReplayPipeline::new(
        &*(state.store) as &(dyn EvidenceStore + 'static),
        &framer,
        ComponentConfig {
            id: "NewlineFramer".into(),
            version: "1.0.0".into(),
        },
        &parser_registry,
        &inference_engine,
        &ir_converter,
        &mapping_engine,
        ComponentConfig {
            id: "DefaultMapper".into(),
            version: "1.0.0".into(),
        },
    );

    let interpretation = pipeline.replay(&id).map_err(|e| match e {
        ulpx_core::storage::StoreError::NotFound => {
            (StatusCode::NOT_FOUND, "Event not found".to_string())
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal replay error".to_string(),
        ),
    })?;

    Ok(Json(ApiDetailedInterpretation::from(&interpretation)))
}

async fn get_entity(
    State(state): State<Arc<AppState>>,
    Path((entity_type, entity_value)): Path<(String, String)>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    // ARCHITECTURE NOTE:
    // This API boundary operates exclusively in local/ephemeral offline mode, using `LocalEvidenceStore`.
    // It dynamically reconstructs entity associations on-the-fly using the canonical Phase 15 declarative
    // pipeline configuration. It does NOT depend on PostgreSQL, which is designed as an optional
    // export/durable backend tested independently in `ulpx-postgres`.

    let req_type = entity_type.to_lowercase();
    let norm_value = if req_type == "ip" {
        ulpx_entity::resolution::normalize_ipv4(&entity_value)
            .or_else(|| ulpx_entity::resolution::normalize_ipv6(&entity_value))
    } else if req_type == "hostname" {
        ulpx_entity::resolution::normalize_hostname(&entity_value)
    } else {
        None
    };

    let norm_value = match norm_value {
        Some(v) => v,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Invalid or unsupported entity type/value".to_string(),
            ))
        }
    };

    let framer = NewlineFramer;
    let mut parser_registry = ParserRegistry::new();
    let _ = parser_registry.register(
        Box::new(JsonParser::new()),
        ulpx_core::parser::LifecycleStage::Deployed,
    );
    let _ = parser_registry.register(
        Box::new(SyslogParser::new()),
        ulpx_core::parser::LifecycleStage::Deployed,
    );
    let _ = parser_registry.register(
        Box::new(CefParser::new()),
        ulpx_core::parser::LifecycleStage::Deployed,
    );
    let inference_engine = InferenceEngine::default();
    let ir_converter = CompositeConverter::default_registry();
    let mapping_engine = MappingEngine::default_registry();

    let pipeline = ReplayPipeline::new(
        &*(state.store) as &(dyn EvidenceStore + 'static),
        &framer,
        ComponentConfig {
            id: "NewlineFramer".into(),
            version: "1.0.0".into(),
        },
        &parser_registry,
        &inference_engine,
        &ir_converter,
        &mapping_engine,
        ComponentConfig {
            id: "CompositeMapper".into(),
            version: "1.0.0".into(),
        },
    );

    let events = state.store.list_events(0, 10000);

    let mut matching_interpretations = Vec::new();
    for event in events {
        if let Ok(interpretation) = pipeline.replay(&event.event_id) {
            let obs_list = ulpx_entity::resolution::resolve_interpretation(&interpretation);
            for obs in obs_list {
                let obs_type_str = match obs.node.entity_type {
                    ulpx_entity::model::EntityType::IPv4 => "ip",
                    ulpx_entity::model::EntityType::IPv6 => "ip",
                    ulpx_entity::model::EntityType::Hostname => "hostname",
                };
                if obs_type_str == req_type && obs.node.value == norm_value {
                    let mut hash_hex = String::with_capacity(64);
                    for byte in &interpretation.id.0 .0 {
                        use std::fmt::Write;
                        write!(&mut hash_hex, "{:02x}", byte).unwrap();
                    }
                    matching_interpretations.push(hash_hex);
                    break;
                }
            }
        }
    }

    matching_interpretations.sort();
    matching_interpretations.dedup();

    Ok(Json(matching_interpretations))
}

async fn ephemeral_replay(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplayRequest>,
) -> Result<Json<ApiDetailedInterpretation>, (StatusCode, String)> {
    let id = EventId::new(payload.event_id.clone()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid EventId format".to_string(),
        )
    })?;

    // Phase 15 declarative boundary enforcement:
    // Only the explicit built-in components are permitted.
    // Dynamic WASM parser loading is deferred to a future phase.
    if payload.pipeline_config.framer_id != "NewlineFramer"
        || payload.pipeline_config.framer_version != "1.0.0"
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported framer requested".to_string(),
        ));
    }
    if payload.pipeline_config.mapper_id != "DefaultMapper"
        || payload.pipeline_config.mapper_version != "1.0.0"
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported mapper requested".to_string(),
        ));
    }

    let allowed_parsers = ["json-flat", "syslog", "cef"];
    for p in &payload.pipeline_config.parser_registry {
        if !allowed_parsers.contains(&p.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unsupported parser requested: {}", p),
            ));
        }
    }

    let allowed_detectors = ["json", "syslog", "cef"];
    for d in &payload.pipeline_config.inference_detectors {
        if !allowed_detectors.contains(&d.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unsupported inference detector requested: {}", d),
            ));
        }
    }

    let framer = NewlineFramer;
    let mut parser_registry = ParserRegistry::new();

    // Only register the parsers explicitly requested
    for p in &payload.pipeline_config.parser_registry {
        match p.as_str() {
            "json-flat" => {
                let _ =
                    parser_registry.register(Box::new(JsonParser::new()), LifecycleStage::Deployed);
            }
            "syslog" => {
                let _ = parser_registry
                    .register(Box::new(SyslogParser::new()), LifecycleStage::Deployed);
            }
            "cef" => {
                let _ =
                    parser_registry.register(Box::new(CefParser::new()), LifecycleStage::Deployed);
            }
            _ => {}
        }
    }

    let mut inference_engine = InferenceEngine::new();
    for d in &payload.pipeline_config.inference_detectors {
        match d.as_str() {
            "json" => inference_engine.add_detector("json", ulpx_infer::evidence::detect_json),
            "syslog" => {
                inference_engine.add_detector("syslog", ulpx_infer::evidence::detect_syslog)
            }
            "cef" => inference_engine.add_detector("cef", ulpx_infer::evidence::detect_cef),
            _ => {}
        }
    }

    let ir_converter = CompositeConverter::default_registry();
    let mapping_engine = MappingEngine::default_registry();

    let pipeline = ReplayPipeline::new(
        &*(state.store) as &(dyn EvidenceStore + 'static),
        &framer,
        ComponentConfig {
            id: payload.pipeline_config.framer_id.clone(),
            version: payload.pipeline_config.framer_version.clone(),
        },
        &parser_registry,
        &inference_engine,
        &ir_converter,
        &mapping_engine,
        ComponentConfig {
            id: payload.pipeline_config.mapper_id.clone(),
            version: payload.pipeline_config.mapper_version.clone(),
        },
    );

    let interpretation = pipeline.replay(&id).map_err(|e| match e {
        ulpx_core::storage::StoreError::NotFound => {
            (StatusCode::NOT_FOUND, "Event not found".to_string())
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal replay error".to_string(),
        ),
    })?;

    Ok(Json(ApiDetailedInterpretation::from(&interpretation)))
}
