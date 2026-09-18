pub mod models;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use ulpx_core::event::EventId;
use ulpx_core::storage::{EvidenceStore, StoreError};
use ulpx_core::framing::newline::NewlineFramer;
use ulpx_core::parser::{LifecycleStage, ParserRegistry};
use ulpx_core::parser::json::JsonParser;
use ulpx_core::parser::syslog::SyslogParser;
use ulpx_core::parser::cef::CefParser;
use ulpx_infer::engine::InferenceEngine;
use ulpx_mapping::engine::MappingEngine;
use ulpx_ir::convert::CompositeConverter;
use ulpx_replay::{ReplayPipeline, interpretation::ComponentConfig};
use crate::models::{ApiRawEvent, ApiInterpretation};

pub struct AppState {
    pub store: Arc<dyn EvidenceStore + Send + Sync>,
}

pub fn create_router(store: Arc<dyn EvidenceStore + Send + Sync>) -> Router {
    let state = Arc::new(AppState { store });
    Router::new()
        .route("/api/v1/evidence/:event_id", get(get_evidence))
        .route("/api/v1/interpretation/:event_id", get(get_interpretation))
        .with_state(state)
}

async fn get_evidence(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> Result<Json<ApiRawEvent>, (StatusCode, String)> {
    let id = EventId::new(event_id.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid EventId format".to_string()))?;

    let event = state.store.retrieve(&id)
        .map_err(|e| match e {
            StoreError::NotFound => (StatusCode::NOT_FOUND, "Event not found".to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal store error".to_string()),
        })?;

    Ok(Json(ApiRawEvent::from(&event)))
}

async fn get_interpretation(
    State(state): State<Arc<AppState>>,
    Path(event_id): Path<String>,
) -> Result<Json<ApiInterpretation>, (StatusCode, String)> {
    let id = EventId::new(event_id.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid EventId format".to_string()))?;

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

    let interpretation = pipeline.replay(&id)
        .map_err(|e| match e {
            ulpx_core::storage::StoreError::NotFound => (StatusCode::NOT_FOUND, "Event not found".to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal replay error".to_string()),
        })?;

    if !interpretation.integrity_verified {
        return Err((StatusCode::CONFLICT, "Integrity verification failed for event".to_string()));
    }

    Ok(Json(ApiInterpretation::from(&interpretation)))
}