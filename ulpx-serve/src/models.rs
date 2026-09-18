use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use ulpx_core::event::RawEvent;
use ulpx_replay::interpretation::Interpretation;
use ulpx_replay::ParserOutcome;

#[derive(Serialize, Deserialize)]
pub struct ApiRawEvent {
    pub event_id: String,
    pub source: String,
    pub payload_base64: String,
    pub integrity: Option<ApiIntegrityMetadata>,
}

#[derive(Serialize, Deserialize)]
pub struct ApiIntegrityMetadata {
    pub hash_hex: String,
    pub previous_link: Option<String>,
}

impl From<&RawEvent> for ApiRawEvent {
    fn from(ev: &RawEvent) -> Self {
        Self {
            event_id: ev.metadata.event_id.as_str().to_string(),
            source: ev.metadata.source.0.clone(),
            payload_base64: general_purpose::STANDARD.encode(ev.as_bytes()),
            integrity: ev
                .metadata
                .integrity
                .as_ref()
                .map(|i| ApiIntegrityMetadata {
                    hash_hex: hex::encode(i.content_hash.0),
                    previous_link: i.previous_link.as_ref().map(|l| l.as_str().to_string()),
                }),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiInterpretation {
    pub interpretation_id: String,
    pub source_event_id: String,
    pub created_at_secs: u64,
    pub integrity_verified: bool,
    pub frames: Vec<ApiFrameInterpretation>,
}

#[derive(Serialize, Deserialize)]
pub struct ApiFrameInterpretation {
    pub frame_index: usize,
    pub frame_base64: String,
    pub parser_outcome: Option<String>,
    pub has_ir_event: bool,
    pub has_canonical_event: bool,
}

impl From<&Interpretation> for ApiInterpretation {
    fn from(i: &Interpretation) -> Self {
        Self {
            interpretation_id: hex::encode(i.id.0 .0),
            source_event_id: i.source_event_id.as_str().to_string(),
            created_at_secs: i
                .created_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            integrity_verified: i.integrity_verified,
            frames: i
                .frames
                .iter()
                .map(|f| ApiFrameInterpretation {
                    frame_index: f.frame_index,
                    frame_base64: general_purpose::STANDARD.encode(&f.frame_bytes),
                    parser_outcome: match &f.parser_outcome {
                        ParserOutcome::Success(res) => Some(res.parser_id.clone()),
                        _ => None,
                    },
                    has_ir_event: f.ir_event.is_some(),
                    has_canonical_event: f.canonical_event.is_some(),
                })
                .collect(),
        }
    }
}
