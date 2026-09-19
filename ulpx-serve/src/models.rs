use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ulpx_core::event::{EventMetadata, RawEvent};
use ulpx_infer::model::{FormatCandidate, InferenceConfidence, InferenceOutcome};
use ulpx_ir::model::{EventIr, IrType};
use ulpx_mapping::model::{CanonicalEvent, CanonicalField, Confidence, FieldProvenance};
use ulpx_replay::interpretation::Interpretation;
use ulpx_replay::ParserOutcome;

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiRawEvent {
    pub event_id: String,
    pub source: String,
    pub payload_base64: String,
    pub integrity: Option<ApiIntegrityMetadata>,
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiEventSummary {
    pub event_id: String,
    pub source: String,
    pub ingestion_timestamp: u128,
    pub has_integrity: bool,
}

impl From<&EventMetadata> for ApiEventSummary {
    fn from(m: &EventMetadata) -> Self {
        Self {
            event_id: m.event_id.as_str().to_string(),
            source: m.source.0.clone(),
            ingestion_timestamp: m.ingestion_timestamp.0,
            has_integrity: m.integrity.is_some(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDetailedInterpretation {
    pub interpretation_id: String,
    pub source_event_id: String,
    pub pipeline_config_identity: String,
    pub created_at_secs: u64,
    pub integrity_verified: bool,
    pub integrity_error: Option<String>,
    pub trailing_frame_error: Option<String>,
    pub frames: Vec<ApiDetailedFrame>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiDetailedFrame {
    pub frame_index: usize,
    pub frame_bytes_base64: String,
    pub parser_id: Option<String>,
    pub parser_version: Option<String>,
    pub parser_outcome: String,
    pub inference_decision: Option<ApiInferenceOutcome>,
    pub canonical_event: Option<ApiCanonicalEvent>,
    pub ir_event: Option<ApiIrEvent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiInferenceOutcome {
    pub decision: String,
    pub abstention_reason: Option<String>,
    pub recognized_candidate: Option<ApiFormatCandidate>,
    pub all_candidates: Vec<ApiFormatCandidate>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiFormatCandidate {
    pub parser_id: String,
    pub format_name: String,
    pub confidence: String,
    pub evidence: Vec<ApiEvidence>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiEvidence {
    pub detector_id: String,
    pub description: String,
    pub supports: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiCanonicalEvent {
    pub parser_id: String,
    pub timestamp: Option<ApiCanonicalField>,
    pub source_ip: Option<ApiCanonicalField>,
    pub source_hostname: Option<ApiCanonicalField>,
    pub dest_ip: Option<ApiCanonicalField>,
    pub dest_hostname: Option<ApiCanonicalField>,
    pub severity: Option<ApiCanonicalField>,
    pub message: Option<ApiCanonicalField>,
    pub action: Option<ApiCanonicalField>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiCanonicalField {
    pub value: String,
    pub provenance: ApiFieldProvenance,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiFieldProvenance {
    pub source_field: String,
    pub byte_span: Option<(usize, usize)>,
    pub transformations: Vec<String>,
    pub rule_id: String,
    pub confidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiIrEvent {
    pub parser_id: String,
    pub fields: BTreeMap<String, ApiIrValue>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiIrValue {
    pub value_type: String,
    pub value: serde_json::Value,
    pub byte_span: Option<(usize, usize)>,
}

impl From<&Interpretation> for ApiDetailedInterpretation {
    fn from(i: &Interpretation) -> Self {
        Self {
            interpretation_id: hex::encode(i.id.0 .0),
            source_event_id: i.source_event_id.as_str().to_string(),
            pipeline_config_identity: i
                .pipeline_config
                .configuration_identity()
                .map(|h| hex::encode(h.0))
                .unwrap_or_else(|_| "unknown".to_string()),
            created_at_secs: i
                .created_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            integrity_verified: i.integrity_verified,
            integrity_error: i.integrity_error.as_ref().map(|e| match e {
                ulpx_core::integrity::VerificationResult::HashMismatch { .. } => {
                    "HashMismatch".to_string()
                }
                ulpx_core::integrity::VerificationResult::BrokenLink(_) => "BrokenLink".to_string(),
                ulpx_core::integrity::VerificationResult::MissingMetadata(_) => {
                    "MissingMetadata".to_string()
                }
                ulpx_core::integrity::VerificationResult::CyclicLink(_) => "CyclicLink".to_string(),
                ulpx_core::integrity::VerificationResult::Success => "Success".to_string(),
            }),
            trailing_frame_error: i.trailing_frame_error.as_ref().map(|e| e.to_string()),
            frames: i.frames.iter().map(ApiDetailedFrame::from).collect(),
        }
    }
}

impl From<&ulpx_replay::interpretation::FrameInterpretation> for ApiDetailedFrame {
    fn from(f: &ulpx_replay::interpretation::FrameInterpretation) -> Self {
        let (parser_id, parser_version) = match &f.execution.parser_used {
            Some(p) => (Some(p.id.clone()), Some(p.version.clone())),
            None => (None, None),
        };
        let parser_outcome = match &f.parser_outcome {
            ParserOutcome::Success(_) => "Success",
            ParserOutcome::Failed(_) => "Failed",
            ParserOutcome::Abstained => "Abstained",
        }
        .to_string();

        let inference_decision = f.inference_decision.as_ref().map(|inf| match inf {
            InferenceOutcome::Recognized {
                candidate,
                all_candidates,
            } => ApiInferenceOutcome {
                decision: "Recognized".to_string(),
                abstention_reason: None,
                recognized_candidate: Some(ApiFormatCandidate::from(candidate)),
                all_candidates: all_candidates
                    .iter()
                    .map(ApiFormatCandidate::from)
                    .collect(),
            },
            InferenceOutcome::Abstained {
                reason,
                all_candidates,
            } => ApiInferenceOutcome {
                decision: "Abstained".to_string(),
                abstention_reason: Some(reason.to_string()),
                recognized_candidate: None,
                all_candidates: all_candidates
                    .iter()
                    .map(ApiFormatCandidate::from)
                    .collect(),
            },
        });

        Self {
            frame_index: f.frame_index,
            frame_bytes_base64: general_purpose::STANDARD.encode(&f.frame_bytes),
            parser_id,
            parser_version,
            parser_outcome,
            inference_decision,
            canonical_event: f.canonical_event.as_ref().map(ApiCanonicalEvent::from),
            ir_event: f.ir_event.as_ref().map(ApiIrEvent::from),
        }
    }
}

impl From<&FormatCandidate> for ApiFormatCandidate {
    fn from(c: &FormatCandidate) -> Self {
        Self {
            parser_id: c.parser_id.clone(),
            format_name: c.format_name.clone(),
            confidence: match c.confidence {
                InferenceConfidence::High => "High",
                InferenceConfidence::Medium => "Medium",
                InferenceConfidence::Low => "Low",
            }
            .to_string(),
            evidence: c
                .evidence
                .iter()
                .map(|e| ApiEvidence {
                    detector_id: e.detector_id.to_string(),
                    description: e.description.clone(),
                    supports: e.supports,
                })
                .collect(),
        }
    }
}

impl From<&CanonicalEvent> for ApiCanonicalEvent {
    fn from(c: &CanonicalEvent) -> Self {
        Self {
            parser_id: c.parser_id.clone(),
            timestamp: c.timestamp.as_ref().map(ApiCanonicalField::from),
            source_ip: c.source_ip.as_ref().map(ApiCanonicalField::from),
            source_hostname: c.source_hostname.as_ref().map(ApiCanonicalField::from),
            dest_ip: c.dest_ip.as_ref().map(ApiCanonicalField::from),
            dest_hostname: c.dest_hostname.as_ref().map(ApiCanonicalField::from),
            severity: c.severity.as_ref().map(|f| ApiCanonicalField {
                value: format!("{:?}", f.value),
                provenance: ApiFieldProvenance::from(&f.provenance),
            }),
            message: c.message.as_ref().map(ApiCanonicalField::from),
            action: c.action.as_ref().map(ApiCanonicalField::from),
        }
    }
}

impl<T: std::fmt::Display> From<&CanonicalField<T>> for ApiCanonicalField {
    fn from(f: &CanonicalField<T>) -> Self {
        Self {
            value: f.value.to_string(),
            provenance: ApiFieldProvenance::from(&f.provenance),
        }
    }
}

impl From<&FieldProvenance> for ApiFieldProvenance {
    fn from(p: &FieldProvenance) -> Self {
        Self {
            source_field: p.source_field.clone(),
            byte_span: p.span.as_ref().map(|s| (s.start, s.end)),
            transformations: p.transformations.clone(),
            rule_id: p.rule_id.clone(),
            confidence: match p.confidence {
                Confidence::Certain => "Certain",
                Confidence::Probable => "Probable",
                Confidence::Heuristic => "Heuristic",
            }
            .to_string(),
        }
    }
}

impl From<&EventIr> for ApiIrEvent {
    fn from(ir: &EventIr) -> Self {
        let mut fields = BTreeMap::new();
        for (k, v) in &ir.fields {
            let (v_type, json_val) = match &v.ty {
                IrType::String(s) => ("String", serde_json::Value::String(s.clone())),
                IrType::Integer(i) => ("Integer", serde_json::Value::Number((*i).into())),
                IrType::Float(f) => (
                    "Float",
                    serde_json::Number::from_f64(*f)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null),
                ),
                IrType::Boolean(b) => ("Boolean", serde_json::Value::Bool(*b)),
                IrType::Null => ("Null", serde_json::Value::Null),
            };
            fields.insert(
                k.clone(),
                ApiIrValue {
                    value_type: v_type.to_string(),
                    value: json_val,
                    byte_span: v.span.as_ref().map(|s| (s.start, s.end)),
                },
            );
        }
        Self {
            parser_id: ir.parser_id.clone(),
            fields,
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ReplayRequest {
    pub event_id: String,
    pub pipeline_config: ApiPipelineConfiguration,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiPipelineConfiguration {
    pub framer_id: String,
    pub framer_version: String,
    pub mapper_id: String,
    pub mapper_version: String,
    pub parser_registry: Vec<String>,
    pub inference_detectors: Vec<String>,
}
