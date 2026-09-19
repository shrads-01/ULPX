use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::time::UNIX_EPOCH;
use ulpx_ir::model::{EventIr, IrType};
use ulpx_mapping::model::{CanonicalEvent, Severity};
use ulpx_replay::interpretation::{InferenceExecution, Interpretation};

#[derive(Debug, thiserror::Error)]
pub enum OpenSearchError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Bulk indexing contained item-level errors: {0}")]
    BulkErrors(String),
    #[error("Invalid bulk response: {0}")]
    InvalidBulkResponse(String),
    #[error("Invalid index name: {0}")]
    InvalidIndexName(String),
    #[error("Duplicate frame index detected: {0}")]
    DuplicateFrameIndex(usize),
    #[error("Non-finite float value encountered in IR projection")]
    NonFiniteFloat,
}

#[derive(Serialize)]
pub struct BulkOperation {
    pub index: BulkIndexAction,
}

#[derive(Serialize)]
pub struct BulkIndexAction {
    pub _index: String,
    pub _id: String,
}

#[derive(Deserialize, Debug)]
pub struct BulkResponse {
    pub errors: bool,
    pub items: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OpenSearchDocument {
    #[serde(skip_serializing)]
    pub id: String,

    #[serde(skip_serializing)]
    pub index_name: String,

    pub source_event_id: String,
    pub interpretation_id: String,
    pub frame_index: usize,

    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    pub integrity_verified: bool,

    pub raw_evidence_id: String,

    pub parser: ParserProjection,
    pub inference: InferenceProjection,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical: Option<CanonicalProjection>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ir: Option<IrProjection>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParserProjection {
    pub id: Option<String>,
    pub version: Option<String>,
    pub outcome: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InferenceProjection {
    pub invoked: bool,
    pub decision: String,
    pub detector_id: Option<String>,
    pub abstention_reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CanonicalProjection {
    pub timestamp: Option<String>,
    pub source_ip: Option<String>,
    pub source_hostname: Option<String>,
    pub dest_ip: Option<String>,
    pub dest_hostname: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub action: Option<String>,
}

impl From<&CanonicalEvent> for CanonicalProjection {
    fn from(c: &CanonicalEvent) -> Self {
        Self {
            timestamp: c.timestamp.as_ref().map(|f| f.value.clone()),
            source_ip: c.source_ip.as_ref().map(|f| f.value.clone()),
            source_hostname: c.source_hostname.as_ref().map(|f| f.value.clone()),
            dest_ip: c.dest_ip.as_ref().map(|f| f.value.clone()),
            dest_hostname: c.dest_hostname.as_ref().map(|f| f.value.clone()),
            severity: c.severity.as_ref().map(|f| {
                match f.value {
                    Severity::Unknown => "Unknown",
                    Severity::Trace => "Trace",
                    Severity::Debug => "Debug",
                    Severity::Info => "Info",
                    Severity::Notice => "Notice",
                    Severity::Warning => "Warning",
                    Severity::Error => "Error",
                    Severity::Critical => "Critical",
                    Severity::Alert => "Alert",
                    Severity::Emergency => "Emergency",
                }
                .to_string()
            }),
            message: c.message.as_ref().map(|f| f.value.clone()),
            action: c.action.as_ref().map(|f| f.value.clone()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IrProjection {
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl IrProjection {
    pub fn try_from_ir(ir: &EventIr) -> Result<Self, OpenSearchError> {
        let mut fields = BTreeMap::new();
        for (k, v) in &ir.fields {
            let val = match &v.ty {
                IrType::String(s) => serde_json::Value::String(s.clone()),
                IrType::Integer(i) => serde_json::Value::Number((*i).into()),
                IrType::Float(f) => {
                    if !f.is_finite() {
                        return Err(OpenSearchError::NonFiniteFloat);
                    }
                    serde_json::Number::from_f64(*f)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::Null)
                }
                IrType::Boolean(b) => serde_json::Value::Bool(*b),
                IrType::Null => serde_json::Value::Null,
            };
            fields.insert(k.clone(), val);
        }
        Ok(Self { fields })
    }
}

impl OpenSearchDocument {
    pub fn generate_from_interpretation(
        interp: &Interpretation,
        index_name: &str,
    ) -> Result<Vec<Self>, OpenSearchError> {
        if index_name.is_empty()
            || index_name.contains(|c: char| {
                c.is_control()
                    || c == '\\'
                    || c == '/'
                    || c == '*'
                    || c == '?'
                    || c == '"'
                    || c == '<'
                    || c == '>'
                    || c == '|'
                    || c == ','
                    || c == '#'
            })
        {
            return Err(OpenSearchError::InvalidIndexName(index_name.to_string()));
        }

        let mut docs = Vec::with_capacity(interp.frames.len());
        let mut seen_frames = HashSet::new();

        let fallback_time = interp
            .created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        let fallback_timestamp_iso = chrono::DateTime::from_timestamp_millis(fallback_time as i64)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        for frame in &interp.frames {
            if !seen_frames.insert(frame.frame_index) {
                return Err(OpenSearchError::DuplicateFrameIndex(frame.frame_index));
            }

            let id = format!("{}_{}", interp.id.0, frame.frame_index);

            let (parser_id, parser_version) = match &frame.execution.parser_used {
                Some(p) => (Some(p.id.clone()), Some(p.version.clone())),
                None => (None, None),
            };

            let outcome = match &frame.parser_outcome {
                ulpx_replay::ParserOutcome::Success(_) => "Success",
                ulpx_replay::ParserOutcome::Failed(_) => "Failed",
                ulpx_replay::ParserOutcome::Abstained => "Abstained",
            };

            let mut inference_proj = InferenceProjection {
                invoked: false,
                decision: "NotInvoked".to_string(),
                detector_id: None,
                abstention_reason: None,
            };

            match &frame.execution.inference {
                InferenceExecution::NotInvoked => {}
                InferenceExecution::InvokedRecognized { detector_id } => {
                    inference_proj.invoked = true;
                    inference_proj.decision = "Recognized".to_string();
                    inference_proj.detector_id = Some(detector_id.clone());
                }
                InferenceExecution::InvokedAbstained { reason } => {
                    inference_proj.invoked = true;
                    inference_proj.decision = "Abstained".to_string();
                    inference_proj.abstention_reason = Some(reason.clone());
                }
            }

            let canonical_proj = frame
                .canonical_event
                .as_ref()
                .map(CanonicalProjection::from);

            let ir_proj = match &frame.ir_event {
                Some(ir) => Some(IrProjection::try_from_ir(ir)?),
                None => None,
            };

            docs.push(OpenSearchDocument {
                id,
                index_name: index_name.to_string(),
                source_event_id: interp.source_event_id.as_str().to_string(),
                interpretation_id: interp.id.0.to_string(),
                frame_index: frame.frame_index,
                timestamp: fallback_timestamp_iso.clone(),
                integrity_verified: interp.integrity_verified,
                raw_evidence_id: interp.source_event_id.as_str().to_string(),
                parser: ParserProjection {
                    id: parser_id,
                    version: parser_version,
                    outcome: outcome.to_string(),
                },
                inference: inference_proj,
                canonical: canonical_proj,
                ir: ir_proj,
            });
        }

        Ok(docs)
    }
}

#[derive(Clone)]
pub struct OpenSearchClient {
    client: reqwest::Client,
    base_url: String,
}

impl OpenSearchClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn bulk_index(&self, docs: &[OpenSearchDocument]) -> Result<(), OpenSearchError> {
        if docs.is_empty() {
            return Ok(());
        }

        let mut bulk_payload = String::new();
        for doc in docs {
            let action = BulkOperation {
                index: BulkIndexAction {
                    _index: doc.index_name.clone(),
                    _id: doc.id.clone(),
                },
            };
            bulk_payload.push_str(&serde_json::to_string(&action)?);
            bulk_payload.push('\n');
            bulk_payload.push_str(&serde_json::to_string(doc)?);
            bulk_payload.push('\n');
        }

        let url = format!("{}/_bulk", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-ndjson")
            .body(bulk_payload)
            .send()
            .await?;

        resp.error_for_status_ref()?;

        let body_text = resp.text().await?;
        if body_text.trim().is_empty() {
            return Err(OpenSearchError::InvalidBulkResponse(
                "Empty response body".into(),
            ));
        }

        let bulk_resp: BulkResponse = match serde_json::from_str(&body_text) {
            Ok(r) => r,
            Err(e) => {
                return Err(OpenSearchError::InvalidBulkResponse(format!(
                    "Failed to parse bulk response: {}",
                    e
                )))
            }
        };

        if bulk_resp.errors {
            let diag = bulk_resp
                .items
                .map(|i| serde_json::to_string(&i).unwrap_or_else(|_| "[]".to_string()))
                .unwrap_or_else(|| "Unknown item-level errors".to_string());

            return Err(OpenSearchError::BulkErrors(diag));
        }

        Ok(())
    }
}
