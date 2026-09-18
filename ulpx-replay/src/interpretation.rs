use crate::ParserOutcome;
use std::time::SystemTime;
use ulpx_core::event::EventId;
use ulpx_core::integrity::{compute_hash, ContentHash, VerificationResult};
use ulpx_infer::model::InferenceOutcome;
use ulpx_mapping::model::CanonicalEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentConfig {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineConfiguration {
    pub framer: ComponentConfig,
    pub mapper: ComponentConfig,
    pub parser_registry: Vec<ComponentConfig>,
    pub inference_detectors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceExecution {
    NotInvoked,
    InvokedRecognized { detector_id: String },
    InvokedAbstained { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameExecution {
    pub parser_used: Option<ComponentConfig>,
    pub inference: InferenceExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterpretationId(pub ContentHash);

impl InterpretationId {
    pub fn generate(source_id: &EventId, config: &PipelineConfiguration) -> Result<Self, String> {
        let mut buf = Vec::new();

        fn write_str(buf: &mut Vec<u8>, s: &str) -> Result<(), String> {
            let len = u32::try_from(s.len()).map_err(|_| "String length exceeds u32::MAX")?;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
            Ok(())
        }

        fn write_component(buf: &mut Vec<u8>, c: &ComponentConfig) -> Result<(), String> {
            write_str(buf, &c.id)?;
            write_str(buf, &c.version)?;
            Ok(())
        }

        write_str(&mut buf, source_id.as_str())?;
        write_component(&mut buf, &config.framer)?;
        write_component(&mut buf, &config.mapper)?;

        let parsers_len = u32::try_from(config.parser_registry.len()).map_err(|_| "Overflow")?;
        buf.extend_from_slice(&parsers_len.to_be_bytes());
        for p in &config.parser_registry {
            write_component(&mut buf, p)?;
        }

        let infer_len = u32::try_from(config.inference_detectors.len()).map_err(|_| "Overflow")?;
        buf.extend_from_slice(&infer_len.to_be_bytes());
        for d in &config.inference_detectors {
            write_str(&mut buf, d)?;
        }

        Ok(Self(compute_hash(&buf)))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameInterpretation {
    pub frame_index: usize,
    pub frame_bytes: Vec<u8>,
    pub execution: FrameExecution,
    pub parser_outcome: ParserOutcome,
    pub inference_decision: Option<InferenceOutcome>,
    pub canonical_event: Option<CanonicalEvent>,
    pub ir_event: Option<ulpx_ir::model::EventIr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Interpretation {
    pub id: InterpretationId,
    pub source_event_id: EventId,
    pub pipeline_config: PipelineConfiguration,
    pub frames: Vec<FrameInterpretation>,
    pub trailing_frame_error: Option<ulpx_core::framing::FrameError>,
    pub created_at: SystemTime,
    pub integrity_verified: bool,
    pub integrity_error: Option<VerificationResult>,
}
