pub mod diff;
pub mod interpretation;

use std::time::SystemTime;
use ulpx_core::event::EventId;
use ulpx_core::framing::Framer;
use ulpx_core::parser::{ParserError, ParserRegistry, ParserResult};
use ulpx_core::storage::{EvidenceStore, StoreError};
use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::model::{AbstentionReason, InferenceOutcome};
use ulpx_ir::convert::IrConverter;
use ulpx_mapping::engine::MappingEngine;

use crate::interpretation::{
    ComponentConfig, FrameExecution, FrameInterpretation, InferenceExecution, Interpretation,
    InterpretationId, PipelineConfiguration,
};

#[derive(Debug, Clone, PartialEq)]
pub enum ParserOutcome {
    Success(ParserResult),
    Failed(ParserError),
    Abstained,
}

pub struct ReplayPipeline<'a> {
    store: &'a dyn EvidenceStore,
    framer: &'a dyn Framer,
    framer_config: ComponentConfig,
    parser_registry: &'a ParserRegistry,
    inference_engine: &'a InferenceEngine,
    ir_converter: &'a dyn IrConverter,
    mapping_engine: &'a MappingEngine,
    mapper_config: ComponentConfig,
}

impl<'a> ReplayPipeline<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: &'a dyn EvidenceStore,
        framer: &'a dyn Framer,
        framer_config: ComponentConfig,
        parser_registry: &'a ParserRegistry,
        inference_engine: &'a InferenceEngine,
        ir_converter: &'a dyn IrConverter,
        mapping_engine: &'a MappingEngine,
        mapper_config: ComponentConfig,
    ) -> Self {
        Self {
            store,
            framer,
            framer_config,
            parser_registry,
            inference_engine,
            ir_converter,
            mapping_engine,
            mapper_config,
        }
    }

    pub fn replay(&self, event_id: &EventId) -> Result<Interpretation, StoreError> {
        let raw_event = self.store.retrieve(event_id)?;
        let verify_result = ulpx_core::integrity::verify_chain(self.store, event_id)?;
        let integrity_verified = verify_result.is_success();
        let mut integrity_error = None;

        if !integrity_verified {
            integrity_error = Some(verify_result);
        }

        let parser_reg_config = self
            .parser_registry
            .configuration_identity()
            .into_iter()
            .map(|(id, version)| ComponentConfig { id, version })
            .collect();

        let pipeline_config = PipelineConfiguration {
            framer: self.framer_config.clone(),
            mapper: self.mapper_config.clone(),
            parser_registry: parser_reg_config,
            inference_detectors: self.inference_engine.configuration_identity(),
        };

        if !integrity_verified {
            let id = InterpretationId::generate(event_id, &pipeline_config).unwrap();
            return Ok(Interpretation {
                id,
                source_event_id: event_id.clone(),
                pipeline_config,
                frames: Vec::new(),
                trailing_frame_error: None,
                created_at: SystemTime::now(),
                integrity_verified: false,
                integrity_error,
            });
        }

        let (frames, trailing_error) = self.framer.frame_all(raw_event.as_bytes());
        let mut frame_interpretations = Vec::with_capacity(frames.len());

        for (i, frame) in frames.into_iter().enumerate() {
            let frame_bytes = frame.as_bytes().to_vec();
            let mut parser_used = None;
            let mut inference = InferenceExecution::NotInvoked;
            let mut parser_outcome;
            let mut inference_decision = None;

            let result = self.parser_registry.parse_first(&frame);
            match result {
                Ok(parsed) => {
                    parser_used = Some(ComponentConfig {
                        id: parsed.parser_id.clone(),
                        version: parsed.parser_version.to_string(),
                    });
                    parser_outcome = ParserOutcome::Success(parsed);
                }
                Err(err) => {
                    parser_outcome = ParserOutcome::Failed(err);
                }
            }

            if matches!(
                parser_outcome,
                ParserOutcome::Failed(ParserError::Unsupported) | ParserOutcome::Abstained
            ) {
                let inference_res = self
                    .inference_engine
                    .infer(&frame, Some(self.parser_registry));

                inference_decision = Some(inference_res.outcome.clone());

                match &inference_res.outcome {
                    InferenceOutcome::Recognized { candidate, .. } => {
                        inference = InferenceExecution::InvokedRecognized {
                            detector_id: candidate.format_name.clone(),
                        };
                        if let Some(parser) = self.parser_registry.get(&candidate.parser_id) {
                            match parser.parse(&frame) {
                                Ok(parsed) => {
                                    parser_used = Some(ComponentConfig {
                                        id: parsed.parser_id.clone(),
                                        version: parsed.parser_version.to_string(),
                                    });
                                    parser_outcome = ParserOutcome::Success(parsed);
                                }
                                Err(err) => {
                                    parser_outcome = ParserOutcome::Failed(err);
                                }
                            }
                        }
                    }
                    InferenceOutcome::Abstained { reason, .. } => {
                        let reason_str = match reason {
                            AbstentionReason::EmptyInput => "EmptyInput",
                            AbstentionReason::NoRecognizableStructure => "NoRecognizableStructure",
                            AbstentionReason::InsufficientEvidence => "InsufficientEvidence",
                            AbstentionReason::AmbiguousCandidates => "AmbiguousCandidates",
                        };
                        inference = InferenceExecution::InvokedAbstained {
                            reason: reason_str.to_string(),
                        };
                    }
                }
            }

            let mut canonical_event = None;
            let mut ir_event_opt = None;
            if let ParserOutcome::Success(ref parsed) = parser_outcome {
                if let Some(ir) = self.ir_converter.convert(event_id.clone(), parsed) {
                    canonical_event = self.mapping_engine.map(&ir);
                    ir_event_opt = Some(ir);
                }
            }

            let execution = FrameExecution {
                parser_used,
                inference,
            };

            frame_interpretations.push(FrameInterpretation {
                frame_index: i,
                frame_bytes,
                execution,
                parser_outcome,
                inference_decision,
                canonical_event,
                ir_event: ir_event_opt,
            });
        }

        let id = InterpretationId::generate(event_id, &pipeline_config).unwrap();

        Ok(Interpretation {
            id,
            source_event_id: event_id.clone(),
            pipeline_config,
            frames: frame_interpretations,
            trailing_frame_error: trailing_error,
            created_at: SystemTime::now(),
            integrity_verified: true,
            integrity_error: None,
        })
    }
}
