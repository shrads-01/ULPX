use std::time::SystemTime;
use ulpx_core::event::EventId;
use ulpx_core::framing::{FrameError, Framer};
use ulpx_core::integrity::VerificationResult;
use ulpx_core::parser::{ParserError, ParserRegistry, ParserResult};
use ulpx_core::storage::{EvidenceStore, StoreError};
use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::model::InferenceOutcome;
use ulpx_ir::convert::IrConverter;
use ulpx_ir::model::EventIr;
use ulpx_mapping::engine::MappingEngine;
use ulpx_mapping::model::CanonicalEvent;

/// Top-level result of a replay operation for a single source event.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    pub source_event_id: EventId,
    /// Whether the integrity verification was successful before processing
    pub integrity_verified: bool,
    pub integrity_error: Option<VerificationResult>,
    /// System time when this replay was executed (metadata only, does not alter payload)
    pub replay_timestamp: SystemTime,
    /// Outcomes for each framed record extracted from the source event
    pub record_outcomes: Vec<RecordReplayOutcome>,
    /// Any frame error encountered at the end of the byte stream
    pub trailing_frame_error: Option<FrameError>,
}

#[derive(Debug, Clone)]
pub enum ParserOutcome {
    /// The parser successfully extracted fields.
    Success(ParserResult),
    /// The input was explicitly unsupported, malformed, or hit a resource limit.
    Failed(ParserError),
    /// No parser matched (via fallback) or parsing abstained.
    Abstained,
}

#[derive(Debug, Clone)]
pub struct RecordReplayOutcome {
    /// The exactly preserved frame bytes
    pub frame_bytes: Vec<u8>,

    /// The parser that was actually executed, if any
    pub parser_id: Option<String>,
    pub parser_version: Option<String>,

    /// The inference decision, if fallback was needed
    pub inference_decision: Option<InferenceOutcome>,

    /// The result from the parser
    pub parser_outcome: ParserOutcome,

    /// If parsing succeeded, the IR conversion outcome
    pub ir_event: Option<EventIr>,

    /// If IR conversion succeeded, the Semantic Mapping outcome
    pub canonical_event: Option<CanonicalEvent>,
}

pub struct ReplayPipeline<'a> {
    store: &'a dyn EvidenceStore,
    framer: &'a dyn Framer,
    parser_registry: &'a ParserRegistry,
    inference_engine: &'a InferenceEngine,
    ir_converter: &'a dyn IrConverter,
    mapping_engine: &'a MappingEngine,
}

impl<'a> ReplayPipeline<'a> {
    pub fn new(
        store: &'a dyn EvidenceStore,
        framer: &'a dyn Framer,
        parser_registry: &'a ParserRegistry,
        inference_engine: &'a InferenceEngine,
        ir_converter: &'a dyn IrConverter,
        mapping_engine: &'a MappingEngine,
    ) -> Self {
        Self {
            store,
            framer,
            parser_registry,
            inference_engine,
            ir_converter,
            mapping_engine,
        }
    }

    /// Replays a stored event through the full analytical pipeline.
    pub fn replay(&self, event_id: &EventId) -> Result<ReplayResult, StoreError> {
        let raw_event = self.store.retrieve(event_id)?;

        let verify_result = ulpx_core::integrity::verify_chain(self.store, event_id)?;
        if !verify_result.is_success() {
            return Ok(ReplayResult {
                source_event_id: event_id.clone(),
                integrity_verified: false,
                integrity_error: Some(verify_result),
                replay_timestamp: SystemTime::now(),
                record_outcomes: Vec::new(),
                trailing_frame_error: None,
            });
        }

        let (frames, trailing_error) = self.framer.frame_all(raw_event.as_bytes());
        let mut record_outcomes = Vec::with_capacity(frames.len());

        for frame in frames {
            let frame_bytes = frame.as_bytes().to_vec();
            let mut outcome = RecordReplayOutcome {
                frame_bytes: frame_bytes.clone(),
                parser_id: None,
                parser_version: None,
                inference_decision: None,
                parser_outcome: ParserOutcome::Abstained,
                ir_event: None,
                canonical_event: None,
            };

            // Attempt fast path via registry
            let result = self.parser_registry.parse_first(&frame);
            match result {
                Ok(parsed) => {
                    outcome.parser_id = Some(parsed.parser_id.clone());
                    outcome.parser_version = Some(parsed.parser_version.to_string());
                    outcome.parser_outcome = ParserOutcome::Success(parsed);
                }
                Err(err) => {
                    // For Unsupported or Malformed on fast path, we fall back to inference
                    outcome.parser_outcome = ParserOutcome::Failed(err);
                }
            }

            // If fast path failed with Unsupported or abstained, attempt inference
            if matches!(
                outcome.parser_outcome,
                ParserOutcome::Failed(ParserError::Unsupported) | ParserOutcome::Abstained
            ) {
                let inference_res = self
                    .inference_engine
                    .infer(&frame, Some(self.parser_registry));
                outcome.inference_decision = Some(inference_res.outcome.clone());

                if let InferenceOutcome::Recognized { candidate, .. } = inference_res.outcome {
                    // Re-run the recommended parser
                    if let Some(parser) = self.parser_registry.get(&candidate.parser_id) {
                        match parser.parse(&frame) {
                            Ok(parsed) => {
                                outcome.parser_id = Some(parsed.parser_id.clone());
                                outcome.parser_version = Some(parsed.parser_version.to_string());
                                outcome.parser_outcome = ParserOutcome::Success(parsed);
                            }
                            Err(err) => {
                                outcome.parser_outcome = ParserOutcome::Failed(err);
                            }
                        }
                    }
                }
            }

            // If we have a successful parse, map to IR and Canonical
            if let ParserOutcome::Success(ref parsed) = outcome.parser_outcome {
                if let Some(ir) = self.ir_converter.convert(event_id.clone(), parsed) {
                    outcome.canonical_event = self.mapping_engine.map(&ir);
                    outcome.ir_event = Some(ir);
                }
            }

            record_outcomes.push(outcome);
        }

        Ok(ReplayResult {
            source_event_id: event_id.clone(),
            integrity_verified: true,
            integrity_error: None,
            replay_timestamp: SystemTime::now(),
            record_outcomes,
            trailing_frame_error: trailing_error,
        })
    }
}

/// A deterministic comparison of two replay records, identifying meaningful changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordComparison {
    pub parser_changed: bool,
    pub fields_changed: bool,
    pub inference_changed: bool,
    pub mapping_changed: bool,
}

impl RecordComparison {
    pub fn compare(old: &RecordReplayOutcome, new: &RecordReplayOutcome) -> Self {
        let parser_changed =
            old.parser_id != new.parser_id || old.parser_version != new.parser_version;

        let fields_changed = match (&old.parser_outcome, &new.parser_outcome) {
            (ParserOutcome::Success(old_res), ParserOutcome::Success(new_res)) => {
                old_res.fields != new_res.fields
            }
            (old_o, new_o) => {
                // If they transitioned between success and failure/abstain, fields changed
                !matches!(
                    (old_o, new_o),
                    (ParserOutcome::Failed(_), ParserOutcome::Failed(_))
                        | (ParserOutcome::Abstained, ParserOutcome::Abstained)
                )
            }
        };

        let inference_changed = old.inference_decision != new.inference_decision;

        let mapping_changed = old.canonical_event != new.canonical_event;

        Self {
            parser_changed,
            fields_changed,
            inference_changed,
            mapping_changed,
        }
    }
}
