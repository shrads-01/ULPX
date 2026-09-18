use arrow::array::{Array, BinaryArray, BooleanArray, Int32Array, StringArray};
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::time::SystemTime;
use ulpx_core::event::EventId;
use ulpx_core::integrity::ContentHash;
use ulpx_core::parser::{ParserError, ParserResult, ParserVersion};
use ulpx_parquet::export_interpretation;
use ulpx_replay::interpretation::{
    ComponentConfig, FrameExecution, FrameInterpretation, InferenceExecution, Interpretation,
    InterpretationId, PipelineConfiguration,
};
use ulpx_replay::ParserOutcome;

fn create_dummy_interpretation(num_frames: usize) -> Interpretation {
    let mut frames = Vec::new();

    for i in 0..num_frames {
        let parser_outcome = if i % 2 == 0 {
            ParserOutcome::Success(ParserResult {
                fields: vec![],
                parser_id: "dummy-parser".to_string(),
                parser_version: ParserVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                raw_bytes: format!("frame_{}", i).into_bytes(),
            })
        } else {
            ParserOutcome::Failed(ParserError::Unsupported)
        };

        frames.push(FrameInterpretation {
            frame_index: i,
            frame_bytes: format!("frame_{}", i).into_bytes(),
            execution: FrameExecution {
                parser_used: Some(ComponentConfig {
                    id: "p".into(),
                    version: "1".into(),
                }),
                inference: InferenceExecution::NotInvoked,
            },
            parser_outcome,
            inference_decision: None,
            canonical_event: None,
            ir_event: None,
        });
    }

    Interpretation {
        id: InterpretationId(ContentHash([1u8; 32])),
        source_event_id: EventId::new("test-source-event").unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        integrity_verified: true,
        frames,
        trailing_frame_error: None,
        integrity_error: None,
        pipeline_config: PipelineConfiguration {
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
        },
    }
}

fn read_parquet_batch(bytes: &[u8]) -> RecordBatch {
    let b = Bytes::from(bytes.to_vec());
    let builder = ParquetRecordBatchReaderBuilder::try_new(b).unwrap();
    let mut reader = builder.build().unwrap();
    reader.next().unwrap().unwrap()
}

#[test]
fn test_successful_export_multiple_frames() {
    let interp = create_dummy_interpretation(3);
    let mut out_bytes = Vec::new();
    export_interpretation(&mut out_bytes, &interp).unwrap();

    let batch = read_parquet_batch(&out_bytes);
    assert_eq!(batch.num_rows(), 3);

    // Explicitly verify exact schema field names and types
    let schema = batch.schema();
    assert_eq!(schema.field(0).name(), "source_event_id");
    assert_eq!(schema.field(0).data_type(), &DataType::Utf8);
    assert_eq!(schema.field(1).name(), "interpretation_id");
    assert_eq!(schema.field(1).data_type(), &DataType::Utf8);
    assert_eq!(schema.field(2).name(), "frame_index");
    assert_eq!(schema.field(2).data_type(), &DataType::Int32);
    assert_eq!(schema.field(3).name(), "frame_bytes");
    assert_eq!(schema.field(3).data_type(), &DataType::Binary);
    assert_eq!(schema.field(4).name(), "parser_id");
    assert_eq!(schema.field(4).data_type(), &DataType::Utf8);
    assert!(schema.field(4).is_nullable()); // Must be nullable
    assert_eq!(schema.field(5).name(), "integrity_verified");
    assert_eq!(schema.field(5).data_type(), &DataType::Boolean);
    assert_eq!(schema.field(6).name(), "created_at_secs");
    assert_eq!(schema.field(6).data_type(), &DataType::Int64);

    // Verify determinism and ordering
    let frame_index_col = batch
        .column(2)
        .as_any()
        .downcast_ref::<Int32Array>()
        .unwrap();
    assert_eq!(frame_index_col.value(0), 0);
    assert_eq!(frame_index_col.value(1), 1);
    assert_eq!(frame_index_col.value(2), 2);

    // Verify non-success parser outcome produces null parser_id
    let parser_id_col = batch
        .column(4)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(parser_id_col.value(0), "dummy-parser");
    assert!(parser_id_col.is_null(1)); // Failed outcome is null
    assert_eq!(parser_id_col.value(2), "dummy-parser");

    // Verify exact binary frame bytes
    let frame_bytes_col = batch
        .column(3)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .unwrap();
    assert_eq!(frame_bytes_col.value(0), b"frame_0");
    assert_eq!(frame_bytes_col.value(1), b"frame_1");

    // Verify integrity_verified propagation
    let integrity_col = batch
        .column(5)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    assert!(integrity_col.value(0));

    // Repeated export produces identical output (determinism)
    let mut out_bytes2 = Vec::new();
    export_interpretation(&mut out_bytes2, &interp).unwrap();
    assert_eq!(out_bytes, out_bytes2);
}

#[test]
fn test_empty_interpretation_export() {
    let interp = create_dummy_interpretation(0);
    let mut out_bytes = Vec::new();
    export_interpretation(&mut out_bytes, &interp).unwrap();

    let b = Bytes::from(out_bytes.clone());
    let builder = ParquetRecordBatchReaderBuilder::try_new(b).unwrap();
    let mut reader = builder.build().unwrap();
    let batch_opt = reader.next();

    if let Some(Ok(batch)) = batch_opt {
        assert_eq!(batch.num_rows(), 0);
    }
}
