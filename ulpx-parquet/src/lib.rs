use arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Int32Builder, Int64Builder, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::sync::Arc;
use ulpx_replay::interpretation::Interpretation;
use ulpx_replay::ParserOutcome;

/// Export interpretation data deterministically to a Parquet writer.
///
/// Parquet is a derived export/analytics representation. The authoritative
/// lossless evidence remains in EvidenceStore.
pub fn export_interpretation<W: std::io::Write + Send>(
    writer: W,
    interpretation: &Interpretation,
) -> Result<(), Box<dyn std::error::Error>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("source_event_id", DataType::Utf8, false),
        Field::new("interpretation_id", DataType::Utf8, false),
        Field::new("frame_index", DataType::Int32, false),
        Field::new("frame_bytes", DataType::Binary, false),
        Field::new("parser_id", DataType::Utf8, true),
        Field::new("integrity_verified", DataType::Boolean, false),
        Field::new("created_at_secs", DataType::Int64, false),
    ]));

    let num_rows = interpretation.frames.len();

    // Builders
    let mut source_id_builder = StringBuilder::new();
    let mut interp_id_builder = StringBuilder::new();
    let mut frame_index_builder = Int32Builder::new();
    let mut frame_bytes_builder = BinaryBuilder::new();
    let mut parser_id_builder = StringBuilder::new();
    let mut integrity_builder = BooleanBuilder::new();
    let mut created_at_builder = Int64Builder::new();

    let source_id_str = interpretation.source_event_id.as_str();
    let interp_id_str = hex::encode(interpretation.id.0 .0);
    let created_at_secs = interpretation
        .created_at
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let integrity_verified = interpretation.integrity_verified;

    // Ordered deterministically by frame_index inherently since interpretation.frames is ordered
    for frame in &interpretation.frames {
        source_id_builder.append_value(source_id_str);
        interp_id_builder.append_value(&interp_id_str);
        frame_index_builder.append_value(frame.frame_index as i32);
        frame_bytes_builder.append_value(&frame.frame_bytes);
        integrity_builder.append_value(integrity_verified);
        created_at_builder.append_value(created_at_secs);

        match &frame.parser_outcome {
            ParserOutcome::Success(res) => parser_id_builder.append_value(&res.parser_id),
            _ => parser_id_builder.append_null(),
        }
    }

    let batch = if num_rows > 0 {
        RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(source_id_builder.finish()) as ArrayRef,
                Arc::new(interp_id_builder.finish()) as ArrayRef,
                Arc::new(frame_index_builder.finish()) as ArrayRef,
                Arc::new(frame_bytes_builder.finish()) as ArrayRef,
                Arc::new(parser_id_builder.finish()) as ArrayRef,
                Arc::new(integrity_builder.finish()) as ArrayRef,
                Arc::new(created_at_builder.finish()) as ArrayRef,
            ],
        )?
    } else {
        RecordBatch::new_empty(schema.clone())
    };

    let props = WriterProperties::builder().build();
    let mut arrow_writer = ArrowWriter::try_new(writer, schema, Some(props))?;

    arrow_writer.write(&batch)?;
    arrow_writer.close()?;

    Ok(())
}
