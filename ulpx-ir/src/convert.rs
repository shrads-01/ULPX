//! Converters from ParserResult to EventIr.

use crate::model::{EventIr, IrType, IrValue};
use ulpx_core::event::EventId;
use ulpx_core::parser::ParserResult;

/// A trait for converting parser-specific output into the canonical IR.
pub trait IrConverter {
    /// Attempt to convert a `ParserResult` into an `EventIr`.
    ///
    /// Returns `None` if this converter does not support the parser that
    /// produced the result.
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr>;
}

/// Converter for the `syslog-rfc3164` parser.
pub struct SyslogConverter;

impl IrConverter for SyslogConverter {
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr> {
        if result.parser_id != "syslog-rfc3164" {
            return None;
        }

        let mut ir = EventIr::new(
            event_id,
            result.parser_id.clone(),
            result.parser_version,
            result.raw_bytes.clone(),
        );

        for field in &result.fields {
            ir.fields.insert(
                field.name.clone(),
                IrValue {
                    ty: IrType::String(field.raw_value.clone()),
                    span: Some(field.span),
                },
            );
        }

        Some(ir)
    }
}

/// Converter for the `cef` parser.
pub struct CefConverter;

impl IrConverter for CefConverter {
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr> {
        if result.parser_id != "cef" {
            return None;
        }

        let mut ir = EventIr::new(
            event_id,
            result.parser_id.clone(),
            result.parser_version,
            result.raw_bytes.clone(),
        );

        for field in &result.fields {
            ir.fields.insert(
                field.name.clone(),
                IrValue {
                    ty: IrType::String(field.raw_value.clone()),
                    span: Some(field.span),
                },
            );
        }

        Some(ir)
    }
}

/// Baseline converter for the `json-flat` parser.
pub struct JsonConverter;

impl IrConverter for JsonConverter {
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr> {
        if result.parser_id != "json-flat" {
            return None;
        }

        let mut ir = EventIr::new(
            event_id,
            result.parser_id.clone(),
            result.parser_version,
            result.raw_bytes.clone(),
        );

        for field in &result.fields {
            let ty = match field.raw_value.as_str() {
                "null" => IrType::Null,
                "true" => IrType::Boolean(true),
                "false" => IrType::Boolean(false),
                _ => IrType::String(field.raw_value.clone()),
            };
            ir.fields.insert(
                field.name.clone(),
                IrValue {
                    ty,
                    span: Some(field.span),
                },
            );
        }

        Some(ir)
    }
}

/// Fallback converter for any parser without special typed rules.
/// Translates all fields as strings with their original span.
pub struct FallbackConverter;

impl IrConverter for FallbackConverter {
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr> {
        let mut ir = EventIr::new(
            event_id,
            result.parser_id.clone(),
            result.parser_version,
            result.raw_bytes.clone(),
        );

        for field in &result.fields {
            ir.fields.insert(
                field.name.clone(),
                IrValue {
                    ty: IrType::String(field.raw_value.clone()),
                    span: Some(field.span),
                },
            );
        }

        Some(ir)
    }
}

/// A composite converter that tries multiple underlying converters.
pub struct CompositeConverter {
    converters: Vec<Box<dyn IrConverter + Send + Sync>>,
}

impl Default for CompositeConverter {
    fn default() -> Self {
        Self::new()
    }
}

impl CompositeConverter {
    pub fn new() -> Self {
        Self {
            converters: Vec::new(),
        }
    }

    pub fn add<C: IrConverter + Send + Sync + 'static>(&mut self, converter: C) {
        self.converters.push(Box::new(converter));
    }

    pub fn default_registry() -> Self {
        let mut composite = Self::new();
        composite.add(SyslogConverter);
        composite.add(CefConverter);
        composite.add(JsonConverter);
        composite.add(FallbackConverter); // Must be last
        composite
    }
}

impl IrConverter for CompositeConverter {
    fn convert(&self, event_id: EventId, result: &ParserResult) -> Option<EventIr> {
        for converter in &self.converters {
            if let Some(ir) = converter.convert(event_id.clone(), result) {
                return Some(ir);
            }
        }
        None
    }
}
