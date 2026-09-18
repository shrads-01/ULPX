use crate::context::MappingContext;
use crate::engine::SemanticMapper;
use crate::mappers::as_string;
use crate::model::{AbstentionReason, CanonicalEvent, Confidence, Severity};
use ulpx_ir::model::EventIr;

pub struct JsonHeuristicMapper;

impl SemanticMapper for JsonHeuristicMapper {
    fn map(&self, ir: &EventIr) -> Option<CanonicalEvent> {
        if ir.parser_id != "json-flat" {
            return None;
        }

        let mut ctx = MappingContext::new(ir);

        // JSON has no strict schema, so these are all Heuristic.
        // By passing multiple source names, if more than one is found,
        // MappingContext::extract will automatically ABSTAIN due to ambiguity.

        let timestamp = ctx.extract(
            "timestamp",
            &["timestamp", "@timestamp", "time"],
            "json-heur-ts-1",
            Confidence::Heuristic,
            as_string,
        );

        let source_ip = ctx.extract(
            "source_ip",
            &["src_ip", "source_ip", "client_ip"],
            "json-heur-srcip-1",
            Confidence::Heuristic,
            as_string,
        );

        let source_hostname = ctx.extract(
            "source_hostname",
            &["host", "hostname", "src_host"],
            "json-heur-srchost-1",
            Confidence::Heuristic,
            as_string,
        );

        let dest_ip = ctx.extract(
            "dest_ip",
            &["dst_ip", "dest_ip", "target_ip"],
            "json-heur-dstip-1",
            Confidence::Heuristic,
            as_string,
        );

        let dest_hostname = ctx.extract(
            "dest_hostname",
            &["dst_host", "dest_host", "target_host"],
            "json-heur-dsthost-1",
            Confidence::Heuristic,
            as_string,
        );

        let message = ctx.extract(
            "message",
            &["message", "msg"],
            "json-heur-msg-1",
            Confidence::Heuristic,
            as_string,
        );

        let severity = ctx.extract(
            "severity",
            &["level", "severity", "log_level"],
            "json-heur-sev-1",
            Confidence::Heuristic,
            |val| {
                let s = as_string(val)?;
                let lower = s.to_lowercase();
                match lower.as_str() {
                    "trace" => Ok(Severity::Trace),
                    "debug" => Ok(Severity::Debug),
                    "info" | "information" => Ok(Severity::Info),
                    "notice" => Ok(Severity::Notice),
                    "warn" | "warning" => Ok(Severity::Warning),
                    "err" | "error" => Ok(Severity::Error),
                    "crit" | "critical" | "fatal" => Ok(Severity::Critical),
                    "alert" => Ok(Severity::Alert),
                    "emerg" | "emergency" => Ok(Severity::Emergency),
                    _ => Err(AbstentionReason::TypeMismatch),
                }
            },
        );

        Some(CanonicalEvent {
            event_id: ir.event_id.clone(),
            parser_id: ir.parser_id.clone(),
            parser_version: ir.parser_version,
            raw_bytes: ir.raw_bytes.clone(),
            timestamp,
            source_ip,
            source_hostname,
            dest_ip,
            dest_hostname,
            severity,
            message,
            action: None,
            unmapped: ctx.unmapped,
            abstentions: ctx.abstentions,
        })
    }
}
