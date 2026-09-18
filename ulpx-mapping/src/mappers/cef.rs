use crate::context::MappingContext;
use crate::engine::SemanticMapper;
use crate::mappers::as_string;
use crate::model::{AbstentionReason, CanonicalEvent, Confidence, Severity};
use ulpx_ir::model::EventIr;

pub struct CefMapper;

impl SemanticMapper for CefMapper {
    fn map(&self, ir: &EventIr) -> Option<CanonicalEvent> {
        if ir.parser_id != "cef" {
            return None;
        }

        let mut ctx = MappingContext::new(ir);

        let timestamp = ctx.extract(
            "timestamp",
            &["rt"],
            "cef-rt-1",
            Confidence::Certain,
            as_string,
        );

        let source_ip = ctx.extract(
            "source_ip",
            &["src"],
            "cef-src-1",
            Confidence::Certain,
            as_string,
        );

        let source_hostname = ctx.extract(
            "source_hostname",
            &["shost"],
            "cef-shost-1",
            Confidence::Certain,
            as_string,
        );

        let dest_ip = ctx.extract(
            "dest_ip",
            &["dst"],
            "cef-dst-1",
            Confidence::Certain,
            as_string,
        );

        let dest_hostname = ctx.extract(
            "dest_hostname",
            &["dhost"],
            "cef-dhost-1",
            Confidence::Certain,
            as_string,
        );

        let message = ctx.extract(
            "message",
            &["cef.name"], // Usually CEF name is treated as the signature/message
            "cef-msg-1",
            Confidence::Probable,
            as_string,
        );

        let severity = ctx.extract(
            "severity",
            &["cef.severity"],
            "cef-sev-1",
            Confidence::Certain,
            |val, transforms| {
                let s = as_string(val, transforms)?;
                transforms.push("cef_severity_to_canonical".to_string());
                if let Ok(num) = s.parse::<u8>() {
                    match num {
                        0..=3 => Ok(Severity::Info),
                        4..=6 => Ok(Severity::Warning),
                        7..=8 => Ok(Severity::Error),
                        9..=10 => Ok(Severity::Critical),
                        _ => Err(AbstentionReason::TypeMismatch),
                    }
                } else {
                    let lower = s.to_lowercase();
                    transforms.push("lowercase".to_string());
                    match lower.as_str() {
                        "low" => Ok(Severity::Info),
                        "medium" => Ok(Severity::Warning),
                        "high" => Ok(Severity::Error),
                        "very-high" | "fatal" => Ok(Severity::Critical),
                        _ => Err(AbstentionReason::TypeMismatch),
                    }
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
