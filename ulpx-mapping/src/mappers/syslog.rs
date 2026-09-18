use crate::context::MappingContext;
use crate::engine::SemanticMapper;
use crate::mappers::as_string;
use crate::model::{AbstentionReason, CanonicalEvent, Confidence, Severity};
use ulpx_ir::model::EventIr;

pub struct SyslogMapper;

impl SemanticMapper for SyslogMapper {
    fn map(&self, ir: &EventIr) -> Option<CanonicalEvent> {
        if ir.parser_id != "syslog-rfc3164" {
            return None;
        }

        let mut ctx = MappingContext::new(ir);

        let timestamp = ctx.extract(
            "timestamp",
            &["syslog.timestamp"],
            "syslog-ts-1",
            Confidence::Certain,
            as_string,
        );

        let source_hostname = ctx.extract(
            "source_hostname",
            &["syslog.hostname"],
            "syslog-host-1",
            Confidence::Certain,
            as_string,
        );

        let message = ctx.extract(
            "message",
            &["syslog.message"],
            "syslog-msg-1",
            Confidence::Certain,
            as_string,
        );

        let severity = ctx.extract(
            "severity",
            &["syslog.severity"],
            "syslog-sev-1",
            Confidence::Certain,
            |val, transforms| {
                let s = as_string(val, transforms)?;
                transforms.push("syslog_priority_to_severity".to_string());
                if let Ok(num) = s.parse::<u8>() {
                    match num {
                        0 => Ok(Severity::Emergency),
                        1 => Ok(Severity::Alert),
                        2 => Ok(Severity::Critical),
                        3 => Ok(Severity::Error),
                        4 => Ok(Severity::Warning),
                        5 => Ok(Severity::Notice),
                        6 => Ok(Severity::Info),
                        7 => Ok(Severity::Debug),
                        _ => Err(AbstentionReason::TypeMismatch),
                    }
                } else {
                    Err(AbstentionReason::TypeMismatch)
                }
            },
        );

        Some(CanonicalEvent {
            event_id: ir.event_id.clone(),
            parser_id: ir.parser_id.clone(),
            parser_version: ir.parser_version,
            raw_bytes: ir.raw_bytes.clone(),
            timestamp,
            source_ip: None,
            source_hostname,
            dest_ip: None,
            dest_hostname: None,
            severity,
            message,
            action: None,
            unmapped: ctx.unmapped,
            abstentions: ctx.abstentions,
        })
    }
}
