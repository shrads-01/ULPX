use crate::model::{EntityNode, EntityObservation, EntityRole, EntityType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use ulpx_mapping::model::{CanonicalEvent, CanonicalField};
use ulpx_replay::interpretation::Interpretation;

/// Resolves an entire interpretation into its constituent entity observations.
pub fn resolve_interpretation(interpretation: &Interpretation) -> Vec<EntityObservation> {
    let mut observations = Vec::new();

    for frame in &interpretation.frames {
        if let Some(canonical) = &frame.canonical_event {
            observations.extend(resolve_canonical_event(
                interpretation.id.clone(),
                frame.frame_index,
                canonical,
            ));
        }
    }

    observations
}

/// Normalizes an IPv4 string deterministically.
pub fn normalize_ipv4(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Ok(ip) = Ipv4Addr::from_str(trimmed) {
        Some(ip.to_string())
    } else {
        None
    }
}

/// Normalizes an IPv6 string deterministically.
pub fn normalize_ipv6(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Ok(ip) = Ipv6Addr::from_str(trimmed) {
        Some(ip.to_string())
    } else {
        None
    }
}

/// Normalizes a hostname (lowercase, trim).
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn process_ip_field(
    id: ulpx_replay::interpretation::InterpretationId,
    frame_index: usize,
    role: EntityRole,
    field: &CanonicalField<String>,
) -> Option<EntityObservation> {
    if let Some(ip) = normalize_ipv4(&field.value) {
        return Some(EntityObservation {
            node: EntityNode {
                entity_type: EntityType::IPv4,
                value: ip,
            },
            interpretation_id: id,
            frame_index,
            role,
            provenance: field.provenance.clone(),
            confidence: field.provenance.confidence,
        });
    }

    if let Some(ip) = normalize_ipv6(&field.value) {
        return Some(EntityObservation {
            node: EntityNode {
                entity_type: EntityType::IPv6,
                value: ip,
            },
            interpretation_id: id,
            frame_index,
            role,
            provenance: field.provenance.clone(),
            confidence: field.provenance.confidence,
        });
    }

    None
}

fn process_hostname_field(
    id: ulpx_replay::interpretation::InterpretationId,
    frame_index: usize,
    role: EntityRole,
    field: &CanonicalField<String>,
) -> Option<EntityObservation> {
    if let Some(host) = normalize_hostname(&field.value) {
        return Some(EntityObservation {
            node: EntityNode {
                entity_type: EntityType::Hostname,
                value: host,
            },
            interpretation_id: id,
            frame_index,
            role,
            provenance: field.provenance.clone(),
            confidence: field.provenance.confidence,
        });
    }
    None
}

fn resolve_canonical_event(
    id: ulpx_replay::interpretation::InterpretationId,
    frame_index: usize,
    canonical: &CanonicalEvent,
) -> Vec<EntityObservation> {
    let mut obs = Vec::new();

    if let Some(f) = &canonical.source_ip {
        if let Some(o) = process_ip_field(id.clone(), frame_index, EntityRole::SourceIp, f) {
            obs.push(o);
        }
    }

    if let Some(f) = &canonical.dest_ip {
        if let Some(o) = process_ip_field(id.clone(), frame_index, EntityRole::DestIp, f) {
            obs.push(o);
        }
    }

    if let Some(f) = &canonical.source_hostname {
        if let Some(o) =
            process_hostname_field(id.clone(), frame_index, EntityRole::SourceHostname, f)
        {
            obs.push(o);
        }
    }

    if let Some(f) = &canonical.dest_hostname {
        if let Some(o) = process_hostname_field(id, frame_index, EntityRole::DestHostname, f) {
            obs.push(o);
        }
    }

    obs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use ulpx_core::event::EventId;
    use ulpx_core::integrity::ContentHash;
    use ulpx_core::parser::ParserVersion;
    use ulpx_mapping::model::{Confidence, FieldProvenance};

    fn dummy_interpretation_id() -> ulpx_replay::interpretation::InterpretationId {
        ulpx_replay::interpretation::InterpretationId(ContentHash([0; 32]))
    }

    fn dummy_provenance() -> FieldProvenance {
        FieldProvenance {
            source_field: "src".into(),
            span: Some(ulpx_core::parser::Span { start: 0, end: 8 }),
            transformations: vec![],
            rule_id: "test".into(),
            confidence: Confidence::Certain,
            parser_id: "test".into(),
            parser_version: ParserVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
        }
    }

    #[test]
    fn test_ip_normalization() {
        let field = CanonicalField {
            value: "  10.1.1.5  ".into(),
            provenance: dummy_provenance(),
        };
        let obs =
            process_ip_field(dummy_interpretation_id(), 0, EntityRole::SourceIp, &field).unwrap();
        assert_eq!(obs.node.entity_type, EntityType::IPv4);
        assert_eq!(obs.node.value, "10.1.1.5");
    }

    #[test]
    fn test_semantic_bounding() {
        let ce = CanonicalEvent {
            event_id: EventId::new("test").unwrap(),
            parser_id: "test".into(),
            parser_version: ParserVersion {
                major: 1,
                minor: 0,
                patch: 0,
            },
            raw_bytes: b"app_version=10.1.1.5".to_vec(),
            timestamp: None,
            source_ip: None,
            source_hostname: None,
            dest_ip: None,
            dest_hostname: None,
            severity: None,
            message: None,
            action: None,
            unmapped: BTreeMap::new(),
            abstentions: vec![],
        };

        let obs = resolve_canonical_event(dummy_interpretation_id(), 0, &ce);
        assert_eq!(obs.len(), 0);
    }
}
