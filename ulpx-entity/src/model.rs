use ulpx_mapping::model::{Confidence, FieldProvenance};
use ulpx_replay::interpretation::InterpretationId;

/// Deterministic type of an entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    IPv4,
    IPv6,
    Hostname,
}

/// The semantic role the entity played in an observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityRole {
    SourceIp,
    DestIp,
    SourceHostname,
    DestHostname,
}

/// A normalized entity identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityNode {
    pub entity_type: EntityType,
    pub value: String, // Normalized value (e.g., lowercased hostname, trimmed IP)
}

/// A specific observation linking an interpretation to an entity.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityObservation {
    pub node: EntityNode,
    pub interpretation_id: InterpretationId,
    pub frame_index: usize,
    pub role: EntityRole,
    pub provenance: FieldProvenance,
    pub confidence: Confidence,
}
