use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ulpx_mapping::model::{CanonicalEvent, CanonicalField};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftProfile {
    pub source: String,
    pub window_start: i64,
    pub window_end: i64,

    pub total_events: u64,
    /// Format distribution (parser_id -> count)
    pub formats: HashMap<String, u64>,
    /// Structural distribution (all raw fields, mapped or unmapped -> count)
    pub structural_fields: HashMap<String, u64>,
    /// Schema distribution (canonical fields present -> count)
    pub schema_fields: HashMap<String, u64>,
    /// Semantic distribution (source_field -> canonical_field -> count)
    pub semantic_mappings: HashMap<String, u64>,
    /// Vocabulary distribution for string fields (field -> value -> count)
    pub vocabulary: HashMap<String, HashMap<String, u64>>,
}

impl DriftProfile {
    pub fn new(source: impl Into<String>, window_start: i64, window_end: i64) -> Self {
        Self {
            source: source.into(),
            window_start,
            window_end,
            total_events: 0,
            formats: HashMap::new(),
            structural_fields: HashMap::new(),
            schema_fields: HashMap::new(),
            semantic_mappings: HashMap::new(),
            vocabulary: HashMap::new(),
        }
    }

    /// Observe a canonical event and update the profile.
    pub fn observe(&mut self, event: &CanonicalEvent) {
        self.total_events += 1;

        *self.formats.entry(event.parser_id.clone()).or_insert(0) += 1;

        // Structural tracking from unmapped fields
        for key in event.unmapped.keys() {
            *self.structural_fields.entry(key.clone()).or_insert(0) += 1;
        }

        // Semantic & Schema & Structural tracking from canonical fields
        if let Some(ref field) = event.action {
            self.track_canonical("action", field);
            self.track_vocabulary("action", &field.value);
        }
        if let Some(ref field) = event.message {
            self.track_canonical("message", field);
        }
        if let Some(ref field) = event.source_ip {
            self.track_canonical("source_ip", field);
        }
        if let Some(ref field) = event.dest_ip {
            self.track_canonical("dest_ip", field);
        }
        if let Some(ref field) = event.source_hostname {
            self.track_canonical("source_hostname", field);
        }
        if let Some(ref field) = event.dest_hostname {
            self.track_canonical("dest_hostname", field);
        }
        if let Some(ref field) = event.severity {
            self.track_canonical("severity", field);
            self.track_vocabulary("severity", &format!("{:?}", field.value));
        }
    }

    fn track_canonical<T>(&mut self, canonical_name: &str, field: &CanonicalField<T>) {
        // Schema: the canonical field is present
        *self
            .schema_fields
            .entry(canonical_name.to_string())
            .or_insert(0) += 1;

        // Structural: the raw field is present
        *self
            .structural_fields
            .entry(field.provenance.source_field.clone())
            .or_insert(0) += 1;

        // Semantic: how this raw field was mapped to this canonical field
        let mapping_key = format!("{}->{}", field.provenance.source_field, canonical_name);
        *self.semantic_mappings.entry(mapping_key).or_insert(0) += 1;
    }

    fn track_vocabulary(&mut self, field: &str, value: &str) {
        // We limit vocabulary tracking to reasonable cardinality per field
        let vocab = self.vocabulary.entry(field.to_string()).or_default();
        if vocab.len() < 1000 || vocab.contains_key(value) {
            *vocab.entry(value.to_string()).or_insert(0) += 1;
        }
    }
}
