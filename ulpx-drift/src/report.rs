use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DriftType {
    Added,
    Removed,
    FrequencyChanged { old_pct: f64, new_pct: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftItem<T> {
    pub item: T,
    pub drift_type: DriftType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeDrift {
    pub old_count: u64,
    pub new_count: u64,
    pub percent_change: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VocabularyDrift {
    pub field: String,
    pub values_added: Vec<String>,
    pub values_removed: Vec<String>,
    pub frequency_changes: Vec<(String, f64, f64)>, // value, old_pct, new_pct
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftReport {
    pub source: String,
    pub volume_drift: Option<VolumeDrift>,
    pub format_drift: Vec<DriftItem<String>>,
    pub structural_drift: Vec<DriftItem<String>>,
    pub semantic_drift: Vec<DriftItem<String>>,
    pub schema_drift: Vec<DriftItem<String>>,
    pub vocabulary_drift: Vec<VocabularyDrift>,
}

impl DriftReport {
    pub fn has_drift(&self) -> bool {
        self.volume_drift.is_some()
            || !self.format_drift.is_empty()
            || !self.structural_drift.is_empty()
            || !self.semantic_drift.is_empty()
            || !self.schema_drift.is_empty()
            || !self.vocabulary_drift.is_empty()
    }
}
