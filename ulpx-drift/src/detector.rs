use crate::profile::DriftProfile;
use crate::report::{DriftItem, DriftReport, DriftType, VocabularyDrift, VolumeDrift};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct DriftDetector {
    /// Percentage change in volume to consider as drift (e.g., 0.50 for 50%)
    pub volume_threshold_pct: f64,
    /// Percentage change in frequency of a key/format to consider as drift (e.g., 0.20 for 20%)
    pub frequency_threshold_pct: f64,
}

impl Default for DriftDetector {
    fn default() -> Self {
        Self {
            volume_threshold_pct: 0.50,
            frequency_threshold_pct: 0.15,
        }
    }
}

impl DriftDetector {
    pub fn new(volume_threshold: f64, freq_threshold: f64) -> Self {
        Self {
            volume_threshold_pct: volume_threshold,
            frequency_threshold_pct: freq_threshold,
        }
    }

    pub fn detect(&self, baseline: &DriftProfile, current: &DriftProfile) -> DriftReport {
        let volume_drift = self.detect_volume(baseline.total_events, current.total_events);

        let format_drift = self.detect_frequencies(
            &baseline.formats,
            &current.formats,
            baseline.total_events,
            current.total_events,
        );

        let structural_drift = self.detect_frequencies(
            &baseline.structural_fields,
            &current.structural_fields,
            baseline.total_events,
            current.total_events,
        );

        let schema_drift = self.detect_frequencies(
            &baseline.schema_fields,
            &current.schema_fields,
            baseline.total_events,
            current.total_events,
        );

        let semantic_drift = self.detect_frequencies(
            &baseline.semantic_mappings,
            &current.semantic_mappings,
            baseline.total_events,
            current.total_events,
        );

        let vocabulary_drift = self.detect_vocabulary(&baseline.vocabulary, &current.vocabulary);

        DriftReport {
            source: current.source.clone(),
            volume_drift,
            format_drift,
            structural_drift,
            semantic_drift,
            schema_drift,
            vocabulary_drift,
        }
    }

    fn detect_volume(&self, old_count: u64, new_count: u64) -> Option<VolumeDrift> {
        if old_count == 0 {
            return None; // Cannot detect volume drift from 0 baseline sensibly
        }

        let diff = (new_count as f64 - old_count as f64).abs();
        let pct_change = diff / old_count as f64;

        if pct_change >= self.volume_threshold_pct {
            Some(VolumeDrift {
                old_count,
                new_count,
                percent_change: pct_change,
            })
        } else {
            None
        }
    }

    fn detect_frequencies(
        &self,
        base_map: &HashMap<String, u64>,
        curr_map: &HashMap<String, u64>,
        base_total: u64,
        curr_total: u64,
    ) -> Vec<DriftItem<String>> {
        let mut drift = Vec::new();
        let mut all_keys = HashSet::new();

        for k in base_map.keys() {
            all_keys.insert(k.clone());
        }
        for k in curr_map.keys() {
            all_keys.insert(k.clone());
        }

        for k in all_keys {
            let base_count = base_map.get(&k).copied().unwrap_or(0);
            let curr_count = curr_map.get(&k).copied().unwrap_or(0);

            if base_count == 0 && curr_count > 0 {
                drift.push(DriftItem {
                    item: k,
                    drift_type: DriftType::Added,
                });
            } else if base_count > 0 && curr_count == 0 {
                drift.push(DriftItem {
                    item: k,
                    drift_type: DriftType::Removed,
                });
            } else if base_count > 0 && curr_count > 0 && base_total > 0 && curr_total > 0 {
                let base_pct = base_count as f64 / base_total as f64;
                let curr_pct = curr_count as f64 / curr_total as f64;

                if (curr_pct - base_pct).abs() >= self.frequency_threshold_pct {
                    drift.push(DriftItem {
                        item: k,
                        drift_type: DriftType::FrequencyChanged {
                            old_pct: base_pct,
                            new_pct: curr_pct,
                        },
                    });
                }
            }
        }

        drift.sort_by(|a, b| a.item.cmp(&b.item)); // Ensure deterministic output
        drift
    }

    fn detect_vocabulary(
        &self,
        base_vocab: &HashMap<String, HashMap<String, u64>>,
        curr_vocab: &HashMap<String, HashMap<String, u64>>,
    ) -> Vec<VocabularyDrift> {
        let mut drifts = Vec::new();

        let mut all_fields = HashSet::new();
        for k in base_vocab.keys() {
            all_fields.insert(k.clone());
        }
        for k in curr_vocab.keys() {
            all_fields.insert(k.clone());
        }

        for field in all_fields {
            let base_map = base_vocab.get(&field);
            let curr_map = curr_vocab.get(&field);

            if let (Some(b), Some(c)) = (base_map, curr_map) {
                let b_total: u64 = b.values().sum();
                let c_total: u64 = c.values().sum();

                let mut values_added = Vec::new();
                let mut values_removed = Vec::new();
                let mut frequency_changes = Vec::new();

                let mut all_vals = HashSet::new();
                for k in b.keys() {
                    all_vals.insert(k.clone());
                }
                for k in c.keys() {
                    all_vals.insert(k.clone());
                }

                for val in all_vals {
                    let b_count = b.get(&val).copied().unwrap_or(0);
                    let c_count = c.get(&val).copied().unwrap_or(0);

                    if b_count == 0 && c_count > 0 {
                        values_added.push(val.clone());
                    } else if b_count > 0 && c_count == 0 {
                        values_removed.push(val.clone());
                    } else if b_total > 0 && c_total > 0 {
                        let b_pct = b_count as f64 / b_total as f64;
                        let c_pct = c_count as f64 / c_total as f64;
                        if (c_pct - b_pct).abs() >= self.frequency_threshold_pct {
                            frequency_changes.push((val.clone(), b_pct, c_pct));
                        }
                    }
                }

                if !values_added.is_empty()
                    || !values_removed.is_empty()
                    || !frequency_changes.is_empty()
                {
                    values_added.sort();
                    values_removed.sort();
                    frequency_changes.sort_by(|a, b| a.0.cmp(&b.0));
                    drifts.push(VocabularyDrift {
                        field,
                        values_added,
                        values_removed,
                        frequency_changes,
                    });
                }
            }
        }

        drifts.sort_by(|a, b| a.field.cmp(&b.field));
        drifts
    }
}
