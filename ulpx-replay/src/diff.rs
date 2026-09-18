use crate::interpretation::{ComponentConfig, InferenceExecution, Interpretation};

#[derive(Debug, Clone, PartialEq)]
pub struct FieldDiff {
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameDiff {
    pub frame_index: usize,
    pub parser_changed: Option<(Option<ComponentConfig>, Option<ComponentConfig>)>,
    pub inference_changed: Option<(InferenceExecution, InferenceExecution)>,
    pub fields_added: Vec<String>,
    pub fields_removed: Vec<String>,
    pub fields_changed: Vec<(String, FieldDiff)>,
    pub abstentions_added: Vec<String>,
    pub abstentions_removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FrameStructureDiff {
    pub old_frame_count: usize,
    pub new_frame_count: usize,
    pub identical_structure: bool,
    pub added_frame_indices: Vec<usize>,
    pub removed_frame_indices: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InterpretationDiff {
    pub framer_changed: Option<(ComponentConfig, ComponentConfig)>,
    pub mapper_changed: Option<(ComponentConfig, ComponentConfig)>,
    pub inference_detectors_changed: bool,
    pub parser_registry_changed: bool,
    pub frame_structure: FrameStructureDiff,
    pub frame_diffs: Vec<FrameDiff>,
}

impl InterpretationDiff {
    pub fn compare(old: &Interpretation, new: &Interpretation) -> Self {
        let framer_changed = if old.pipeline_config.framer != new.pipeline_config.framer {
            Some((
                old.pipeline_config.framer.clone(),
                new.pipeline_config.framer.clone(),
            ))
        } else {
            None
        };

        let mapper_changed = if old.pipeline_config.mapper != new.pipeline_config.mapper {
            Some((
                old.pipeline_config.mapper.clone(),
                new.pipeline_config.mapper.clone(),
            ))
        } else {
            None
        };

        let inference_detectors_changed =
            old.pipeline_config.inference_detectors != new.pipeline_config.inference_detectors;
        let parser_registry_changed =
            old.pipeline_config.parser_registry != new.pipeline_config.parser_registry;

        let old_count = old.frames.len();
        let new_count = new.frames.len();

        let mut identical_structure = old_count == new_count;
        let mut added_frame_indices = Vec::new();
        let mut removed_frame_indices = Vec::new();

        let max_len = std::cmp::max(old_count, new_count);
        let mut byte_matched_indices = Vec::new();

        for i in 0..max_len {
            let o = old.frames.get(i);
            let n = new.frames.get(i);

            match (o, n) {
                (Some(o_frame), Some(n_frame)) => {
                    if o_frame.frame_bytes == n_frame.frame_bytes {
                        byte_matched_indices.push(i);
                    } else {
                        identical_structure = false;
                        removed_frame_indices.push(i);
                        added_frame_indices.push(i);
                    }
                }
                (Some(_), None) => {
                    identical_structure = false;
                    removed_frame_indices.push(i);
                }
                (None, Some(_)) => {
                    identical_structure = false;
                    added_frame_indices.push(i);
                }
                _ => {}
            }
        }

        let frame_structure = FrameStructureDiff {
            old_frame_count: old_count,
            new_frame_count: new_count,
            identical_structure,
            added_frame_indices,
            removed_frame_indices,
        };

        let mut frame_diffs = Vec::new();

        for &i in &byte_matched_indices {
            let o = &old.frames[i];
            let n = &new.frames[i];

            let parser_changed = if o.execution.parser_used != n.execution.parser_used {
                Some((
                    o.execution.parser_used.clone(),
                    n.execution.parser_used.clone(),
                ))
            } else {
                None
            };

            let inference_changed = if o.execution.inference != n.execution.inference {
                Some((o.execution.inference.clone(), n.execution.inference.clone()))
            } else {
                None
            };

            let mut fields_added = Vec::new();
            let mut fields_removed = Vec::new();
            let mut fields_changed = Vec::new();
            let mut abstentions_added = Vec::new();
            let mut abstentions_removed = Vec::new();

            if let Some(old_evt) = &o.canonical_event {
                if let Some(new_evt) = &n.canonical_event {
                    macro_rules! cmp_field {
                        ($name:literal, $o:expr, $n:expr) => {
                            match (&$o, &$n) {
                                (Some(o_f), Some(n_f)) => {
                                    if o_f != n_f {
                                        fields_changed.push((
                                            $name.to_string(),
                                            FieldDiff {
                                                old_value: Some(format!("{:?}", o_f.value)),
                                                new_value: Some(format!("{:?}", n_f.value)),
                                            },
                                        ));
                                    }
                                }
                                (Some(_), None) => fields_removed.push($name.to_string()),
                                (None, Some(_)) => fields_added.push($name.to_string()),
                                (None, None) => {}
                            }
                        };
                    }

                    cmp_field!("timestamp", old_evt.timestamp, new_evt.timestamp);
                    cmp_field!("source_ip", old_evt.source_ip, new_evt.source_ip);
                    cmp_field!(
                        "source_hostname",
                        old_evt.source_hostname,
                        new_evt.source_hostname
                    );
                    cmp_field!("dest_ip", old_evt.dest_ip, new_evt.dest_ip);
                    cmp_field!(
                        "dest_hostname",
                        old_evt.dest_hostname,
                        new_evt.dest_hostname
                    );
                    cmp_field!("severity", old_evt.severity, new_evt.severity);
                    cmp_field!("message", old_evt.message, new_evt.message);
                    cmp_field!("action", old_evt.action, new_evt.action);

                    for (k, v) in &old_evt.unmapped {
                        if let Some(nv) = new_evt.unmapped.get(k) {
                            if v != nv {
                                fields_changed.push((
                                    format!("unmapped.{}", k),
                                    FieldDiff {
                                        old_value: Some(format!("{:?}", v)),
                                        new_value: Some(format!("{:?}", nv)),
                                    },
                                ));
                            }
                        } else {
                            fields_removed.push(format!("unmapped.{}", k));
                        }
                    }
                    for k in new_evt.unmapped.keys() {
                        if !old_evt.unmapped.contains_key(k) {
                            fields_added.push(format!("unmapped.{}", k));
                        }
                    }

                    for old_a in &old_evt.abstentions {
                        let repr = format!("{:?}", old_a);
                        if !new_evt
                            .abstentions
                            .iter()
                            .any(|a| format!("{:?}", a) == repr)
                        {
                            abstentions_removed.push(repr);
                        }
                    }
                    for new_a in &new_evt.abstentions {
                        let repr = format!("{:?}", new_a);
                        if !old_evt
                            .abstentions
                            .iter()
                            .any(|a| format!("{:?}", a) == repr)
                        {
                            abstentions_added.push(repr);
                        }
                    }
                } else {
                    // New is missing
                    if old_evt.timestamp.is_some() {
                        fields_removed.push("timestamp".to_string());
                    }
                    if old_evt.source_ip.is_some() {
                        fields_removed.push("source_ip".to_string());
                    }
                    if old_evt.source_hostname.is_some() {
                        fields_removed.push("source_hostname".to_string());
                    }
                    if old_evt.dest_ip.is_some() {
                        fields_removed.push("dest_ip".to_string());
                    }
                    if old_evt.dest_hostname.is_some() {
                        fields_removed.push("dest_hostname".to_string());
                    }
                    if old_evt.severity.is_some() {
                        fields_removed.push("severity".to_string());
                    }
                    if old_evt.message.is_some() {
                        fields_removed.push("message".to_string());
                    }
                    if old_evt.action.is_some() {
                        fields_removed.push("action".to_string());
                    }
                    for k in old_evt.unmapped.keys() {
                        fields_removed.push(format!("unmapped.{}", k));
                    }
                    for a in &old_evt.abstentions {
                        abstentions_removed.push(format!("{:?}", a));
                    }
                }
            } else if let Some(new_evt) = &n.canonical_event {
                // Old is missing
                if new_evt.timestamp.is_some() {
                    fields_added.push("timestamp".to_string());
                }
                if new_evt.source_ip.is_some() {
                    fields_added.push("source_ip".to_string());
                }
                if new_evt.source_hostname.is_some() {
                    fields_added.push("source_hostname".to_string());
                }
                if new_evt.dest_ip.is_some() {
                    fields_added.push("dest_ip".to_string());
                }
                if new_evt.dest_hostname.is_some() {
                    fields_added.push("dest_hostname".to_string());
                }
                if new_evt.severity.is_some() {
                    fields_added.push("severity".to_string());
                }
                if new_evt.message.is_some() {
                    fields_added.push("message".to_string());
                }
                if new_evt.action.is_some() {
                    fields_added.push("action".to_string());
                }
                for k in new_evt.unmapped.keys() {
                    fields_added.push(format!("unmapped.{}", k));
                }
                for a in &new_evt.abstentions {
                    abstentions_added.push(format!("{:?}", a));
                }
            }

            fields_added.sort();
            fields_removed.sort();
            fields_changed.sort_by(|a, b| a.0.cmp(&b.0));
            abstentions_added.sort();
            abstentions_removed.sort();

            frame_diffs.push(FrameDiff {
                frame_index: i,
                parser_changed,
                inference_changed,
                fields_added,
                fields_removed,
                fields_changed,
                abstentions_added,
                abstentions_removed,
            });
        }

        Self {
            framer_changed,
            mapper_changed,
            inference_detectors_changed,
            parser_registry_changed,
            frame_structure,
            frame_diffs,
        }
    }
}
