use crate::model::{
    AbstentionReason, AbstentionRecord, CanonicalField, Confidence, FieldProvenance,
};
use std::collections::BTreeMap;
use ulpx_ir::model::{EventIr, IrValue};

/// A context for safely building a Semantic Mapping without field loss.
pub struct MappingContext<'a> {
    ir: &'a EventIr,
    /// Unmapped fields. Initialized to all IR fields, depleted as fields are mapped.
    pub unmapped: BTreeMap<String, IrValue>,
    /// Audit log of mapping decisions that were declined.
    pub abstentions: Vec<AbstentionRecord>,
}

impl<'a> MappingContext<'a> {
    pub fn new(ir: &'a EventIr) -> Self {
        Self {
            ir,
            unmapped: ir.fields.clone(),
            abstentions: Vec::new(),
        }
    }

    /// Access the underlying EventIr for read-only checks.
    pub fn ir(&self) -> &EventIr {
        self.ir
    }

    /// Attempts to extract and map a canonical field from one or more source fields.
    ///
    /// If multiple source fields exist, it ABSTAINS to prevent silent overriding.
    /// If a field is successfully mapped, it is removed from `unmapped`.
    pub fn extract<T, F>(
        &mut self,
        target_name: &str,
        source_names: &[&str],
        rule_id: &str,
        confidence: Confidence,
        transform: F,
    ) -> Option<CanonicalField<T>>
    where
        F: FnOnce(&IrValue, &mut Vec<String>) -> Result<T, AbstentionReason>,
    {
        let mut found = Vec::new();
        for &src in source_names {
            if let Some(val) = self.unmapped.get(src) {
                found.push((src, val.clone()));
            }
        }

        if found.is_empty() {
            return None; // Value strictly absent.
        }

        if found.len() > 1 {
            // Ambiguity: Multiple fields matched the extraction rule.
            self.abstentions.push(AbstentionRecord {
                canonical_target: target_name.to_string(),
                involved_source_fields: found.iter().map(|(k, _)| k.to_string()).collect(),
                rule_id: rule_id.to_string(),
                reason: AbstentionReason::Ambiguous,
            });
            return None;
        }

        let (src_name, val) = &found[0];
        let mut transformations = Vec::new();

        match transform(val, &mut transformations) {
            Ok(mapped_val) => {
                // Mapping successful. Consume the field so it doesn't stay in unmapped.
                let span = val.span;
                self.unmapped.remove(*src_name);

                Some(CanonicalField {
                    value: mapped_val,
                    provenance: FieldProvenance {
                        source_field: src_name.to_string(),
                        span,
                        transformations,
                        rule_id: rule_id.to_string(),
                        confidence,
                        parser_id: self.ir.parser_id.clone(),
                        parser_version: self.ir.parser_version,
                    },
                })
            }
            Err(reason) => {
                // Transform explicitly declined.
                self.abstentions.push(AbstentionRecord {
                    canonical_target: target_name.to_string(),
                    involved_source_fields: vec![src_name.to_string()],
                    rule_id: rule_id.to_string(),
                    reason,
                });
                None
            }
        }
    }
}
