pub mod cef;
pub mod json;
pub mod syslog;

use crate::model::AbstentionReason;
use ulpx_ir::model::{IrType, IrValue};

/// Helper to coerce an IrValue to a String losslessly.
/// Returns InsufficientEvidence if the value is purely empty/null.
pub fn as_string(
    val: &IrValue,
    transformations: &mut Vec<String>,
) -> Result<String, AbstentionReason> {
    if transformations.is_empty() {
        transformations.push("identity".to_string());
    }
    match &val.ty {
        IrType::String(s) => {
            if s.trim().is_empty() {
                Err(AbstentionReason::InsufficientEvidence)
            } else {
                Ok(s.clone())
            }
        }
        IrType::Integer(i) => Ok(i.to_string()),
        IrType::Float(f) => Ok(f.to_string()),
        IrType::Boolean(b) => Ok(b.to_string()),
        IrType::Null => Err(AbstentionReason::InsufficientEvidence),
    }
}
