pub mod cef;
pub mod json;
pub mod syslog;

use crate::model::AbstentionReason;
use ulpx_ir::model::IrValue;

/// Helper to coerce an IrValue to a String losslessly.
/// Returns InsufficientEvidence if the value is purely empty/null.
pub fn as_string(val: &IrValue) -> Result<String, AbstentionReason> {
    match val {
        IrValue::String(s) => {
            if s.trim().is_empty() {
                Err(AbstentionReason::InsufficientEvidence)
            } else {
                Ok(s.clone())
            }
        }
        IrValue::Integer(i) => Ok(i.to_string()),
        IrValue::Float(f) => Ok(f.to_string()),
        IrValue::Boolean(b) => Ok(b.to_string()),
        IrValue::Null => Err(AbstentionReason::InsufficientEvidence),
    }
}
