use crate::model::CanonicalEvent;
use ulpx_ir::model::EventIr;

/// Trait for transforming an EventIr into a CanonicalEvent.
pub trait SemanticMapper {
    /// Attempt to map the IR into a canonical event.
    /// Returns None if the mapper does not support the originating parser.
    fn map(&self, ir: &EventIr) -> Option<CanonicalEvent>;
}

/// A registry that attempts multiple semantic mappers in sequence.
pub struct MappingEngine {
    mappers: Vec<Box<dyn SemanticMapper + Send + Sync>>,
}

impl Default for MappingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MappingEngine {
    pub fn new() -> Self {
        Self {
            mappers: Vec::new(),
        }
    }

    pub fn register<M: SemanticMapper + Send + Sync + 'static>(&mut self, mapper: M) {
        self.mappers.push(Box::new(mapper));
    }

    pub fn default_registry() -> Self {
        let mut engine = Self::new();
        engine.register(crate::mappers::syslog::SyslogMapper);
        engine.register(crate::mappers::cef::CefMapper);
        engine.register(crate::mappers::json::JsonHeuristicMapper);
        engine
    }

    pub fn map(&self, ir: &EventIr) -> Option<CanonicalEvent> {
        for mapper in &self.mappers {
            if let Some(canonical) = mapper.map(ir) {
                return Some(canonical);
            }
        }
        None
    }
}
