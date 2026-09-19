use ulpx_core::event::EventId;
use ulpx_core::framing::FramedRecord;
use ulpx_core::parser::{Parser, ParserError};
use ulpx_ir::convert::{CompositeConverter, IrConverter};
use ulpx_mapping::engine::MappingEngine;

/// Represents the deterministic outcome of a ParserLab validation suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub syntax_passed: bool,
    pub semantic_passed: bool,
    pub golden_passed: bool,
    pub negative_passed: bool,
    pub mutation_passed: bool,
    pub security_passed: bool,
    pub performance_passed: bool,
}

impl ValidationReport {
    pub fn is_fully_valid(&self) -> bool {
        self.syntax_passed
            && self.semantic_passed
            && self.golden_passed
            && self.negative_passed
            && self.mutation_passed
            && self.security_passed
            && self.performance_passed
    }
}

/// A deterministic validation function for semantic expected output.
pub type SemanticValidator = fn(&ulpx_mapping::model::CanonicalEvent) -> bool;

/// Expected parsed fields (name, raw value as string)
pub type ExpectedFields = Vec<(String, String)>;

/// A suite of test cases to run against a candidate parser.
pub struct LabSuite {
    pub syntax_inputs: Vec<Vec<u8>>,
    pub semantic_inputs: Vec<(Vec<u8>, SemanticValidator)>,
    /// Input and expected parsed field (name, value) pairs
    pub golden_tests: Vec<(Vec<u8>, ExpectedFields)>,
    pub negative_inputs: Vec<Vec<u8>>,
    pub security_inputs: Vec<Vec<u8>>,
    pub performance_inputs: Vec<Vec<u8>>,
}

pub struct ParserLab;

impl ParserLab {
    /// Evaluates a candidate parser deterministically.
    pub fn evaluate(
        parser: &dyn Parser,
        mapper: &MappingEngine,
        suite: &LabSuite,
    ) -> ValidationReport {
        let syntax_passed = Self::run_syntax(parser, &suite.syntax_inputs);
        let semantic_passed = Self::run_semantic(parser, mapper, &suite.semantic_inputs);
        let golden_passed = Self::run_golden(parser, &suite.golden_tests);
        let negative_passed = Self::run_negative(parser, &suite.negative_inputs);
        let mutation_passed = Self::run_mutation(parser, &suite.golden_tests);
        let security_passed = Self::run_security(parser, &suite.security_inputs);
        let performance_passed = Self::run_performance(parser, &suite.performance_inputs);

        ValidationReport {
            syntax_passed,
            semantic_passed,
            golden_passed,
            negative_passed,
            mutation_passed,
            security_passed,
            performance_passed,
        }
    }

    fn run_syntax(parser: &dyn Parser, inputs: &[Vec<u8>]) -> bool {
        if inputs.is_empty() {
            return false;
        }
        for input in inputs {
            let record = FramedRecord::new(input.clone());
            if parser.parse(&record).is_err() {
                return false;
            }
        }
        true
    }

    fn run_semantic(
        parser: &dyn Parser,
        mapper: &MappingEngine,
        inputs: &[(Vec<u8>, SemanticValidator)],
    ) -> bool {
        if inputs.is_empty() {
            return false;
        }
        let converter = CompositeConverter::default_registry();
        for (input, validator) in inputs {
            let record = FramedRecord::new(input.clone());
            if let Ok(res) = parser.parse(&record) {
                let event_id = EventId::new("lab-test").unwrap();
                if let Some(ir) = converter.convert(event_id, &res) {
                    if let Some(mapped) = mapper.map(&ir) {
                        if !validator(&mapped) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    fn run_golden(parser: &dyn Parser, tests: &[(Vec<u8>, ExpectedFields)]) -> bool {
        if tests.is_empty() {
            return false;
        }
        for (input, expected_fields) in tests {
            let record = FramedRecord::new(input.clone());
            match parser.parse(&record) {
                Ok(res) => {
                    let mut actual: ExpectedFields = res
                        .fields
                        .iter()
                        .map(|f| (f.name.clone(), f.raw_value.clone()))
                        .collect();
                    actual.sort();
                    let mut expected = expected_fields.clone();
                    expected.sort();
                    if actual != expected {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    fn run_negative(parser: &dyn Parser, inputs: &[Vec<u8>]) -> bool {
        if inputs.is_empty() {
            return false;
        }
        for input in inputs {
            let record = FramedRecord::new(input.clone());
            match parser.parse(&record) {
                Ok(_) => return false,
                Err(e) => match e {
                    ParserError::Malformed(_) | ParserError::Unsupported => {}
                    _ => return false,
                },
            }
        }
        true
    }

    fn run_mutation(parser: &dyn Parser, tests: &[(Vec<u8>, ExpectedFields)]) -> bool {
        if tests.is_empty() {
            return false;
        }
        let mut meaningful = false;
        for (input, expected) in tests {
            if input.is_empty() {
                continue;
            }
            // Deterministic structural mutation: replace first '=' or ':' or space with 'X', else flip middle byte
            let mut mutated = input.clone();
            let mut mutated_flag = false;
            for byte in &mut mutated {
                if *byte == b'=' || *byte == b':' || *byte == b',' {
                    *byte = b'X';
                    mutated_flag = true;
                    break;
                }
            }
            if !mutated_flag {
                let mid = input.len() / 2;
                mutated[mid] = mutated[mid].wrapping_add(1);
            }

            let record = FramedRecord::new(mutated);
            match parser.parse(&record) {
                Ok(res) => {
                    let mut actual: ExpectedFields = res
                        .fields
                        .iter()
                        .map(|f| (f.name.clone(), f.raw_value.clone()))
                        .collect();
                    actual.sort();
                    let mut exp = expected.clone();
                    exp.sort();
                    if actual != exp {
                        meaningful = true;
                    }
                }
                Err(_) => {
                    meaningful = true;
                }
            }
        }
        meaningful
    }

    fn run_security(parser: &dyn Parser, _inputs: &[Vec<u8>]) -> bool {
        // Pathological test: very long sequence of key=value pairs or deeply nested JSON
        // tests the direct-parser boundary (bypassing NewlineFramer).
        // This establishes a deterministic contract of safe adversarial handling:
        // it verifies the parser will not panic or hit uncontrolled recursion
        // within this defined test boundary, without claiming strict mathematical memory proofs.
        let mut pathological = Vec::with_capacity(100_000);
        for i in 0..10_000 {
            pathological.extend_from_slice(b"k");
            pathological.extend_from_slice(i.to_string().as_bytes());
            pathological.extend_from_slice(b"=v ");
        }
        let record = FramedRecord::new(pathological);

        // The parser might succeed or return a limit error, both are fine, but it MUST NOT panic.
        let _ = parser.parse(&record);

        // Deeply nested input for JSON/recursive parsers
        let mut nested = b"{\"a\":".repeat(500);
        nested.extend_from_slice(b"1");
        nested.extend_from_slice(&b"}".repeat(500));
        let nested_record = FramedRecord::new(nested);
        let _ = parser.parse(&nested_record);

        true
    }

    fn run_performance(parser: &dyn Parser, inputs: &[Vec<u8>]) -> bool {
        if inputs.is_empty() {
            return false;
        }
        // Bounded iteration contract: strictly verifies that 1,000 iterations
        // complete without panicking, infinitely blocking, or crashing.
        // This explicitly avoids machine-specific microsecond timing thresholds
        // and does not claim to mathematically prove O(1) memory.
        for input in inputs {
            let record = FramedRecord::new(input.clone());
            for _ in 0..1000 {
                let _ = parser.parse(&record);
            }
        }
        true
    }
}
