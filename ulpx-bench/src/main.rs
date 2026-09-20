use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use ulpx_core::event::EventId;
use ulpx_core::framing::{FrameError, Framer, newline::NewlineFramer};
use ulpx_core::parser::cef::CefParser;
use ulpx_core::parser::json::JsonParser;
use ulpx_core::parser::syslog::SyslogParser;
use ulpx_core::parser::{LifecycleStage, ParserRegistry};

use ulpx_infer::engine::InferenceEngine;
use ulpx_infer::evidence::{
    detect_cef, detect_generic_csv, detect_generic_kv, detect_json, detect_syslog,
};
use ulpx_infer::model::{InferenceConfidence, InferenceOutcome};

use ulpx_ir::convert::{
    CefConverter, CompositeConverter, FallbackConverter, IrConverter, JsonConverter,
    SyslogConverter,
};
use ulpx_ir::model::IrType;
use ulpx_mapping::engine::MappingEngine;
use ulpx_mapping::mappers::cef::CefMapper;
use ulpx_mapping::mappers::json::JsonHeuristicMapper;
use ulpx_mapping::mappers::syslog::SyslogMapper;

use ulpx_onboard::generator::ParserGenerator;
use ulpx_onboard::inference::derive_spec_from_inference;

#[cfg(windows)]
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::GetCurrentProcess;

// ─────────────────────────────────────────────
// Data model
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
enum Category {
    Known,
    Unknown,
    Malformed,
    Adversarial,
    UnseenVendor,
}

/// A single benchmark fixture loaded from JSON.
///
/// `expected_frame_hex` stores the expected frame bytes as hex strings
/// for byte-exact comparison (lossless for non-UTF8 payloads).
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Fixture {
    name: String,
    category: Category,
    payload: String,
    expected_parser: Option<String>,
    expect_abstain: bool,
    expected_inference: Option<String>,
    expected_extracted: HashMap<String, String>,
    expected_mapped: HashMap<String, String>,
    expected_frame_count: Option<usize>,
    expected_frame_hex: Option<Vec<String>>,
    expected_oversized: Option<bool>,
}

#[derive(Default, Serialize)]
struct Metrics {
    total_cases: usize,

    // Accuracy
    framing_correct: usize,
    format_detection_correct: usize,
    field_extraction_correct: usize,
    semantic_mapping_correct: usize,

    // Stats
    correct_abstentions: usize,
    false_attributions: usize,
    onboarding_successes: usize,

    // Confidence-Stratified Accuracy
    // NOTE: ULPX exposes only categorical confidence (High/Medium/Low).
    // These metrics report accuracy stratified by confidence level, NOT
    // true probabilistic calibration. See README for details.
    high_conf_total: usize,
    high_conf_correct: usize,
    medium_conf_total: usize,
    medium_conf_correct: usize,
    low_conf_total: usize,
    low_conf_correct: usize,

    // Performance — Micro = Framer+Parse/Infer, E2E = full pipeline
    p50_e2e_us: u128,
    p95_e2e_us: u128,
    p99_e2e_us: u128,
    p50_micro_us: u128,
    p95_micro_us: u128,
    p99_micro_us: u128,
    throughput_bytes_per_us: f64,
    peak_memory_mb: f64,
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

fn get_memory_usage() -> usize {
    #[cfg(windows)]
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) != 0
        {
            return counters.PeakWorkingSetSize;
        }
    }
    0
}

fn initialize_pipeline() -> (
    NewlineFramer,
    InferenceEngine,
    ParserRegistry,
    CompositeConverter,
    MappingEngine,
) {
    let framer = NewlineFramer;

    let mut infer = InferenceEngine::new();
    infer.add_detector("syslog", detect_syslog);
    infer.add_detector("json", detect_json);
    infer.add_detector("cef", detect_cef);
    infer.add_detector("generic-kv", detect_generic_kv);
    infer.add_detector("generic-csv", detect_generic_csv);

    let mut current_registry = ParserRegistry::new();
    current_registry
        .register(Box::new(CefParser::new()), LifecycleStage::Deployed)
        .unwrap();
    current_registry
        .register(Box::new(JsonParser::new()), LifecycleStage::Deployed)
        .unwrap();
    current_registry
        .register(Box::new(SyslogParser::new()), LifecycleStage::Deployed)
        .unwrap();

    let mut ir_converter = CompositeConverter::new();
    ir_converter.add(SyslogConverter);
    ir_converter.add(JsonConverter);
    ir_converter.add(CefConverter);
    ir_converter.add(FallbackConverter);

    let mut mapping_engine = MappingEngine::new();
    mapping_engine.register(SyslogMapper);
    mapping_engine.register(JsonHeuristicMapper);
    mapping_engine.register(CefMapper);

    (
        framer,
        infer,
        current_registry,
        ir_converter,
        mapping_engine,
    )
}

fn expand_payload(payload: &str) -> Vec<u8> {
    if payload == "[GENERATE_OVERSIZED]" {
        // Exceed the 64 MiB MAX_FRAME_BYTES limit
        return vec![b'A'; 65 * 1024 * 1024];
    }
    payload.as_bytes().to_vec()
}

/// Run the full-pipeline processing used by both the correctness and E2E
/// timing loop: framer -> parser attempt -> inference fallback -> onboarding
/// (for unseen-vendor) -> IR -> semantic mapping.
fn run_full_pipeline(
    fix: &Fixture,
    payload_bytes: &[u8],
    framer: &NewlineFramer,
    current_registry: &ParserRegistry,
    infer: &InferenceEngine,
    ir_converter: &CompositeConverter,
    mapping_engine: &MappingEngine,
) {
    let (records, _) = framer.frame_all(payload_bytes);
    if records.is_empty() {
        return;
    }
    let record = &records[0];
    let mut final_res = None;
    if let Ok(res) = current_registry.parse_first(record) {
        final_res = Some(res);
    } else {
        let infer_res = infer.infer(record, None);
        if let InferenceOutcome::Recognized { .. } = &infer_res.outcome
            && fix.category == Category::UnseenVendor
            && let Ok(spec) = derive_spec_from_inference(&infer_res)
            && let Ok(new_parser) = ParserGenerator::build(spec)
            && let Ok(res2) = new_parser.parse(record)
        {
            final_res = Some(res2);
        }
    }
    if let Some(res) = final_res {
        let event_id = EventId::new("e2e-bench".to_string()).unwrap();
        if let Some(ir) = ir_converter.convert(event_id, &res) {
            let _ = mapping_engine.map(&ir);
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─────────────────────────────────────────────
// Main benchmark runner
// ─────────────────────────────────────────────

fn run_bench(fixtures: &[Fixture], bench_iterations: usize) -> (bool, Metrics) {
    let mut m = Metrics::default();
    let (framer, infer, current_registry, ir_converter, mapping_engine) = initialize_pipeline();

    let mut all_correct = true;
    let mut total_bytes: usize = 0;

    for fix in fixtures {
        m.total_cases += 1;
        let payload_bytes = expand_payload(&fix.payload);

        // Only count bytes for fixtures included in the micro-benchmark loop.
        if fix.expected_oversized != Some(true) {
            total_bytes += payload_bytes.len();
        }

        let mut case_correct = true;

        // ── 1. Framing ──
        let (records, err) = framer.frame_all(&payload_bytes);

        let mut framing_ok = true;

        // Check oversized error
        if fix.expected_oversized == Some(true)
            && !matches!(err, Some(FrameError::OversizedFrame(_)))
        {
            println!(
                "[-] {}: Expected OversizedFrame error but got {:?}",
                fix.name, err
            );
            framing_ok = false;
        }

        // Check frame count
        if let Some(expected_count) = fix.expected_frame_count
            && records.len() != expected_count
        {
            println!(
                "[-] {}: Expected {} frames, got {}",
                fix.name,
                expected_count,
                records.len()
            );
            framing_ok = false;
        }

        // Byte-exact frame content verification via hex encoding
        if let Some(expected_hexes) = &fix.expected_frame_hex {
            if records.len() != expected_hexes.len() {
                println!(
                    "[-] {}: Expected {} frame hex entries, but found {} frames",
                    fix.name,
                    expected_hexes.len(),
                    records.len()
                );
                framing_ok = false;
            } else {
                for (i, (record, expected_hex)) in
                    records.iter().zip(expected_hexes.iter()).enumerate()
                {
                    let actual_hex = hex_encode(record.as_bytes());
                    if actual_hex != *expected_hex {
                        println!(
                            "[-] {}: Frame {} byte mismatch. Expected hex: {}, Got hex: {}",
                            fix.name, i, expected_hex, actual_hex
                        );
                        framing_ok = false;
                    }
                }
            }
        }

        if framing_ok {
            m.framing_correct += 1;
        } else {
            case_correct = false;
        }

        let record = records
            .first()
            .unwrap_or(&ulpx_core::framing::FramedRecord::new(Vec::new()))
            .clone();

        // Stop pipeline for oversized framing-rejection tests
        if fix.expected_oversized == Some(true) {
            if case_correct {
                println!("[+] {}: OK (Oversized)", fix.name);
            } else {
                all_correct = false;
            }
            continue;
        }

        // ── 2. Parse / Infer / Onboard ──
        let mut final_parser_id = None;
        let mut parsed_result = None;
        let mut confidence = None;
        let mut onboarded = false;

        let parse_res = current_registry.parse_first(&record);
        match parse_res {
            Ok(res) => {
                final_parser_id = Some(res.parser_id.clone());
                parsed_result = Some(res);
                confidence = Some(InferenceConfidence::High);
            }
            Err(_) => {
                let infer_res = infer.infer(&record, None);
                match infer_res.outcome {
                    InferenceOutcome::Recognized { ref candidate, .. } => {
                        if fix.category == Category::UnseenVendor {
                            if let Ok(spec) = derive_spec_from_inference(&infer_res)
                                && let Ok(new_parser) = ParserGenerator::build(spec)
                                && let Ok(res2) = new_parser.parse(&record)
                            {
                                final_parser_id = Some(res2.parser_id.clone());
                                parsed_result = Some(res2);
                                onboarded = true;
                                confidence = Some(candidate.confidence);
                            }
                        } else {
                            final_parser_id = Some(candidate.parser_id.clone());
                            confidence = Some(candidate.confidence);
                        }
                    }
                    InferenceOutcome::Abstained { .. } => {
                        if fix.expect_abstain {
                            m.correct_abstentions += 1;
                        } else {
                            case_correct = false;
                            println!("[-] {}: Incorrect abstention", fix.name);
                        }
                    }
                }
            }
        }

        // ── 3. Format Detection Validation ──
        if let Some(expected) = &fix.expected_parser {
            if let Some(actual) = &final_parser_id {
                if expected == actual {
                    m.format_detection_correct += 1;
                } else {
                    println!(
                        "[-] {}: Expected parser {}, got {}",
                        fix.name, expected, actual
                    );
                    if fix.category != Category::UnseenVendor {
                        m.false_attributions += 1;
                    }
                    case_correct = false;
                }
            } else {
                println!("[-] {}: Expected parser {}, got None", fix.name, expected);
                case_correct = false;
            }
        } else if !fix.expect_abstain {
            if let Some(actual) = &final_parser_id {
                if fix.expected_inference.as_deref() == Some(actual.as_str()) {
                    m.format_detection_correct += 1;
                } else {
                    println!(
                        "[-] {}: Expected inference {:?}, got Some({})",
                        fix.name, fix.expected_inference, actual
                    );
                    case_correct = false;
                }
            } else {
                println!(
                    "[-] {}: Expected inference {:?}, got None",
                    fix.name, fix.expected_inference
                );
                case_correct = false;
            }
        }

        // ── Confidence-stratified accuracy ──
        if let Some(c) = confidence {
            match c {
                InferenceConfidence::High => {
                    m.high_conf_total += 1;
                    if case_correct {
                        m.high_conf_correct += 1;
                    }
                }
                InferenceConfidence::Medium => {
                    m.medium_conf_total += 1;
                    if case_correct {
                        m.medium_conf_correct += 1;
                    }
                }
                InferenceConfidence::Low => {
                    m.low_conf_total += 1;
                    if case_correct {
                        m.low_conf_correct += 1;
                    }
                }
            }
        }

        if fix.category == Category::UnseenVendor && onboarded && case_correct {
            m.onboarding_successes += 1;
        }

        // ── 4. Field Extraction (exact set comparison) ──
        if let Some(res) = parsed_result {
            let event_id = EventId::new(format!("bench-{}", m.total_cases)).unwrap();
            if let Some(ir) = ir_converter.convert(event_id.clone(), &res) {
                let mut extraction_ok = true;

                // Check all expected fields are present with correct values
                for (k, expected_v) in &fix.expected_extracted {
                    if let Some(actual_ir_val) = ir.fields.get(k) {
                        let actual_str = match &actual_ir_val.ty {
                            IrType::String(s) => s.clone(),
                            IrType::Integer(i) => i.to_string(),
                            _ => String::new(),
                        };
                        if &actual_str != expected_v {
                            println!(
                                "[-] {}: Extracted field '{}' mismatch. Expected '{}', got '{}'",
                                fix.name, k, expected_v, actual_str
                            );
                            extraction_ok = false;
                        }
                    } else {
                        println!("[-] {}: Extracted field '{}' missing", fix.name, k);
                        extraction_ok = false;
                    }
                }

                // Check that no unexpected fields were extracted
                let actual_field_count = ir.fields.len();
                let expected_field_count = fix.expected_extracted.len();
                if actual_field_count != expected_field_count {
                    let actual_keys: Vec<_> = ir.fields.keys().collect();
                    println!(
                        "[-] {}: Extracted field count mismatch. Expected {}, got {}. Actual keys: {:?}",
                        fix.name, expected_field_count, actual_field_count, actual_keys
                    );
                    extraction_ok = false;
                }

                if extraction_ok && !fix.expected_extracted.is_empty() {
                    m.field_extraction_correct += 1;
                } else if !extraction_ok {
                    case_correct = false;
                }

                // ── 5. Semantic Mapping (exact set comparison) ──
                let mapped_opt = mapping_engine.map(&ir);
                let mut mapping_ok = true;
                if let Some(mapped) = mapped_opt {
                    for (k, expected_v) in &fix.expected_mapped {
                        let actual_val = match k.as_str() {
                            "source_ip" => mapped.source_ip.as_ref().map(|f| f.value.clone()),
                            "dest_ip" => mapped.dest_ip.as_ref().map(|f| f.value.clone()),
                            "source_hostname" => {
                                mapped.source_hostname.as_ref().map(|f| f.value.clone())
                            }
                            "dest_hostname" => {
                                mapped.dest_hostname.as_ref().map(|f| f.value.clone())
                            }
                            "timestamp" => mapped.timestamp.as_ref().map(|f| f.value.clone()),
                            "message" => mapped.message.as_ref().map(|f| f.value.clone()),
                            "severity" => {
                                mapped.severity.as_ref().map(|f| format!("{:?}", f.value))
                            }
                            "action" => mapped.action.as_ref().map(|f| f.value.clone()),
                            _ => None,
                        };

                        if let Some(av) = actual_val {
                            if &av != expected_v {
                                println!(
                                    "[-] {}: Mapped field '{}' mismatch. Expected '{}', got '{}'",
                                    fix.name, k, expected_v, av
                                );
                                mapping_ok = false;
                            }
                        } else {
                            println!("[-] {}: Mapped field '{}' missing", fix.name, k);
                            mapping_ok = false;
                        }
                    }

                    // Check for unexpected mapped fields
                    let actual_mapped_count = [
                        &mapped.source_ip,
                        &mapped.dest_ip,
                        &mapped.source_hostname,
                        &mapped.dest_hostname,
                        &mapped.message,
                        &mapped.action,
                    ]
                    .iter()
                    .filter(|o| o.is_some())
                    .count()
                        + if mapped.severity.is_some() { 1 } else { 0 }
                        + if mapped.timestamp.is_some() { 1 } else { 0 };

                    let expected_mapped_count = fix.expected_mapped.len();
                    if actual_mapped_count != expected_mapped_count {
                        let mut present = Vec::new();
                        if mapped.source_ip.is_some() {
                            present.push("source_ip");
                        }
                        if mapped.dest_ip.is_some() {
                            present.push("dest_ip");
                        }
                        if mapped.source_hostname.is_some() {
                            present.push("source_hostname");
                        }
                        if mapped.dest_hostname.is_some() {
                            present.push("dest_hostname");
                        }
                        if mapped.message.is_some() {
                            present.push("message");
                        }
                        if mapped.action.is_some() {
                            present.push("action");
                        }
                        if mapped.severity.is_some() {
                            present.push("severity");
                        }
                        if mapped.timestamp.is_some() {
                            present.push("timestamp");
                        }

                        println!(
                            "[-] {}: Mapped field count mismatch. Expected {}, got {}. Present: {:?}",
                            fix.name, expected_mapped_count, actual_mapped_count, present
                        );
                        mapping_ok = false;
                    }
                } else if !fix.expected_mapped.is_empty() {
                    println!("[-] {}: Mapped event is None", fix.name);
                    mapping_ok = false;
                }

                if mapping_ok && !fix.expected_mapped.is_empty() {
                    m.semantic_mapping_correct += 1;
                } else if !mapping_ok {
                    case_correct = false;
                }
            } else {
                println!("[-] {}: IR conversion failed", fix.name);
                case_correct = false;
            }
        }

        if !case_correct {
            all_correct = false;
            println!("[-] {} FAILED", fix.name);
        } else {
            println!("[+] {}: OK", fix.name);
        }
    }

    // ── Performance measurement ──
    if bench_iterations > 0 {
        // Micro: Framer -> Parse/Infer ONLY (no IR, no mapping)
        let mut micro_latencies = Vec::with_capacity(bench_iterations * fixtures.len());
        let micro_start = Instant::now();
        for _ in 0..bench_iterations {
            for fix in fixtures {
                if fix.expected_oversized == Some(true) {
                    continue;
                }
                let payload_bytes = expand_payload(&fix.payload);
                let start = Instant::now();
                let (records, _) = framer.frame_all(&payload_bytes);
                if !records.is_empty() {
                    let record = &records[0];
                    if current_registry.parse_first(record).is_err() {
                        let _ = infer.infer(record, None);
                    }
                }
                micro_latencies.push(start.elapsed());
            }
        }
        let total_micro = micro_start.elapsed();

        // E2E: full pipeline (same path as correctness loop)
        let mut e2e_latencies = Vec::with_capacity(bench_iterations * fixtures.len());
        for _ in 0..bench_iterations {
            for fix in fixtures {
                if fix.expected_oversized == Some(true) {
                    continue;
                }
                let payload_bytes = expand_payload(&fix.payload);
                let start = Instant::now();
                run_full_pipeline(
                    fix,
                    &payload_bytes,
                    &framer,
                    &current_registry,
                    &infer,
                    &ir_converter,
                    &mapping_engine,
                );
                e2e_latencies.push(start.elapsed());
            }
        }

        micro_latencies.sort();
        e2e_latencies.sort();
        let n_m = micro_latencies.len();
        let n_e = e2e_latencies.len();

        if n_m > 0 {
            m.p50_micro_us = micro_latencies[n_m / 2].as_micros();
            m.p95_micro_us = micro_latencies[n_m * 95 / 100].as_micros();
            m.p99_micro_us = micro_latencies[n_m * 99 / 100].as_micros();

            m.p50_e2e_us = e2e_latencies[n_e / 2].as_micros();
            m.p95_e2e_us = e2e_latencies[n_e * 95 / 100].as_micros();
            m.p99_e2e_us = e2e_latencies[n_e * 99 / 100].as_micros();

            // throughput = total bytes actually timed / total micro wall-clock
            m.throughput_bytes_per_us =
                (total_bytes * bench_iterations) as f64 / total_micro.as_micros() as f64;
        }
    }

    m.peak_memory_mb = get_memory_usage() as f64 / 1024.0 / 1024.0;
    (all_correct, m)
}

// ─────────────────────────────────────────────
// main
// ─────────────────────────────────────────────

fn main() {
    let mut fixtures = Vec::new();
    let bench_dir = if Path::new("benchmarks").exists() {
        "benchmarks"
    } else {
        "ulpx-bench/benchmarks"
    };
    for entry in WalkDir::new(bench_dir) {
        let e = entry.unwrap();
        if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
            let mut data = fs::read_to_string(e.path()).unwrap();
            data = data.trim_start_matches('\u{FEFF}').to_string();
            let fix: Fixture = serde_json::from_str(&data).unwrap();
            fixtures.push(fix);
        }
    }

    println!("Starting ULPX Benchmarks...");
    println!("Loaded {} fixtures.", fixtures.len());

    let (all_correct, m) = run_bench(&fixtures, 1000);

    let json_result = serde_json::to_string_pretty(&m).unwrap();
    fs::write("benchmark_results.json", json_result).unwrap();

    let expected_extr = fixtures
        .iter()
        .filter(|f| !f.expected_extracted.is_empty())
        .count();
    let expected_map = fixtures
        .iter()
        .filter(|f| !f.expected_mapped.is_empty())
        .count();
    let expected_det = fixtures
        .iter()
        .filter(|f| !f.expect_abstain && f.expected_oversized != Some(true))
        .count();

    println!("\n--- Correctness ---");
    println!("Total Cases:             {}", m.total_cases);
    println!(
        "Framing Accuracy:        {}/{}",
        m.framing_correct, m.total_cases
    );
    println!(
        "Format Det Accuracy:     {}/{}",
        m.format_detection_correct, expected_det
    );
    println!(
        "Field Extr Accuracy:     {}/{}",
        m.field_extraction_correct, expected_extr
    );
    println!(
        "Semantic Map Accuracy:   {}/{}",
        m.semantic_mapping_correct, expected_map
    );
    println!("Correct Abstentions:     {}", m.correct_abstentions);
    println!("False Attributions:      {}", m.false_attributions);
    println!("Onboarding Successes:    {}", m.onboarding_successes);

    println!("\n--- Confidence-Stratified Accuracy (NOT calibration) ---");
    println!(
        "High-Conf Accuracy:      {}/{}",
        m.high_conf_correct, m.high_conf_total
    );
    println!(
        "Med-Conf Accuracy:       {}/{}",
        m.medium_conf_correct, m.medium_conf_total
    );
    println!(
        "Low-Conf Accuracy:       {}/{}",
        m.low_conf_correct, m.low_conf_total
    );

    println!("\n--- Performance (local macro-benchmark, NOT production claims) ---");
    println!("Micro p50 Latency:       {} us", m.p50_micro_us);
    println!("Micro p95 Latency:       {} us", m.p95_micro_us);
    println!("Micro p99 Latency:       {} us", m.p99_micro_us);
    println!("E2E p50 Latency:         {} us", m.p50_e2e_us);
    println!("E2E p95 Latency:         {} us", m.p95_e2e_us);
    println!("E2E p99 Latency:         {} us", m.p99_e2e_us);
    println!(
        "Throughput (micro):      {:.2} Bytes/us",
        m.throughput_bytes_per_us
    );
    println!("Peak Memory (Working):   {:.2} MB", m.peak_memory_mb);

    if !all_correct {
        std::process::exit(1);
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fixture(payload: &str, parser: Option<&str>) -> Fixture {
        // Compute expected hex from payload, stripping trailing newline (framer strips it)
        let content = payload.trim_end_matches('\n').as_bytes();
        let mut expected_extracted = HashMap::new();
        let mut expected_mapped = HashMap::new();
        if payload.contains("src_ip") {
            expected_extracted.insert("src_ip".into(), "1.1.1.1".into());
            expected_mapped.insert("source_ip".into(), "1.1.1.1".into());
        }
        Fixture {
            name: "Test".into(),
            category: Category::Known,
            payload: payload.into(),
            expected_parser: parser.map(String::from),
            expect_abstain: false,
            expected_inference: None,
            expected_extracted,
            expected_mapped,
            expected_frame_count: Some(1),
            expected_frame_hex: Some(vec![hex_encode(content)]),
            expected_oversized: Some(false),
        }
    }

    #[test]
    fn test_valid_fixture_passes() {
        let fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("json-flat"));
        let (ok, _) = run_bench(&[fix], 0);
        assert!(ok, "Valid fixture should pass");
    }

    #[test]
    fn test_wrong_parser_expectation_fails() {
        let fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("cef"));
        let (ok, _) = run_bench(&[fix], 0);
        assert!(!ok, "Wrong parser expectation must fail");
    }

    #[test]
    fn test_wrong_frame_hex_fails() {
        let mut fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("json-flat"));
        // Corrupt one hex byte
        fix.expected_frame_hex = Some(vec!["ff".to_string()]);
        let (ok, _) = run_bench(&[fix], 0);
        assert!(!ok, "Corrupted frame hex must fail");
    }

    #[test]
    fn test_wrong_extraction_expectation_fails() {
        let mut fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("json-flat"));
        fix.expected_extracted
            .insert("src_ip".into(), "WRONG_VALUE".into());
        let (ok, _) = run_bench(&[fix], 0);
        assert!(!ok, "Wrong extraction expectation must fail");
    }

    #[test]
    fn test_wrong_mapped_expectation_fails() {
        let mut fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("json-flat"));
        fix.expected_mapped
            .insert("source_ip".into(), "WRONG_IP".into());
        let (ok, _) = run_bench(&[fix], 0);
        assert!(!ok, "Wrong mapped expectation must fail");
    }

    #[test]
    fn test_confidence_stratified_accuracy_semantics() {
        // A Known-parser hit should be counted as High confidence
        let fix = make_fixture("{\"src_ip\":\"1.1.1.1\"}\n", Some("json-flat"));
        let (ok, m) = run_bench(&[fix], 0);
        assert!(ok);
        assert_eq!(m.high_conf_total, 1);
        assert_eq!(m.high_conf_correct, 1);
        assert_eq!(m.medium_conf_total, 0);
        assert_eq!(m.low_conf_total, 0);
    }
}
