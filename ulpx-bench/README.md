# ULPX Benchmarks (Phase 17)

This crate provides a deterministic, data-driven macro-benchmark suite for
evaluating the ULPX ingestion and parsing pipeline.

## Important Disclaimer

These figures represent **local offline macro-benchmarks** over a controlled
deterministic fixture corpus. They **do not constitute formal production
performance claims** for an end-to-end distributed ULPX deployment.

## Benchmark Environment

| Property | Value |
|---|---|
| Rust edition | 2024 (stable) |
| Build profile | `dev` (unoptimized + debuginfo) |
| OS | Windows (development workstation) |
| Measurement | `std::time::Instant` wall-clock |
| Memory | Windows `K32GetProcessMemoryInfo` Peak Working Set Size |

## Corpus

| Category | Count | Description |
|---|---|---|
| Known | 3 | Syslog, JSON, CEF — parsed by deployed parsers |
| Malformed | 5 | Binary, invalid JSON, truncated JSON, malformed CEF, oversized (65 MiB) |
| Adversarial | 2 | Fake syslog embedded in JSON, mixed CEF+JSON |
| Unknown | 1 | Plain text — inference correctly abstains |
| Unseen Vendor | 2 | KV and CSV — exercises inference → spec → generated parser → extraction |
| **Total** | **13** | |

### Fixture sizes

Typical single-frame payloads are 30–80 bytes. The "Oversized" payload is
dynamically expanded to 65 MiB to exercise the `MAX_FRAME_BYTES` (64 MiB)
threshold in `ulpx_core::framing::newline`. This fixture is **excluded** from
latency and throughput measurements because its purpose is to validate the
resource-limit rejection path, not measure steady-state processing speed.

## Correctness Assertions

Every fixture declares:

- **`expected_frame_count`**: exact number of frames the framer must produce.
- **`expected_frame_hex`**: hex-encoded byte sequences for byte-exact frame
  comparison (lossless even for non-UTF8 payloads like binary).
- **`expected_parser`**: the parser ID that must handle the frame.
- **`expected_extracted`**: exact field names and values that must appear in the
  IR after extraction.
- **`expected_mapped`**: exact canonical/semantic field values after mapping.
- **`expect_abstain`**: whether the inference engine should abstain.
- **`expected_oversized`**: whether the framer should produce an
  `OversizedFrame` error.

If any assertion fails, the benchmark halts with exit code `1`.

## Performance Methodology

### Warm-up and Iterations

- No explicit warm-up phase; the first of 1,000 iterations serves as implicit
  warm-up.
- All 1,000 iterations run over the same in-memory fixture corpus.
- The oversized fixture (65 MiB) is excluded from both latency arrays and the
  throughput byte numerator.

### Micro Latency (Framer + Parse/Infer)

Measures only:
`NewlineFramer::frame_all` → `ParserRegistry::parse_first` (or
`InferenceEngine::infer` on parser failure)

Does **not** include IR conversion or semantic mapping.

### E2E Latency (Full Pipeline)

Measures the complete processing path that the correctness benchmark uses:
`NewlineFramer::frame_all` → `ParserRegistry::parse_first` → (on failure)
`InferenceEngine::infer` → (for unseen-vendor) `derive_spec_from_inference` →
`ParserGenerator::build` → generated parser → `CompositeConverter::convert` →
`MappingEngine::map`

### Percentile Calculation

All per-fixture-per-iteration latencies are collected into a sorted `Vec`, and
p50/p95/p99 are selected by integer index: `latencies[n * P / 100]`.

### Throughput

`throughput_bytes_per_us = (sum of non-oversized fixture payload sizes * 1000)
/ total_micro_wall_clock_us`

The byte numerator counts **only** the payloads actually processed in the
timed micro-benchmark loop. The denominator is the wall-clock duration of
that same loop.

### Peak Memory

`K32GetProcessMemoryInfo` → `PeakWorkingSetSize`. This is the peak RAM
footprint (in bytes) that the OS allocated for the process at any point during
execution. It is an upper-bound estimate, not a steady-state measurement.

## Confidence-Stratified Accuracy

ULPX's `InferenceConfidence` is a categorical enum (`High | Medium | Low`)
without associated numerical probabilities. True probabilistic calibration
(e.g., "of all predictions labeled 80% confident, 80% are correct") is
**not implemented** because the model does not expose numerical confidence
scores.

Instead, the benchmark reports **confidence-stratified accuracy**: for each
confidence level, the fraction of cases at that level where the overall
correctness assertions passed. This is informative but is **not** the same as
calibration in the statistical sense.

## Unseen-Vendor Methodology

The `detect_generic_kv` and `detect_generic_csv` functions are **production
inference capabilities** implemented in `ulpx_infer::evidence`, not
benchmark-specific helpers. They include strict guards against false
attribution (reject JSON, CEF, Syslog, XML prefixes) and emit only `Medium`
confidence.

The unseen-vendor benchmark exercises the full onboarding pipeline:
1. Inference engine identifies an unknown format via structural detectors
2. `derive_spec_from_inference` generates a `ParserSpec`
3. `ParserGenerator::build` creates a parser from the spec
4. The generated parser extracts fields from the raw frame
5. Extracted fields are compared against fixture expectations

The fixtures use structurally independent examples (space-delimited KV pairs,
comma-separated values) that are not isomorphic to any built-in parser format.

## Limitations

- Confidence calibration is NOT IMPLEMENTED (categorical levels only).
- Benchmark runs in `dev` profile; production builds would differ.
- Only 13 fixtures; a production benchmark suite would need more.
- Single-threaded, single-machine measurement.
- No network I/O or storage I/O in the timed loop.
