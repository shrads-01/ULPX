# ULPX: Universal Lossless Security Telemetry Intelligence Framework

ULPX is a security telemetry processing pipeline built on three non-negotiable architectural principles:
1. **Never lose original evidence:** Raw bytes are preserved unmodified. The system guarantees byte-for-byte recovery.
2. **Strict separation of concerns:** Event framing (finding record boundaries) is strictly separated from parsing (interpreting fields).
3. **Represent uncertainty explicitly:** Format inference, confidence levels, and provenance are first-class concepts. Interpretations are versioned and deterministic.

## End-to-End Flow

```text
raw evidence -> lossless evidence storage -> framing -> parser/inference -> ULPX-IR -> semantic mapping -> provenance/integrity -> interpretation/replay -> API/UI/export/storage boundaries
```
*Note: ULPX-IR is the canonical internal representation. The interpretation is an ephemeral projection; the raw evidence remains the authoritative source of truth.*

## Core Capabilities

- **Lossless Evidence Storage**: Ingested data is protected by cryptographic integrity checks (SHA-256) and never overwritten.
- **Deterministic Replay**: Reprocessing evidence with new parsers yields a new, versioned interpretation without modifying history.
- **Unknown-Format Inference**: If an event format is unknown, ULPX uses structural detectors to generate a parser spec automatically, explicitly marking confidence.
- **Air-Gapped Deployment**: ULPX operates without an internet connection, cloud AI dependency, or external APIs.

---

## Quick-Start / Demo Instructions

### 1. Build and Test
```bash
cargo build --workspace
cargo test --workspace
```

### 2. Start the Server (Local)
Starts the local storage backend and the REST API. (Ensure PostgreSQL is running externally if configured, though the default is local file storage).
```bash
# Ensure you are in the ULPX directory
cargo run -p ulpx-serve
```
*The API will be available at `http://localhost:3000`.*

### 3. Ingest a Sample Log
In a separate terminal, use the CLI to process a local file:
```bash
echo 'CEF:0|Vendor|Product|1.0|100|Test|3|src=10.0.0.1' > sample.log
cargo run -p ulpx-ingest -- process sample.log
```

### 4. Query Evidence and Interpretations
Retrieve the canonical interpretation of the ingested event (replace `evt_...` with your actual Event ID):
```bash
curl http://localhost:3000/api/v1/events
curl http://localhost:3000/api/v1/evidence/<EVENT_ID>
curl http://localhost:3000/api/v1/interpretation/<EVENT_ID>/detailed
```

### 5. Run the Analyst UI
Navigate to `http://localhost:3000/` in your web browser to explore events, view raw bytes, check provenance, and review inferences.

### 6. Run the Benchmark Suite
The deterministic benchmark evaluates framing, parsing, mapping, and unseen-vendor inference.
```bash
cargo run -p ulpx-bench
```

---

## Air-Gapped Deployment (Phase 16)

ULPX includes a fully air-gapped Docker Compose deployment ensuring true offline operation.

### Deployment Architecture
- **`ulpx_airgap` Container**: Runs the `ulpx-serve` API and UI.
- **`airgap_net` Network**: Docker bridge network with `internal: true` ensuring no outbound internet access.
- **`ulpx_data` Volume**: Persistent storage for evidence.

### Usage
```bash
docker compose -f deploy/docker-compose.yml up --build
```
*The E2E tests (`cargo test -p ulpx-e2e`) validate that ingestion, parsing, inference, storage, and the UI all function flawlessly within this completely disconnected environment.*

---

## Benchmark Suite (Phase 17)

The `ulpx-bench` crate provides a deterministic macro-benchmark evaluated against 13 strict fixtures:
- **Known (3)**: JSON, CEF, Syslog
- **Malformed (5)**: Binary, Invalid JSON, Truncated JSON, Malformed CEF, Oversized (65 MiB boundary test)
- **Adversarial (2)**: Fake syslog embedded in JSON, Mixed formats
- **Unknown (1)**: Plain text triggering proper abstention
- **Unseen Vendor (2)**: Exercises the inference -> onboarding -> parser generation pipeline

### Measurement
- **Accuracy**: Exact complete-set validation for framing, field extraction, and semantic mapping. Hallucinated fields cause immediate failure.
- **Performance**: Reports p50/p95/p99 micro and E2E wall-clock latency, throughput (Bytes/us), and peak working set memory. (Note: These are local macro-benchmarks, not distributed production claims).
- **Confidence**: Reports confidence-stratified accuracy. **Note: True probabilistic calibration is NOT IMPLEMENTED.** The model uses categorical confidence (`Low`, `Medium`, `High`) derived from structural evidence. Mapping this to a numeric percentage is mathematically unsound and deliberately avoided.

---

## Documentation Links

- [Architecture Document](ARCHITECTURE.md)
- [REST API Reference](API.md)
- [Detailed Benchmarks](ulpx-bench/README.md)
- [Air-Gapped Deployment Guide](docs/PHASE_16_AIRGAP.md)
