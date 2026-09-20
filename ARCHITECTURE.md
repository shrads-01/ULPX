# ULPX Architecture

## 1. System Objective
ULPX is a Universal Lossless Security Telemetry Intelligence Framework designed for processing heterogeneous security and network telemetry. The primary objective is to guarantee lossless evidence preservation while providing semantic normalization, explicit provenance tracking, deterministic reproducibility, and analytics-ready output. Unlike systems that silently mutate or discard raw bytes upon ingestion, ULPX ensures original evidence is always retained byte-for-byte.

## 2. High-Level Architecture
The ULPX architecture follows a strict, one-way deterministic flow:

Security / Network Log Sources
    ->
ULPX Ingestion
    ->
Lossless Evidence Store
    ->
Framing
    ->
Detection / Parsing / Inference
    ->
ULPX-IR
    ->
Semantic Mapping + Provenance + Confidence
    ->
Versioned Interpretation / Replay
    ->
REST API / Analyst UI / Export / Integration Boundaries

**Boundary Descriptions:**
- **Security / Network Log Sources**: External sources producing raw security telemetry (files, streams, HTTP payloads).
- **ULPX Ingestion**: The entry point that accepts byte streams and routes them for storage.
- **Lossless Evidence Store**: The authoritative persistent storage that saves raw bytes unmodified with cryptographic hashes.
- **Framing**: Identifies record boundaries within raw byte streams without mutating the bytes.
- **Detection / Parsing / Inference**: Identifies formats, extracts fields using known parsers, or infers structure for unknown formats.
- **ULPX-IR**: The canonical internal representation used to bridge varied input formats into a unified event structure.
- **Semantic Mapping + Provenance + Confidence**: Normalizes fields to a common schema while attaching trace data back to source bytes and confidence scores.
- **Versioned Interpretation / Replay**: Deterministically runs the pipeline to project raw evidence into structured analysis data.
- **REST API / Analyst UI / Export / Integration Boundaries**: The consumption layer exposing processed data to analysts and downstream systems.

## 3. End-to-End Data Flow
1. Evidence enters the system through supported ingestion paths (CLI, browser paste/upload, Kafka).
2. The exact original bytes are preserved into the storage backend.
3. Records are explicitly framed (e.g., via newlines) before any interpretation begins.
4. Known formats are parsed by registered parsers, while unknown formats can be structurally analyzed through format inference.
5. Parsed fields are represented in the canonical ULPX internal representation (ULPX-IR).
6. Interpretations attach provenance and explicit confidence metadata to normalized fields.
7. Reprocessing an event deterministically creates new interpretations without replacing or altering the historical raw evidence.
8. Results are exposed through the REST API and Analyst UI, while optional integration/export crates provide downstream persistence and analytics boundaries.

## 4. Lossless Evidence and Integrity
Raw evidence is strictly retained byte-for-byte exactly as it was received. Each stored record is protected with SHA-256 integrity metadata computed at the time of ingestion. Parsing and semantic normalization generate derived interpretations but never replace or modify the authoritative raw evidence.

## 5. Provenance, Confidence and Abstention
ULPX ensures that normalized and semantic values can always be traced back toward their source evidence and the specific parser that interpreted them. When the pipeline extracts or maps data, it attaches categorical confidence scores (`Low`, `Medium`, `High`) derived from structural characteristics. Probabilistic calibration is explicitly not implemented. When evidence is insufficient or ambiguous, the system prefers abstention (producing `UNKNOWN` states) rather than emitting confidently incorrect inferences.

## 6. Unknown-Format Handling
When telemetry arrives in an unknown format, ULPX can structurally analyze the raw bytes to generate candidate interpretations and parser specifications. Uncertainty in these generated candidates is explicitly represented via confidence metadata. This candidate inference operates purely in an advisory capacity; it is not equivalent to automatic, trusted parser promotion, and validation is still required.

## 7. Streaming and Integration Boundaries
ULPX provides a streaming integration boundary for Kafka/Redpanda using `rskafka`. The current implementation operates strictly as an ingestion adapter with documented limitations: it lacks Kafka consumer groups, does not perform broker offset commits, begins consumption at `StartOffset::Latest`, provides no at-least-once delivery guarantee, and falls back to local in-memory retry behavior upon failure. For full details, refer to `docs/KAFKA_LIMITATIONS.md`.

ULPX also defines specific integration boundary crates (`ulpx-postgres`, `ulpx-opensearch`, `ulpx-parquet`, `ulpx-object-store`) for exporting derived interpretations. These are optional infrastructure boundaries distinct from the default local API server path.

## 8. Deployment and Air-Gapped Operation
ULPX includes a Docker Compose deployment containing the `ulpx-serve` API/UI container and a Redpanda integration container. The Docker Compose runtime network is configured with `internal: true` to prevent outbound internet access, and data is stored in a persistent application data volume. Runtime configuration is managed through environment variables.

The runtime is designed for disconnected, air-gapped operation. However, for a genuinely offline installation, the required container images and build dependencies must already be available locally prior to execution. The publicly accessible Render deployment is strictly a demonstration environment using ephemeral filesystem storage and is not the air-gapped deployment itself.

## 9. Security and Design Constraints
- Raw telemetry is treated as attacker-controlled input.
- All pipeline processing is strictly deterministic.
- Parsing errors are explicit and defensively handled to prevent crashes.
- Bounded resource handling is implemented where applicable.
- The system operates entirely without cloud AI dependency.
- Core telemetry processing can operate fully without Internet connectivity.
- Uncertain interpretations explicitly prefer `UNKNOWN` over unsupported certainty.

## 10. Current Implementation Scope
The current implementation scope of the repository includes:
- A modular Rust workspace architecture.
- Lossless evidence storage backed by local file systems.
- Cryptographic SHA-256 integrity tracking on stored records.
- Record framing separated from interpretation.
- Parsing and explicit format inference for unknown inputs.
- The canonical ULPX-IR translation layer.
- Provenance and interpretation APIs exposing categorical confidence.
- Deterministic event replay.
- A Kafka/Redpanda streaming ingestion boundary with documented limitations.
- An Analyst UI supporting browser-based evidence ingestion (paste/file upload).
- A REST API for retrieving evidence and detailed interpretations.
- A Docker Compose deployment validated for air-gapped operation.
- A deterministic benchmark suite.
- A public demonstration deployment (Render).

*Note: Conceptual roadmap features (such as entity resolution, semantic drift detection, Merkle trees, signed evidence checkpoints, probabilistic confidence calibration, and distributed production API auth) are not claimed as implemented.*
