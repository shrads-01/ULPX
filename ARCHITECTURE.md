# ULPX -- Architecture

> **Status**: Living document. Updated after each implemented phase.
> Last updated: Documentation / Benchmark.

---

## Architectural principles

ULPX is built around three non-negotiable design rules that apply to every
layer of the pipeline:

1. **Lossless evidence preservation.** Original raw bytes are never silently
   modified or discarded. The system must preserve enough information to
   recover the original input byte-for-byte.

2. **Framing and parsing are separate concerns.** Framing identifies event
   record boundaries within a byte stream. Parsing interprets an already-framed
   record. These stages must remain independent components so that either can
   change without affecting the other.

3. **ULPX-IR is the canonical internal representation.** OCSF, ECS, and other
   output projections are derived views, not the source of truth.

---

## Implemented pipeline

The current pipeline covers: ingestion -> evidence storage -> replay -> framing -> parsing
-> IR conversion -> semantic mapping -> interpretation.

```
                           â”Œâ”€ lossless evidence storage â”€â”
                           â”‚                             â”‚
raw input (file/stdin)     â”‚                             â”‚
        â”‚                  â”‚                             â”‚
        â–¼                  â”‚                             â”‚
   [ulpx-ingest]           â”‚                             â”‚
   (CLI boundary)          â”‚                             â”‚
   Frames byte stream      â”‚                             â”‚
   and constructs RawEvent â”‚                             â”‚
        â”‚                  â”‚                             â”‚
        â–¼                  â”‚                             â”‚
   EvidenceStore::store    â”‚  â† original bytes stored    â”‚
   (assigns EventId,       â”‚    unmodified; integrity    â”‚
    computes hash,         â”‚    hash computed at store   â”‚
    links to chain)        â”‚    time; never overwritten  â”‚
        â”‚                  â”‚                             â”‚
        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–ºâ”‚  InMemoryStore              â”‚
                           â”‚  LocalEvidenceStore         â”‚
                           â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”˜
                                      â”‚
                                      â”‚ EvidenceStore::retrieve
                                      â”‚ (returns original bytes,
                                      â”‚  byte-for-byte identical)
                                      â–¼
                           â”Œâ”€â”€â”€â”€ ReplayPipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                           â”‚                                                 â”‚
                           â”‚  1. verify_chain -- confirms integrity before   â”‚
                           â”‚     any interpretation begins                   â”‚
                           â”‚                                                 â”‚
                           â”‚  2. Framer::frame_all(raw_bytes)                â”‚
                           â”‚     Identifies record boundaries.               â”‚
                           â”‚     Does NOT modify the original stored bytes.  â”‚
                           â”‚     Produces FramedRecord slices.               â”‚
                           â”‚                                                 â”‚
                           â”‚  3. ParserRegistry / InferenceEngine            â”‚
                           â”‚     Interprets each FramedRecord.               â”‚
                           â”‚     Parsers receive the already-framed bytes.   â”‚
                           â”‚                                                 â”‚
                           â”‚  4. IrConverter  â†’  EventIr (canonical IR)     â”‚
                           â”‚                                                 â”‚
                           â”‚  5. MappingEngine  â†’  CanonicalEvent            â”‚
                           â”‚                       (OCSF draft projection)   â”‚
                           â”‚                                                 â”‚
                           â”‚  Returns: Interpretation                        â”‚
                           â”‚    .id              (InterpretationId)          â”‚
                           â”‚    .integrity_verified                          â”‚
                           â”‚    .frames          (FrameInterpretation[])     â”‚
                           â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                      â”‚
                                      â–¼
                           [FUTURE] export / persistence
                           (not yet implemented -- see Â§Future)
```

**Key invariants of the above:**

- Ingestion framing does not consume or replace the original evidence. The exact framed bytes become the `RawEvent` bytes.
- **Byte exactness on delimiters**: Ingestion strictly preserves the exact framed source bytes via FramedRecord::byte_range(). The payload and its delimiters are byte-exact.
- Framing does not modify the original stored bytes during replay either.
- If `verify_chain` fails, the pipeline returns an `Interpretation` with `integrity_verified: false` and empty frames. No parsing occurs on evidence whose integrity cannot be confirmed.
- `Interpretation` is an ephemeral in-memory result. It is not currently persisted anywhere.
- **Atomicity:** Ingestion is **record-wise, not transactional**. A failure mid-stream leaves previously successfully stored records in the `EvidenceStore`.

---

## Crate dependency graph (implemented)

```
ulpx-core
  (event, storage, framing, parser, integrity)
        ^         ^          ^         ^
        |         |          |         |
   ulpx-ingest  ulpx-infer  ulpx-ir  ulpx-mapping
  (CLI/offline) (inference)  (IR)    (mapping)
                                         ^
                                    ulpx-replay
                                    (replay pipeline,
                                     interpretation types)
                                         ^
                                    ulpx-onboard
                                    (parser onboarding)
```

No crate has a dependency on Kafka, Redpanda, PostgreSQL, OpenSearch, Parquet,
or any external network service. All crates compile and operate fully offline.

---

## EvidenceStore -- the storage abstraction boundary

`EvidenceStore` (in `ulpx-core::storage`) is the **single boundary** between
the core evidence semantics and all storage backends.

---

## Separation of concerns -- confirmed

| Concern | Current location | Status |
|---|---|---|
| Evidence persistence | `ulpx-core::storage` | Implemented |
| Integrity metadata attachment | `ulpx-core::storage` (at `store` time) | Implemented |
| Cryptographic chain verification | `ulpx-core::integrity` (free functions) | Implemented |
| Event retrieval | `ulpx-core::storage` | Implemented |
| Framing (record boundary identification) | `ulpx-core::framing` | Implemented |
| Parsing (field extraction from framed records) | `ulpx-core::parser` | Implemented |
| Unknown-format inference | `ulpx-infer` | Implemented |
| IR conversion | `ulpx-ir` | Implemented |
| Semantic mapping | `ulpx-mapping` | Implemented |
| Deterministic replay / interpretation | `ulpx-replay` | Implemented |
| Ingestion from external sources | `ulpx-ingest` (CLI) | Implemented |
| Interpretation persistence | Not yet implemented | -- |
| Export projections (OCSF, ECS, Parquet) | Not yet implemented | -- |

---

## Infrastructure Connection Points (Implemented)

### Streaming ingestion (Kafka / Redpanda)

The streaming boundary is implemented in `ulpx-ingest` using `rskafka`. It operates strictly as an ingestion adapter and is not a dependency of `ulpx-core`.

```text
[Kafka / Redpanda]
      | reads batches of raw bytes per topic/partition
      v
[ulpx-ingest]
      | streaming adapter (rskafka)
      | frames bytes into per-record boundaries
      | constructs RawEvent (assigns EventId, source)
      v
EvidenceStore::store(raw_event)   <- core interface boundary
```

**Explicit Limitations:**
- `rskafka` does not provide Kafka Consumer Groups or broker offset commits.
- Consumption starts at `StartOffset::Latest`.
- There is no at-least-once delivery guarantee or durable broker offset tracking.
- Processing failures are retried locally in memory.

### Relational persistence (PostgreSQL)
Implemented in `ulpx-postgres` as a persistence boundary for PostgreSQL-backed data.

### Search (OpenSearch)
Implemented in `ulpx-opensearch`. Analyst-facing indexed search over `CanonicalEvent` and `Interpretation` projections.

### Columnar / archival (Parquet / object storage)
Implemented in `ulpx-parquet` and `ulpx-object-store`. Bulk export of evidence and interpretation records for long-term retention and analytics.

### Interpretation persistence
When full interpretation persistence is finalized, `InterpretationId` remains the primary key. Currently, interpretation is ephemeral via API.

---

## Identity model

| Identifier | Type | Scope | Determinism |
|---|---|---|---|
| `EventId` | Non-empty `String` | Global; caller-assigned at ingestion | Stable |
| `IntegrityMetadata.content_hash` | SHA-256 of raw bytes | Per stored event | Deterministic |
| `InterpretationId` | SHA-256 of `(EventId || PipelineConfiguration)` | Per interpretation | Deterministic |
| `PipelineConfiguration` | Framer id+version, mapper id+version, parser registry ids+versions, inference detector ids | Per replay run | Deterministic |

**EventId Policy (Offline CLI Ingestion):**
`EventId` is deterministic for offline processing: `hex(SHA-256(source_length || source || index || raw_bytes))`.
This guarantees stable IDs across identical ingestion runs (enabling duplicate rejection), while correctly disambiguating multiple identical records within the same stream.

**Source Metadata Policy (Offline CLI Ingestion):**
For local files, the `Source` is the file path provided to the CLI. For standard input, the `Source` is explicitly `"stdin"`.

---

## Offline-first guarantee

The following capabilities work with no network connection, no external services, and no additional dependencies:
- Ingestion (`ulpx process`)
- Offline Replay (`ulpx replay`)
- Evidence storage (`LocalEvidenceStore`)
- Framing, parsing, unknown-format inference
- Cryptographic integrity verification (`verify_chain`)
- Deterministic replay (`ReplayPipeline`)

---

## Implemented Infrastructure

### Authoritative evidence:
    EvidenceStore (LocalEvidenceStore)

### Derived artifacts:
    Parquet (ulpx-parquet) / Object Storage (ulpx-object-store)
    PostgreSQL (ulpx-postgres) / OpenSearch (ulpx-opensearch)

### Offline operation:
    LocalObjectStore, CLI, REST API, and Docker Air-gap require no network.

- **Parquet Export**: Deterministic export layer (ulpx-parquet). Parquet is a derived frame-level export / analytics representation.
- **PostgreSQL**: Persistent operational record of schemas/indices (ulpx-postgres).
- **OpenSearch**: Derived searchable output projection for interpretations (ulpx-opensearch).
- **Air-Gapped Deployment**: Full Docker Compose environment isolating network access, validating ingestion, parsing, inference, and storage without internet (ulpx-e2e).
- **Local REST API (ulpx-serve)**: Exposes read-only evidence retrieval (`/api/v1/evidence/:id`), interpretation retrieval (`/api/v1/interpretation/:id/detailed`), and ephemeral replay (`/api/v1/replay`).
- **Zero-Network Ingestion**: The offline CLI (`ulpx process`) remains fully functional without any network requirement.
- **Benchmarking (ulpx-bench)**: Data-driven deterministic correctness and performance benchmark suite.

## Future Infrastructure (Not Implemented)

- **Future remote object storage**: may be introduced as another implementation later (e.g. S3).
- **Production API Server**: Authentication, authorization, and rate limiting are not yet implemented.
- **Interpretation Persistence**: Full durable storage of interpretation artifacts is not yet implemented.

## Known limitations

- **Kafka Streaming**: No durable consumer-group offset commits or at-least-once guarantee.
- **In-memory index**: `LocalEvidenceStore` builds its entire `EventId` index in memory at startup via an O(N) sequential file scan.
- **Unbounded log growth**: the append-only log file is never compacted or rotated.
- **Silent tail recovery**: malformed trailing records are silently discarded on startup.
- **Memory buffering**: Ingestion currently buffers entire streams into memory.
- **Categorical Confidence**: Inference operates on discrete categorical confidence (`Low/Medium/High`) using exact rule counters. True probabilistic calibration is mathematically impossible without numeric probability signals and is NOT IMPLEMENTED.
- **Interpretation**: Interpretation retrieval and replay is currently ephemeral.
- **Production Readiness**: Benchmark results are local measurements, not production capacity claims. API authentication, authorization, and rate limiting are not implemented.