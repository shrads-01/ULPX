# ULPX -- Architecture

> **Status**: Living document. Updated after each implemented phase.
> Last updated: Phase 14D (Offline CLI Ingestion Boundary).

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
                           ┌─ lossless evidence storage ─┐
                           │                             │
raw input (file/stdin)     │                             │
        │                  │                             │
        ▼                  │                             │
   [ulpx-ingest]           │                             │
   (CLI boundary)          │                             │
   Frames byte stream      │                             │
   and constructs RawEvent │                             │
        │                  │                             │
        ▼                  │                             │
   EvidenceStore::store    │  ← original bytes stored    │
   (assigns EventId,       │    unmodified; integrity    │
    computes hash,         │    hash computed at store   │
    links to chain)        │    time; never overwritten  │
        │                  │                             │
        └─────────────────►│  InMemoryStore              │
                           │  LocalEvidenceStore         │
                           └──────────────────────────── ┘
                                      │
                                      │ EvidenceStore::retrieve
                                      │ (returns original bytes,
                                      │  byte-for-byte identical)
                                      ▼
                           ┌──── ReplayPipeline ─────────────────────────────┐
                           │                                                 │
                           │  1. verify_chain -- confirms integrity before   │
                           │     any interpretation begins                   │
                           │                                                 │
                           │  2. Framer::frame_all(raw_bytes)                │
                           │     Identifies record boundaries.               │
                           │     Does NOT modify the original stored bytes.  │
                           │     Produces FramedRecord slices.               │
                           │                                                 │
                           │  3. ParserRegistry / InferenceEngine            │
                           │     Interprets each FramedRecord.               │
                           │     Parsers receive the already-framed bytes.   │
                           │                                                 │
                           │  4. IrConverter  →  EventIr (canonical IR)     │
                           │                                                 │
                           │  5. MappingEngine  →  CanonicalEvent            │
                           │                       (OCSF draft projection)   │
                           │                                                 │
                           │  Returns: Interpretation                        │
                           │    .id              (InterpretationId)          │
                           │    .integrity_verified                          │
                           │    .frames          (FrameInterpretation[])     │
                           └─────────────────────────────────────────────────┘
                                      │
                                      ▼
                           [FUTURE] export / persistence
                           (not yet implemented -- see §Future)
```

**Key invariants of the above:**

- Ingestion framing does not consume or replace the original evidence. The exact framed bytes become the `RawEvent` bytes.
- **Limitation (Phase 14D):** The current `NewlineFramer` strips the framing delimiters (`\n` and `\r\n`). Because ingestion currently uses this framer, the delimiter bytes are not preserved in the stored `RawEvent`. The payload itself is byte-exact.
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

## FUTURE: Infrastructure connection points

**None of the following are implemented. They are design directions for later
phases. Do not assume any of these exist until they are committed.**

### FUTURE -- Streaming ingestion (Kafka / Redpanda)

The intended design is:

```
[FUTURE] Kafka / Redpanda consumer
      | reads batches of raw bytes per topic/partition
      v
[FUTURE] ulpx-ingest streaming adapter
      | frames bytes into per-record boundaries
      | constructs RawEvent (assigns EventId, source)
      v
EvidenceStore::store(raw_event)   <- no change to this interface
```

Kafka and Redpanda must never become required dependencies of `ulpx-core`.

### FUTURE -- Relational persistence (PostgreSQL)

Intended responsibility: durable, indexed storage of `RawEvent` records.

### FUTURE -- Search (OpenSearch)

Intended responsibility: analyst-facing indexed search over `CanonicalEvent` and `Interpretation` projections.

### FUTURE -- Columnar / archival (Parquet / object storage)

Intended responsibility: bulk export of evidence and interpretation records for long-term retention and analytics.

### FUTURE -- Interpretation persistence

When persistence is added, `InterpretationId` is suitable as a primary key without changes to the existing type.

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

## Known limitations (Phase 14D)

- **In-memory index**: `LocalEvidenceStore` builds its entire `EventId` index in memory at startup via an O(N) sequential file scan.
- **Unbounded log growth**: the append-only log file is never compacted or rotated.
- **Silent tail recovery**: malformed trailing records are silently discarded on startup.
- **Byte exactness on delimiters**: Because the current `NewlineFramer` strips newlines, the framing delimiters (`\n`, `\r\n`) are not preserved in the stored `RawEvent` during ingestion. The payload itself is byte-exact.
- **Memory buffering**: Ingestion currently buffers entire streams into memory.
- **No interpretation persistence**: `Interpretation` records are ephemeral.
- **No export projections**: OCSF, ECS, Parquet, and OpenSearch output are not implemented.
