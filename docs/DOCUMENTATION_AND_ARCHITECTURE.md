# Documentation, Architecture & Demonstration

## Objective
The objective is to ensure the project documentation accurately reflects the current state of the implemented system, explicitly documenting architectural boundaries, explicit limitations, and capabilities implemented in previous phases. No source code or runtime behavior is modified in this update.

## Implemented Capabilities Documented

### Kafka/Redpanda Streaming Boundary & Blocker
ULPX implements a streaming boundary for Kafka/Redpanda via `ulpx-ingest` (using `rskafka`). This is an ingestion adapter only. It lacks consumer-group tracking, durable broker offset commits, and at-least-once delivery guarantees. See `docs/KAFKA_LIMITATIONS.md` for full details.

### Analyst UI & API
The REST API (in `ulpx-serve`) and Analyst UI provide capabilities to query evidence, retrieve canonical interpretations (including parsing, inference confidence, semantic mapping, and field provenance), and perform ephemeral pipeline replay without mutating authoritative evidence. The API also includes the `GET /api/v1/entity/:type/:value` endpoint for entity resolution.

### Air-Gapped Deployment
ULPX is fully capable of operating without an internet connection or external services. The `deploy/docker-compose.yml` provides a completely isolated, offline deployment for ingestion, parsing, inference, storage, and the UI. Validated by `ulpx-e2e`.

### Benchmarking
The `ulpx-bench` crate provides deterministic macro-benchmarks using 13 strict fixtures covering known, malformed, adversarial, and unseen vendor scenarios. It measures correctness, completeness, inference mapping, throughput, latency, and memory usage.

### Infrastructure Boundaries
The workspace includes several crates representing boundaries for derived data and integrations:
- `ulpx-postgres` (relational persistence)
- `ulpx-opensearch` (searchable interpretation)
- `ulpx-parquet` (columnar export)
- `ulpx-object-store` (archival)

## Known Limitations

- **Kafka Streaming**: `rskafka` implementation has no durable consumer-group offset commits, starts at `StartOffset::Latest`, and provides no at-least-once guarantee.
- **In-Memory Index**: `LocalEvidenceStore` builds its entire `EventId` index in memory at startup via an O(N) sequential file scan.
- **Unbounded Log Growth**: The append-only log file in `LocalEvidenceStore` is never compacted or rotated.
- **Interpretation Persistence**: Interpretation retrieval and replay is ephemeral; durable storage of interpretation artifacts is not implemented.
- **Production API**: Authentication, authorization, and rate limiting are not implemented.
- **Benchmarking**: Benchmark results represent local measurements and are not production capacity claims.

## Documentation Files Updated
- `README.md`
- `ARCHITECTURE.md`
- `API.md`
- `demo/DEMO.md`
- `docs/DOCUMENTATION_AND_ARCHITECTURE.md` (this document)

## Validation Commands
To verify the integrity of the workspace after documentation updates, run:
```bash
cargo fmt --all -- --check
cargo test --workspace
cargo run -p ulpx-bench
```

## Completion Criteria
- All architectural updates reflect the currently implemented `HEAD`.
- Explicit limitations regarding Kafka are accurately recorded.
- API changes correctly highlight ephemeral replay and inference details.
- Demonstration guide incorporates new UI steps without breaking PowerShell compatibility.
- Workspace tests and benchmark validation complete; `cargo fmt --all -- --check` remains subject to the pre-existing formatting issue in `ulpx-e2e\tests\airgap_e2e.rs`.
