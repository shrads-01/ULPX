# Air-Gapped Deployment & Network Isolation

## Overview

ULPX is designed from the ground up for high-security, sovereign, and fully disconnected (air-gapped) environments. This repository provides a verified, reproducible Docker Compose deployment that guarantees:
1. **Zero External Runtime Dependencies**: Binaries, structural heuristic parsers, schema converters, and web UI assets are fully self-contained. No external models, packages, crates, or runtime fonts/CDNs are queried or downloaded.
2. **Kernel-Enforced Network Isolation**: The deployment runs on a Docker bridge network with `internal: true`. The Docker daemon and Linux kernel drop all outbound gateway/NAT packets from containers on this network.
3. **Lossless Evidence Persistence**: Ingested raw telemetry and cryptographic content hashes persist on a dedicated local volume (`ulpx_data:/data`) across container lifecycle events.
4. **End-to-End Verification**: An automated integration test suite in `ulpx-e2e` programmatically deploys, tests, and verifies the air-gapped stack.

---

## Deployment Architecture

```text
Host System / CI Environment
  │
  ├── [docker-compose.yml]
  │     ├── Networks:
  │     │     └── ulpx_airgap_net (driver: bridge, internal: true)
  │     │           │
  │     │           ├── [ulpx_airgap] (ulpx-serve & ulpx CLI)
  │     │           │     ├── Environment: ULPX_STORE_PATH=/data/.ulpx_store
  │     │           │     ├── Port: 3000:3000 (host-mapped for local analyst UI)
  │     │           │     └── Volume: ulpx_data -> /data
  │     │           │
  │     │           └── [ulpx_redpanda] (Kafka/Redpanda streaming broker)
  │     │                 └── Port: 9092:9092
  │     │
  │     └── Volumes:
  │           └── ulpx_data (Persistent evidence storage)
```

### Network Isolation Policy
- **`internal: true`**: When specified on a Docker bridge network, Docker omits default NAT routing rules to external interfaces. Outbound connection attempts to public or external IP addresses (e.g., `https://1.1.1.1`) instantly time out or fail with no route to host.
- **Inter-Service Communication**: Containers on `ulpx_airgap_net` retain DNS resolution and internal socket connectivity with each other (e.g. `ulpx_airgap` can reach `redpanda:9092`), but neither can reach the internet.

---

## Zero-Dependency Runtime Verification

The ULPX runtime container (`deploy/Dockerfile`) uses a two-stage build:
1. **Builder Stage (`rust:1.98`)**: Compiles `ulpx` and `ulpx-serve` in release mode.
2. **Runtime Stage (`debian:bookworm-slim`)**: Contains only the minimal base operating system, `ca-certificates`, `curl` (for internal container probes), and the native binaries.
3. **Embedded UI Assets**: The web UI assets (`ulpx-serve/static/index.html`, `style.css`, `app.js`) are compiled directly into the `ulpx-serve` binary using Rust's `include_str!` macro. No Node.js runtime, npm packages, or external font/CSS CDNs are required.

---

## Step-by-Step Deployment Runbook

### 1. Build and Start the Air-Gapped Stack
```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

### 2. Verify Container Health and Network Isolation
Verify that the container is attached to `ulpx_airgap_net` with `internal: true`:
```bash
docker network inspect ulpx_airgap_net --format "{{.Internal}}"
# Expected output: true
```

Verify that external internet access is blocked from inside the container:
```bash
docker exec ulpx_airgap curl -s --connect-timeout 2 https://1.1.1.1
# Expected output: Exit code 28 (Connection timed out) or 7 (Failed to connect)
```

### 3. Ingest Telemetry Under Air-Gap
Copy a raw log file into the container and execute the ingestion pipeline:
```bash
docker cp sample.log ulpx_airgap:/tmp/sample.log
docker exec ulpx_airgap sh -c "ULPX_STORE_PATH=/data/.ulpx_store ulpx process /tmp/sample.log"
```

### 4. Query Evidence and UI
Access the analyst UI from the host machine:
```text
http://localhost:3000/
```
Or query the API from within the container:
```bash
docker exec ulpx_airgap curl -s http://localhost:3000/api/v1/events
```

### 5. Teardown
To cleanly stop containers and remove test networks:
```bash
docker compose -f deploy/docker-compose.yml down -v
```

---

## Automated Air-Gap Integration Test (`ulpx-e2e`)

The crate `ulpx-e2e` contains the automated integration test `test_airgap_end_to_end_real_docker` in `tests/airgap_e2e.rs`.

### Requirements Validated:
1. **Stack Deployment**: Verifies `docker-compose.yml` builds and boots all services.
2. **Network Isolation**: Verifies network `Internal == true` and verifies outgoing connection to `https://1.1.1.1` is dropped.
3. **Air-Gap Violation Guard**: Explicitly asserts that if `curl https://1.1.1.1` returns exit code 0, the test immediately fails with `AIR-GAP VIOLATION`.
4. **UI Availability**: Verifies that `http://localhost:3000/` serves valid HTML with `#events-list` and `#tab-provenance`.
5. **Lossless Ingestion**: Ingests syslog evidence into `/data/.ulpx_store`.
6. **Byte-for-Byte Preservation**: Retrieves raw bytes via `/api/v1/evidence/{id}` and asserts exact equality with original input bytes.
7. **Volume Durability Across Restarts**: Restarts container twice and verifies evidence persists and is queryable.
8. **Offline Parsing**: Executes `/api/v1/replay` with the Syslog parser, ensuring IR and OCSF canonical mapping succeed offline.
9. **Offline Inference**: Executes `/api/v1/replay` with an empty parser registry, ensuring structural inference identifies the Syslog format candidate with high confidence without internet access.

### Execution Command:
```bash
cargo test -p ulpx-e2e -- --nocapture
```

*Note: In CI or development environments without Docker, the test detects Docker absence and outputs `AIRGAP_INTEGRATION_TEST_SKIPPED_DUE_TO_NO_DOCKER` without masking failures.*
