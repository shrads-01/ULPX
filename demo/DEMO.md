# ULPX Demonstration Walkthrough

This guide provides a reproducible, one-command-at-a-time walkthrough to demonstrate ULPX's core capabilities to a reviewer. All commands are designed for Windows PowerShell.

## Prerequisites
Ensure Rust, Cargo, and Docker are installed.

---

## 1. Start ULPX
Start the local API and UI server. (It is recommended to run this in a separate PowerShell window).

```powershell
cargo run -p ulpx-serve
```
*Wait a few seconds for the server to bind to `http://localhost:3000`.*

## 2. Ingest a Sample Event
We will ingest an unseen vendor log (KV format) that ULPX does not have a hardcoded parser for.

```powershell
"vendor=ACME product=Firewall action=DENY" | Out-File -FilePath sample.log -Encoding ascii -NoNewline
cargo run -p ulpx-ingest -- process sample.log
```

## 3. Retrieve the Event & Show Raw Evidence Preserved
The ingest command will output an Event ID (e.g., `evt_...`). Store it as a PowerShell variable for the remaining steps (replace with your actual ID):
```powershell
$EVENT_ID = "evt_..."
```

Prove that ULPX preserved the original bytes exactly (notice it returns base64 and the integrity hash):
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/api/v1/evidence/$EVENT_ID"
```

## 4. Show IR/Canonical Interpretation & Provenance
Retrieve the canonical interpretation, which includes inference, parsed IR, semantic mapping, and provenance metadata:
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/api/v1/interpretation/$EVENT_ID/detailed" | ConvertTo-Json -Depth 10
```
Notice how ULPX used the `generic-kv-space-eq` structural detector to correctly extract the fields without a hardcoded parser, and preserved provenance data.
## 5. Phase 15 Analyst UI
Navigate to `http://localhost:3000/` in a web browser. The Phase 15 Analyst UI allows you to visually explore ingested events, view raw preserved bytes, inspect field provenance, and review the structural inference confidence levels.

## 6. Ephemeral Replay (Reprocessing)
Demonstrate reprocessing the event with a custom pipeline configuration without mutating the original evidence:
```powershell
$ReplayBody = @{
    event_id = $EVENT_ID
    pipeline_config = @{
        framer_id = "NewlineFramer"
        framer_version = "1.0.0"
        mapper_id = "default"
        mapper_version = "1.0.0"
        parser_registry = @("json-flat", "cef", "syslog-rfc3164")
        inference_detectors = @("json", "cef", "syslog", "generic-kv-space-eq", "generic-csv-3col")
    }
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri "http://localhost:3000/api/v1/replay" `
  -Method Post `
  -ContentType "application/json" `
  -Body $ReplayBody | ConvertTo-Json -Depth 10
```

## 7. Run the Benchmark Suite
Run the Phase 17 deterministic benchmark to prove framing, parsing, and exact completeness validations:
```powershell
cargo run -p ulpx-bench
```

## 8. Demonstrate the Air-Gapped Deployment
Finally, demonstrate that ULPX operates seamlessly in a fully disconnected environment.
```powershell
docker compose -f deploy/docker-compose.yml up --build -d
```

You can run the end-to-end integration test which verifies this air-gapped configuration programmatically:
```powershell
cargo test -p ulpx-e2e
```

When finished, tear down the air-gap environment:
```powershell
docker compose -f deploy/docker-compose.yml down -v
```

## 9. Kafka / Streaming Boundary
ULPX implements a streaming boundary using `rskafka` in `ulpx-ingest`. Note that this is currently an ingestion adapter only. It does **not** provide consumer-group offset commits, it starts consumption at `StartOffset::Latest`, and it provides **no at-least-once delivery guarantees**. It is documented here as an explicit architectural boundary and limitation (Phase 14), rather than a production-grade distributed consumer demonstration.
