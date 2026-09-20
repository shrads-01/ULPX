use base64::{engine::general_purpose, Engine as _};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;
use tokio::time::sleep;

fn get_docker_cmd() -> Command {
    Command::new("docker")
}

fn get_compose_cmd() -> Command {
    let mut cmd = get_docker_cmd();
    cmd.arg("compose");
    cmd
}

fn is_docker_available() -> bool {
    get_docker_cmd()
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

struct DockerCleanup {
    compose_path: PathBuf,
}

impl Drop for DockerCleanup {
    fn drop(&mut self) {
        let _ = get_compose_cmd()
            .arg("-f")
            .arg(&self.compose_path)
            .arg("down")
            .arg("-v")
            .output();
    }
}

fn exec_in_ulpx(args: &[&str]) -> Output {
    let mut cmd = get_docker_cmd();
    cmd.arg("exec").arg("ulpx_airgap");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output()
        .expect("Failed to execute command inside ulpx_airgap container")
}

#[tokio::test]
async fn test_airgap_end_to_end_real_docker() {
    if !is_docker_available() {
        println!("AIRGAP_INTEGRATION_TEST_SKIPPED_DUE_TO_NO_DOCKER");
        return;
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("[Requirement 1] CARGO_MANIFEST_DIR must be set by cargo test runner");
    let workspace_dir = std::path::Path::new(&manifest_dir)
        .parent()
        .expect("[Requirement 1] Unable to find workspace root from CARGO_MANIFEST_DIR");
    let compose_path = workspace_dir.join("deploy").join("docker-compose.yml");
    assert!(
        compose_path.exists(),
        "[Requirement 1] Compose file not found at {:?}",
        compose_path
    );

    let _cleanup = DockerCleanup {
        compose_path: compose_path.clone(),
    };

    // Teardown any leftover containers/volumes first
    let _ = get_compose_cmd()
        .arg("-f")
        .arg(&compose_path)
        .arg("down")
        .arg("-v")
        .output();

    println!("Building and bringing up ULPX stack in air-gapped environment...");
    let status = get_compose_cmd()
        .arg("-f")
        .arg(&compose_path)
        .arg("up")
        .arg("-d")
        .arg("--build")
        .status()
        .expect("[Requirement 1] Failed to execute 'docker compose up'");
    assert!(
        status.success(),
        "[Requirement 1] 'docker compose up --build -d' failed to start the ULPX deployment stack"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 1. VERIFY AIR-GAP NETWORK ARCHITECTURE
    // ─────────────────────────────────────────────────────────────────────────
    let inspect_out = get_docker_cmd()
        .arg("inspect")
        .arg("ulpx_airgap")
        .arg("--format")
        .arg("{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}")
        .output()
        .expect("[Requirement 7] Failed to inspect ulpx_airgap container networks");
    let network_name = String::from_utf8_lossy(&inspect_out.stdout)
        .trim()
        .to_string();
    assert!(
        !network_name.is_empty(),
        "[Requirement 7] Container 'ulpx_airgap' is not attached to any network"
    );

    let net_inspect = get_docker_cmd()
        .arg("network")
        .arg("inspect")
        .arg(&network_name)
        .arg("--format")
        .arg("{{.Internal}}")
        .output()
        .expect("[Requirement 7] Failed to inspect network configuration");
    let is_internal = String::from_utf8_lossy(&net_inspect.stdout)
        .trim()
        .to_string();
    assert_eq!(
        is_internal, "true",
        "[Requirement 7] Network '{}' is NOT strictly internal! 'internal: true' must be enforced in deploy/docker-compose.yml.",
        network_name
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 2. VERIFY OUTBOUND INTERNET IS TRULY BLOCKED (AIR-GAP ENFORCEMENT)
    // ─────────────────────────────────────────────────────────────────────────
    // Directly test the deployed ulpx_airgap container to ensure it cannot communicate externally.
    let ext_req = exec_in_ulpx(&["curl", "-s", "--connect-timeout", "2", "https://1.1.1.1"]);
    let exit_code = ext_req.status.code().unwrap_or(-1);

    // If exit code is 0, the container successfully reached the public internet — a catastrophic air-gap breach!
    assert_ne!(
        exit_code, 0,
        "[Requirement 2 & 9] AIR-GAP VIOLATION: Container 'ulpx_airgap' successfully reached external internet (https://1.1.1.1)! Outbound network isolation failed."
    );

    // Curl exit codes: 28 = operation timeout, 7 = failed to connect, 6 = couldn't resolve host.
    assert!(
        exit_code == 28 || exit_code == 7 || exit_code == 6,
        "[Requirement 2] Expected network failure exit code (28 timeout, 7 connection refused, or 6 host resolution failure) when attempting internet access, but got code: {}. Stderr: {}",
        exit_code,
        String::from_utf8_lossy(&ext_req.stderr)
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 3. VERIFY SERVER & UI AVAILABILITY WHILE AIR-GAPPED
    // ─────────────────────────────────────────────────────────────────────────
    let mut retries = 120;
    while retries > 0 {
        let check = exec_in_ulpx(&[
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://127.0.0.1:3000/",
        ]);
        if String::from_utf8_lossy(&check.stdout).trim() == "200" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
        retries -= 1;
    }
    assert!(
        retries > 0,
        "[Requirement 4] ulpx-serve inside container did not bind and respond on http://127.0.0.1:3000/ within 60s"
    );

    // Verify UI Root serves complete offline HTML without requiring external CDNs/fonts
    let ui_resp = exec_in_ulpx(&["curl", "-s", "http://127.0.0.1:3000/"]);
    assert!(
        ui_resp.status.success(),
        "[Requirement 4] UI root endpoint failed to return HTTP 200"
    );
    let html = String::from_utf8_lossy(&ui_resp.stdout);
    assert!(
        html.contains("<!DOCTYPE html>"),
        "[Requirement 4] UI root did not return valid HTML markup"
    );
    assert!(
        html.contains("events-list"),
        "[Requirement 4] UI does not contain required frontend element '#events-list'"
    );
    assert!(
        html.contains("tab-provenance"),
        "[Requirement 4] UI does not contain Phase 15 Provenance Explorer element"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 4. VERIFY INGESTION UNDER AIR-GAPPED OPERATION
    // ─────────────────────────────────────────────────────────────────────────
    let test_log = env::temp_dir().join("airgap_test.log");
    let raw_content =
        "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n";
    fs::write(&test_log, raw_content)
        .expect("[Requirement 4] Failed to write temporary test log on host");

    let cp_status = get_docker_cmd()
        .arg("cp")
        .arg(&test_log)
        .arg("ulpx_airgap:/tmp/airgap_test.log")
        .status()
        .expect("[Requirement 4] Failed to docker cp test log into container");
    assert!(
        cp_status.success(),
        "[Requirement 4] Failed to copy test log file into 'ulpx_airgap' container"
    );

    let exec_status = exec_in_ulpx(&[
        "sh",
        "-c",
        "ULPX_STORE_PATH=/data/.ulpx_store ulpx process /tmp/airgap_test.log",
    ]);
    assert!(
        exec_status.status.success(),
        "[Requirement 4] Ingestion command 'ulpx process' failed inside container: {}",
        String::from_utf8_lossy(&exec_status.stderr)
    );

    // Restart container so ulpx-serve reloads persistent store
    let restart_status = get_docker_cmd()
        .arg("restart")
        .arg("ulpx_airgap")
        .status()
        .expect("[Requirement 4] Failed to restart container after ingestion");
    assert!(
        restart_status.success(),
        "[Requirement 4] Failed to restart container"
    );

    let mut retries = 120;
    while retries > 0 {
        let check = exec_in_ulpx(&[
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://127.0.0.1:3000/api/v1/events",
        ]);
        if String::from_utf8_lossy(&check.stdout).trim() == "200" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
        retries -= 1;
    }
    assert!(
        retries > 0,
        "[Requirement 4] Server did not become ready after container restart"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 5. VERIFY API & PERSISTENT STORAGE
    // ─────────────────────────────────────────────────────────────────────────
    let ev_resp = exec_in_ulpx(&["curl", "-s", "http://127.0.0.1:3000/api/v1/events"]);
    assert!(
        ev_resp.status.success(),
        "[Requirement 4] Failed to query /api/v1/events"
    );

    let json: serde_json::Value = serde_json::from_slice(&ev_resp.stdout)
        .expect("[Requirement 4] Invalid JSON response from /api/v1/events");
    let events = json
        .get("events")
        .expect("[Requirement 4] 'events' field missing from /api/v1/events response")
        .as_array()
        .expect("[Requirement 4] 'events' should be an array");
    assert_eq!(
        events.len(),
        1,
        "[Requirement 4] Expected exactly 1 event ingested into persistent store"
    );
    let event_id = events[0]
        .get("event_id")
        .expect("[Requirement 4] 'event_id' missing from event summary")
        .as_str()
        .expect("[Requirement 4] 'event_id' should be a string");

    // Retrieve raw evidence and verify byte-for-byte exact preservation
    let ev_raw_resp = exec_in_ulpx(&[
        "curl",
        "-s",
        &format!("http://127.0.0.1:3000/api/v1/evidence/{}", event_id),
    ]);
    assert!(
    ev_raw_resp.status.success(),
    "[Requirement 4] Failed to fetch raw evidence from /api/v1/evidence/{}",
    event_id
    );

    let raw_json: serde_json::Value = serde_json::from_slice(&ev_raw_resp.stdout)
        .expect("[Requirement 4] Invalid JSON response from /api/v1/evidence");
    let b64_payload = raw_json
        .get("payload_base64")
        .expect("[Requirement 4] 'payload_base64' missing from evidence response")
        .as_str()
        .expect("[Requirement 4] 'payload_base64' should be a string");
    let decoded = general_purpose::STANDARD
        .decode(b64_payload)
        .expect("[Requirement 4] Failed to decode base64 evidence payload");

    assert_eq!(
        decoded,
        raw_content.as_bytes(),
        "[Requirement 4 & Rule 1] Stored raw bytes do NOT match original evidence byte-for-byte!"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 6. VERIFY DURABLE VOLUME PERSISTENCE ACROSS SECOND RESTART
    // ─────────────────────────────────────────────────────────────────────────
    let restart_status_2 = get_docker_cmd()
        .arg("restart")
        .arg("ulpx_airgap")
        .status()
        .expect("[Requirement 4] Failed to restart container a second time");
    assert!(
        restart_status_2.success(),
        "[Requirement 4] Failed second container restart"
    );

    let mut retries_2 = 120;
    while retries_2 > 0 {
        let check = exec_in_ulpx(&[
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "http://127.0.0.1:3000/api/v1/events",
        ]);
        if String::from_utf8_lossy(&check.stdout).trim() == "200" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
        retries_2 -= 1;
    }
    assert!(
        retries_2 > 0,
        "[Requirement 4] Server did not become ready after second container restart"
    );

    let ev_raw_resp_2 = exec_in_ulpx(&[
        "curl",
        "-s",
        &format!("http://127.0.0.1:3000/api/v1/evidence/{}", event_id),
    ]);
    assert!(
        ev_raw_resp_2.status.success(),
        "[Requirement 4] Failed to fetch evidence after second restart"
    );

    let raw_json_2: serde_json::Value = serde_json::from_slice(&ev_raw_resp_2.stdout)
        .expect("[Requirement 4] Invalid JSON response after second restart");
    let b64_payload_2 = raw_json_2.get("payload_base64").unwrap().as_str().unwrap();
    let decoded_2 = general_purpose::STANDARD.decode(b64_payload_2).unwrap();

    assert_eq!(
        decoded_2,
        raw_content.as_bytes(),
        "[Requirement 4 & Rule 1] Evidence lost or corrupted after second container restart! Persistent volume durability failed."
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 7. VERIFY OFFLINE PARSING (KNOWN PARSER PATH)
    // ─────────────────────────────────────────────────────────────────────────
    let known_replay_req = serde_json::json!({
        "event_id": event_id,
        "pipeline_config": {
            "framer_id": "NewlineFramer",
            "framer_version": "1.0.0",
            "mapper_id": "DefaultMapper",
            "mapper_version": "1.0.0",
            "parser_registry": ["syslog"],
            "inference_detectors": ["syslog", "json"]
        }
    });

    let known_payload_file = env::temp_dir().join("known_payload.json");
    fs::write(&known_payload_file, known_replay_req.to_string())
        .expect("[Requirement 4] Failed to write known_payload.json");

    let cp_known = get_docker_cmd()
        .arg("cp")
        .arg(&known_payload_file)
        .arg("ulpx_airgap:/tmp/known_payload.json")
        .status()
        .expect("[Requirement 4] Failed to cp known_payload.json to container");
    assert!(
        cp_known.success(),
        "[Requirement 4] Failed to copy known_payload.json to container"
    );

    let known_replay_resp = exec_in_ulpx(&[
        "curl",
        "-s",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-d",
        "@/tmp/known_payload.json",
        "http://127.0.0.1:3000/api/v1/replay",
    ]);

    assert!(
        known_replay_resp.status.success(),
        "[Requirement 4 & 5] Offline replay POST failed for known syslog parser"
    );
    let known_replay_json: serde_json::Value = serde_json::from_slice(&known_replay_resp.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "[Requirement 4] Failed to parse JSON from known replay: {}. Raw stdout: {}",
                e,
                String::from_utf8_lossy(&known_replay_resp.stdout)
            );
        });

    let known_frames = known_replay_json
        .get("frames")
        .expect("[Requirement 4] 'frames' missing from known replay response")
        .as_array()
        .expect("[Requirement 4] 'frames' should be an array");
    assert!(
        !known_frames.is_empty(),
        "[Requirement 4] No frames returned in known replay"
    );
    let known_frame = &known_frames[0];

    let known_parser_outcome = known_frame
        .get("parser_outcome")
        .expect("[Requirement 4] 'parser_outcome' missing")
        .as_str()
        .unwrap();
    assert_eq!(
        known_parser_outcome, "Success",
        "[Requirement 4] Offline parser failed for known syslog event, outcome: {}",
        known_parser_outcome
    );

    let ir_event = known_frame.get("ir_event");
    assert!(
        ir_event.is_some() && !ir_event.unwrap().is_null(),
        "[Requirement 4] ULPX-IR event missing on successful offline parse"
    );
    let canonical = known_frame.get("canonical_event");
    assert!(
        canonical.is_some() && !canonical.unwrap().is_null(),
        "[Requirement 4] Canonical OCSF event missing on successful offline parse"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // 8. VERIFY OFFLINE UNKNOWN-FORMAT SEMANTIC INFERENCE
    // ─────────────────────────────────────────────────────────────────────────
    // Intentionally pass an EMPTY parser registry to force abstention and engagement of inference
    let replay_req = serde_json::json!({
        "event_id": event_id,
        "pipeline_config": {
            "framer_id": "NewlineFramer",
            "framer_version": "1.0.0",
            "mapper_id": "DefaultMapper",
            "mapper_version": "1.0.0",
            "parser_registry": [],
            "inference_detectors": ["syslog", "json"]
        }
    });
    let payload_file = env::temp_dir().join("payload.json");
    fs::write(&payload_file, replay_req.to_string())
        .expect("[Requirement 4] Failed to write payload.json");

    let cp_infer = get_docker_cmd()
        .arg("cp")
        .arg(&payload_file)
        .arg("ulpx_airgap:/tmp/payload.json")
        .status()
        .expect("[Requirement 4] Failed to cp payload.json to container");
    assert!(
        cp_infer.success(),
        "[Requirement 4] Failed to copy payload.json to container"
    );

    let replay_resp = exec_in_ulpx(&[
        "curl",
        "-s",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-d",
        "@/tmp/payload.json",
        "http://127.0.0.1:3000/api/v1/replay",
    ]);

    assert!(
        replay_resp.status.success(),
        "[Requirement 4 & 5] Offline inference replay POST failed"
    );
    let replay_json: serde_json::Value = serde_json::from_slice(&replay_resp.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "[Requirement 4] Failed to parse JSON from inference replay: {}. Raw stdout: {}",
                e,
                String::from_utf8_lossy(&replay_resp.stdout)
            );
        });

    let frames = replay_json
        .get("frames")
        .expect("[Requirement 4] 'frames' missing from inference replay")
        .as_array()
        .unwrap();
    assert!(
        !frames.is_empty(),
        "[Requirement 4] No frames returned in inference replay"
    );
    let frame = &frames[0];

    let parser_outcome = frame
        .get("parser_outcome")
        .expect("[Requirement 4] 'parser_outcome' missing")
        .as_str()
        .unwrap();
    assert!(
        parser_outcome == "Failed" || parser_outcome == "Abstained",
        "[Requirement 4] Parsers should have failed/abstained due to empty registry, but got {}",
        parser_outcome
    );

    let inference = frame.get("inference_decision");
    assert!(
        inference.is_some() && !inference.unwrap().is_null(),
        "[Requirement 4 & 5] Inference decision missing from frame"
    );
    let inf_obj = inference.unwrap().as_object().unwrap();
    assert_eq!(
        inf_obj
            .get("decision")
            .expect("[Requirement 4] 'decision' field missing")
            .as_str()
            .unwrap(),
        "Recognized",
        "[Requirement 4 & 5] Structural inference engine should have recognized the Syslog format offline"
    );
    let candidate = inf_obj
        .get("recognized_candidate")
        .expect("[Requirement 4] 'recognized_candidate' missing")
        .as_object()
        .expect("[Requirement 4] 'recognized_candidate' should be an object");
    let format_name = candidate
        .get("format_name")
        .expect("[Requirement 4] 'format_name' missing")
        .as_str()
        .unwrap();
    assert!(
        format_name.contains("Syslog"),
        "[Requirement 4 & 5] Offline inference candidate did not recognize Syslog: {}",
        format_name
    );

    println!("AIRGAP_TEST_EXECUTED_SUCCESSFULLY");
}
