use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
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

#[tokio::test]
async fn test_airgap_end_to_end_real_docker() {
    if !is_docker_available() {
        println!("AIRGAP_INTEGRATION_TEST_SKIPPED_DUE_TO_NO_DOCKER");
        return;
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_dir = std::path::Path::new(&manifest_dir).parent().unwrap();
    let compose_path = workspace_dir.join("deploy").join("docker-compose.yml");
    assert!(
        compose_path.exists(),
        "Compose file not found at {:?}",
        compose_path
    );

    let _cleanup = DockerCleanup {
        compose_path: compose_path.clone(),
    };

    // Teardown any left-over state first
    let _ = get_compose_cmd()
        .arg("-f")
        .arg(&compose_path)
        .arg("down")
        .arg("-v")
        .output();

    println!("Building and bringing up docker container (this may take a few minutes)...");
    let status = get_compose_cmd()
        .arg("-f")
        .arg(&compose_path)
        .arg("up")
        .arg("-d")
        .arg("--build")
        .status()
        .expect("Failed to execute docker compose up");
    assert!(status.success(), "Docker compose up failed");

    // VERIFY THE ACTUAL AIR-GAP NETWORK
    let inspect_out = get_docker_cmd()
        .arg("inspect")
        .arg("ulpx_airgap")
        .arg("--format")
        .arg("{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}")
        .output()
        .expect("Failed to inspect container");
    let network_name = String::from_utf8_lossy(&inspect_out.stdout)
        .trim()
        .to_string();
    assert!(
        !network_name.is_empty(),
        "Container is not attached to any network"
    );

    let net_inspect = get_docker_cmd()
        .arg("network")
        .arg("inspect")
        .arg(&network_name)
        .arg("--format")
        .arg("{{.Internal}}")
        .output()
        .expect("Failed to inspect network");
    let is_internal = String::from_utf8_lossy(&net_inspect.stdout)
        .trim()
        .to_string();
    assert_eq!(
        is_internal, "true",
        "Network {} is NOT strictly internal!",
        network_name
    );

    // VERIFY NO RUNTIME INTERNET DEPENDENCY
    // We use rust:1.98 container because it contains `curl`. We assert that the exit code is network failure (e.g. 28 timeout or 6/7 failed to connect).
    let ext_req = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg("--connect-timeout")
        .arg("2")
        .arg("https://1.1.1.1")
        .output()
        .unwrap();

    let exit_code = ext_req.status.code().unwrap_or(-1);
    // Curl exit codes: 28 is timeout, 7 is failed to connect, 6 is couldn't resolve host.
    // An exit code of 127 would mean curl wasn't found (which would falsely pass isolation test).
    assert!(
        exit_code == 28 || exit_code == 7 || exit_code == 6,
        "Curl failed but with unexpected exit code {} (expected network failure 28, 7, or 6). Isolation test inconclusive.",
        exit_code
    );

    // Wait for the server to be ready inside the network
    let mut retries = 120;
    while retries > 0 {
        let check = get_docker_cmd()
            .arg("run")
            .arg("--rm")
            .arg("--network")
            .arg(&network_name)
            .arg("rust:1.98")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://ulpx_airgap:3000/")
            .output()
            .unwrap();
        if String::from_utf8_lossy(&check.stdout).trim() == "200" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
        retries -= 1;
    }
    assert!(retries > 0, "Server in docker did not start in time");

    // VERIFY UI
    let ui_resp = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg("http://ulpx_airgap:3000/")
        .output()
        .expect("Failed to fetch UI root");
    assert!(ui_resp.status.success(), "UI root did not return HTTP 200");
    let html = String::from_utf8_lossy(&ui_resp.stdout);
    assert!(html.contains("<!DOCTYPE html>"), "UI did not return HTML");
    assert!(
        html.contains("events-list"),
        "UI does not contain expected frontend elements"
    );

    // Ingestion
    let test_log = env::temp_dir().join("airgap_test.log");
    let raw_content =
        "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n";
    fs::write(&test_log, raw_content).unwrap();

    let cp_status = get_docker_cmd()
        .arg("cp")
        .arg(&test_log)
        .arg("ulpx_airgap:/tmp/airgap_test.log")
        .status()
        .expect("Failed to docker cp");
    assert!(cp_status.success(), "Failed to copy test log to container");

    let exec_status = get_docker_cmd()
        .arg("exec")
        .arg("ulpx_airgap")
        .arg("sh")
        .arg("-c")
        .arg("ULPX_STORE_PATH=/data/.ulpx_store ulpx process /tmp/airgap_test.log")
        .status()
        .expect("Failed to docker exec ingestion");
    assert!(exec_status.success(), "Docker exec ingestion failed");

    // ULPX_STORE_PATH was modified by `ulpx process`, but `ulpx-serve` reads it on startup.
    // We must restart the container so the server reloads the store.
    let restart_status = get_docker_cmd()
        .arg("restart")
        .arg("ulpx_airgap")
        .status()
        .expect("Failed to restart container");
    assert!(restart_status.success(), "Failed to restart container");

    let mut retries = 120;
    while retries > 0 {
        let check = get_docker_cmd()
            .arg("run")
            .arg("--rm")
            .arg("--network")
            .arg(&network_name)
            .arg("rust:1.98")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://ulpx_airgap:3000/api/v1/events")
            .output()
            .unwrap();
        if String::from_utf8_lossy(&check.stdout).trim() == "200" {
            break;
        }
        sleep(Duration::from_millis(500)).await;
        retries -= 1;
    }
    assert!(
        retries > 0,
        "Server in docker did not start in time after restart"
    );

    // Verify storage API
    let ev_resp = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg("http://ulpx_airgap:3000/api/v1/events")
        .output()
        .expect("Failed to fetch events");
    assert!(ev_resp.status.success());

    let json: serde_json::Value = serde_json::from_slice(&ev_resp.stdout).unwrap();
    let events = json.get("events").unwrap().as_array().unwrap();
    assert_eq!(events.len(), 1, "Expected exactly 1 event ingested");
    let event_id = events[0].get("event_id").unwrap().as_str().unwrap();

    // VERIFY STORAGE SEPARATELY (Fetch raw evidence bytes)
    let ev_raw_resp = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg(format!(
            "http://ulpx_airgap:3000/api/v1/evidence/{}",
            event_id
        ))
        .output()
        .expect("Failed to fetch raw evidence");
    assert!(ev_raw_resp.status.success());

    let raw_json: serde_json::Value = serde_json::from_slice(&ev_raw_resp.stdout).unwrap();
    use base64::{engine::general_purpose, Engine as _};
    let b64_payload = raw_json.get("payload_base64").unwrap().as_str().unwrap();
    let decoded = general_purpose::STANDARD.decode(b64_payload).unwrap();

    // Directly compare decoded bytes to the original bytes!
    assert_eq!(
        decoded,
        raw_content.as_bytes(),
        "Stored raw bytes do not match original evidence"
    );

    // RESTART CONTAINER AND VERIFY STORAGE PERSISTENCE AGAIN
    let restart_status_2 = get_docker_cmd()
        .arg("restart")
        .arg("ulpx_airgap")
        .status()
        .expect("Failed to restart container second time");
    assert!(
        restart_status_2.success(),
        "Failed to restart container second time"
    );

    // Wait for server to come back up
    let mut retries_2 = 120;
    while retries_2 > 0 {
        let check = get_docker_cmd()
            .arg("run")
            .arg("--rm")
            .arg("--network")
            .arg(&network_name)
            .arg("rust:1.98")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://ulpx_airgap:3000/")
            .output()
            .expect("Failed to run health check curl");
        if check.status.success() {
            let code = String::from_utf8_lossy(&check.stdout);
            if code == "200" {
                break;
            }
        }
        sleep(Duration::from_millis(500)).await;
        retries_2 -= 1;
    }
    assert!(
        retries_2 > 0,
        "Server did not restart successfully the second time"
    );

    let ev_raw_resp_2 = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg(format!(
            "http://ulpx_airgap:3000/api/v1/evidence/{}",
            event_id
        ))
        .output()
        .expect("Failed to fetch raw evidence after restart");
    assert!(
        ev_raw_resp_2.status.success(),
        "Failed to fetch evidence after restart"
    );

    let raw_json_2: serde_json::Value = serde_json::from_slice(&ev_raw_resp_2.stdout).unwrap();
    let b64_payload_2 = raw_json_2.get("payload_base64").unwrap().as_str().unwrap();
    let decoded_2 = general_purpose::STANDARD.decode(b64_payload_2).unwrap();

    // Directly compare decoded bytes again
    assert_eq!(
        decoded_2,
        raw_content.as_bytes(),
        "Stored raw bytes do not match original evidence AFTER RESTART (Persistence failed)"
    );

    // VERIFY INFERENCE AND PARSING
    // PATH A: KNOWN PARSER PATH
    // We send a replay with "syslog" in the registry. It should parse successfully.
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
    fs::write(&known_payload_file, known_replay_req.to_string()).unwrap();

    let known_replay_resp = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("-v")
        .arg(format!("{}:/payload.json", known_payload_file.display()))
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg("@/payload.json")
        .arg("http://ulpx_airgap:3000/api/v1/replay")
        .output()
        .expect("Failed to replay event (Known path)");

    assert!(
        known_replay_resp.status.success(),
        "Known Replay request failed"
    );
    let known_replay_json: serde_json::Value =
        match serde_json::from_slice(&known_replay_resp.stdout) {
            Ok(v) => v,
            Err(e) => {
                panic!(
                    "Failed to parse JSON from known replay. Error: {}. Stdout: {}",
                    e,
                    String::from_utf8_lossy(&known_replay_resp.stdout)
                );
            }
        };

    let known_frames = known_replay_json.get("frames").unwrap().as_array().unwrap();
    assert!(
        !known_frames.is_empty(),
        "No frames returned in known replay"
    );
    let known_frame = &known_frames[0];

    // VERIFY PARSING WAS SUCCESSFUL
    let known_parser_outcome = known_frame.get("parser_outcome").unwrap().as_str().unwrap();
    assert_eq!(
        known_parser_outcome, "Success",
        "Parser should have succeeded for syslog, got {}",
        known_parser_outcome
    );

    let ir_event = known_frame.get("ir_event");
    assert!(
        ir_event.is_some() && !ir_event.unwrap().is_null(),
        "IR Event missing on successful parse"
    );
    let canonical = known_frame.get("canonical_event");
    assert!(
        canonical.is_some() && !canonical.unwrap().is_null(),
        "Canonical Event missing on successful parse"
    );

    // PATH B: UNKNOWN PARSER PATH (INFERENCE)
    // We intentionally leave parser_registry EMPTY so that parsers will abstain,
    // forcing the semantic inference engine to trigger and recognize the Syslog format.
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
    fs::write(&payload_file, replay_req.to_string()).unwrap();

    let replay_resp = get_docker_cmd()
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg(&network_name)
        .arg("-v")
        .arg(format!("{}:/payload.json", payload_file.display()))
        .arg("rust:1.98")
        .arg("curl")
        .arg("-s")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg("@/payload.json")
        .arg("http://ulpx_airgap:3000/api/v1/replay")
        .output()
        .expect("Failed to replay event");

    assert!(replay_resp.status.success(), "Replay request failed");
    let replay_json: serde_json::Value = match serde_json::from_slice(&replay_resp.stdout) {
        Ok(v) => v,
        Err(e) => {
            panic!(
                "Failed to parse JSON from inference replay. Error: {}. Stdout: {}",
                e,
                String::from_utf8_lossy(&replay_resp.stdout)
            );
        }
    };

    let frames = replay_json.get("frames").unwrap().as_array().unwrap();
    assert!(!frames.is_empty(), "No frames returned in replay");
    let frame = &frames[0];

    // VERIFY PARSING SEPARATELY
    let parser_outcome = frame.get("parser_outcome").unwrap().as_str().unwrap();
    assert!(
        parser_outcome == "Failed" || parser_outcome == "Abstained",
        "Parsers should have failed/abstained due to empty registry, but got {}",
        parser_outcome
    );

    // VERIFY INFERENCE
    let inference = frame.get("inference_decision");
    assert!(
        inference.is_some() && !inference.unwrap().is_null(),
        "Inference decision missing"
    );
    let inf_obj = inference.unwrap().as_object().unwrap();
    assert_eq!(
        inf_obj.get("decision").unwrap().as_str().unwrap(),
        "Recognized",
        "Inference should have recognized the Syslog format"
    );
    let candidate = inf_obj
        .get("recognized_candidate")
        .unwrap()
        .as_object()
        .unwrap();
    let format_name = candidate.get("format_name").unwrap().as_str().unwrap();
    assert!(
        format_name.contains("Syslog"),
        "Inference did not recognize Syslog: {}",
        format_name
    );

    println!("AIRGAP_TEST_EXECUTED_SUCCESSFULLY");
}
