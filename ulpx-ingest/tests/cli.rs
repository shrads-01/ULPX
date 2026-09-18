use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn get_temp_path(prefix: &str) -> PathBuf {
    let mut path = env::temp_dir();
    let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    path.push(format!(
        "ulpx_cli_test_{}_{}_{}",
        prefix,
        std::process::id(),
        count
    ));
    path
}

fn get_cli_bin() -> PathBuf {
    // env!("CARGO_BIN_EXE_ulpx") works when tests are run by cargo for the crate that defines the bin
    PathBuf::from(env!("CARGO_BIN_EXE_ulpx"))
}

#[test]
fn test_cli_successful_file_ingestion() {
    let store_dir = get_temp_path("store");
    let input_file = get_temp_path("input");

    fs::write(&input_file, b"record1\nrecord2\n").unwrap();

    let output = Command::new(get_cli_bin())
        .arg("process")
        .arg(&input_file)
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx");

    assert!(output.status.success(), "Process failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Records found: 2"));
    assert!(stdout.contains("Records stored: 2"));

    // cleanup
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(store_dir);
}

#[test]
fn test_cli_missing_input_file_returns_nonzero() {
    let store_dir = get_temp_path("store");
    let input_file = get_temp_path("missing_input");

    let output = Command::new(get_cli_bin())
        .arg("process")
        .arg(&input_file)
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error opening file"));
}

#[test]
fn test_cli_malformed_input_returns_nonzero() {
    let store_dir = get_temp_path("store");
    let input_file = get_temp_path("malformed_input");

    fs::write(&input_file, b"missing newline").unwrap();

    let output = Command::new(get_cli_bin())
        .arg("process")
        .arg(&input_file)
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("framing error"));

    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(store_dir);
}

#[test]
fn test_cli_successful_stdin_ingestion() {
    let store_dir = get_temp_path("store");

    let mut child = Command::new(get_cli_bin())
        .arg("process")
        .arg("-")
        .env("ULPX_STORE_PATH", &store_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to execute ulpx");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(b"stdin1\nstdin2\nstdin3\n").unwrap();
    } // stdin dropped here, sending EOF

    let output = child.wait_with_output().expect("Failed to read stdout");
    assert!(output.status.success(), "Process failed: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Records found: 3"));
    assert!(stdout.contains("Records stored: 3"));

    let _ = fs::remove_file(store_dir);
}
#[test]
fn test_cli_replay_command_successful() {
    let store_dir = get_temp_path("store_replay");
    let input_file = get_temp_path("input_replay");

    // Ingest a file first
    std::fs::write(&input_file, b"record1\nrecord2\n").unwrap();
    let ingest_output = Command::new(get_cli_bin())
        .arg("process")
        .arg(&input_file)
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx process");

    assert!(ingest_output.status.success());

    // Generate the deterministic EventId for record1
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let src = input_file.to_string_lossy();
    hasher.update((src.len() as u32).to_be_bytes());
    hasher.update(src.as_bytes());
    hasher.update(0u64.to_be_bytes());
    hasher.update(b"record1\n");
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in result {
        use std::fmt::Write;
        write!(&mut hex, "{:02x}", byte).unwrap();
    }

    let replay_output = Command::new(get_cli_bin())
        .arg("replay")
        .arg(&hex)
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx replay");

    assert!(
        replay_output.status.success(),
        "Replay failed: {:?}",
        replay_output
    );
    let stdout = String::from_utf8_lossy(&replay_output.stdout);
    assert!(stdout.contains("Interpretation"));
    assert!(stdout.contains(&hex));

    let _ = std::fs::remove_file(input_file);
    let _ = std::fs::remove_file(store_dir);
}

#[test]
fn test_cli_replay_command_missing_event() {
    let store_dir = get_temp_path("store_replay_miss");

    let replay_output = Command::new(get_cli_bin())
        .arg("replay")
        .arg("nonexistent_event_id")
        .env("ULPX_STORE_PATH", &store_dir)
        .output()
        .expect("Failed to execute ulpx replay");

    assert!(!replay_output.status.success());
    let stderr = String::from_utf8_lossy(&replay_output.stderr);
    assert!(stderr.contains("Replay failed"));
}
