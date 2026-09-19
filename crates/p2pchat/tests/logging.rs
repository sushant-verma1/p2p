//! M0 gate, parts 2 and 3: a `tracing::info!` lands in the log file, and the
//! binary writes nothing to stdout or stderr.

use std::process::Command;

#[test]
fn logs_to_file_and_says_nothing_on_the_terminal() {
    let data_dir = tempfile::tempdir().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .env("P2PCHAT_DATA_DIR", data_dir.path())
        .env("RUST_LOG", "info")
        .output()
        .unwrap();

    assert!(out.status.success(), "exit status {:?}", out.status);
    assert_eq!(
        out.stdout,
        b"",
        "stdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        out.stderr,
        b"",
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    let logs: Vec<_> = std::fs::read_dir(data_dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(logs.len(), 1, "expected one log file, found {logs:?}");

    let body = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(body.contains("p2pchat starting"), "log body: {body:?}");
    assert!(body.contains("INFO"), "log body: {body:?}");
}

/// `RUST_LOG` is honoured: below `info`, the same run logs nothing.
#[test]
fn respects_rust_log() {
    let data_dir = tempfile::tempdir().unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .env("P2PCHAT_DATA_DIR", data_dir.path())
        .env("RUST_LOG", "warn")
        .output()
        .unwrap();

    assert!(out.status.success());
    let body: String = std::fs::read_dir(data_dir.path())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(!body.contains("p2pchat starting"), "log body: {body:?}");
}
