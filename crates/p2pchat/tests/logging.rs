//! M0's gate: a `tracing::info!` lands in the log file, and no log line ever
//! reaches stdout or stderr.
//!
//! "Nothing on the terminal" is not the same as "the binary is mute". F-28's
//! subcommands print the value they exist to print, and a fatal startup error
//! before the TUI takes the terminal goes to stderr (agent.md §2). What the
//! gate forbids is *log output* on either stream, because that is what
//! corrupts the display once the TUI is up.

use std::path::PathBuf;
use std::process::{Command, Output};

/// What a `tracing_subscriber::fmt` line looks like: a level, a target, and
/// the message. Any of them on a terminal stream is the failure M0 is about.
const LOG_MARKERS: [&str; 6] = [
    "INFO",
    "WARN",
    "DEBUG",
    "TRACE",
    "p2pchat starting",
    "p2pchat::",
];

fn assert_no_log_output(stream: &str, text: &str) {
    for marker in LOG_MARKERS {
        assert!(
            !text.contains(marker),
            "a log line reached {stream}: {marker:?} in {text:?}"
        );
    }
}

/// Runs the binary with its config and data under `dir`, and hands back what
/// it wrote and where the log went.
fn run(dir: &std::path::Path, level: &str, args: &[&str]) -> (Output, PathBuf) {
    let out = Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", dir.join("config"))
        .env("P2PCHAT_DATA_DIR", dir.join("data"))
        .env("RUST_LOG", level)
        .output()
        .expect("the binary runs");
    (out, dir.join("data"))
}

/// Everything in the log directory, concatenated. Empty when nothing logged.
fn log_body(data_dir: &std::path::Path) -> String {
    std::fs::read_dir(data_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().is_file())
                .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The gate. `whoami` is used because it is a subcommand that runs to
/// completion and prints exactly what F-28 says it prints — so anything else
/// on either stream came from the logger.
#[test]
fn logs_go_to_the_file_and_never_to_a_terminal_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (out, data_dir) = run(dir.path(), "info", &["whoami"]);

    assert!(out.status.success(), "exit status {:?}", out.status);

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_no_log_output("stdout", &stdout);
    assert_no_log_output("stderr", &stderr);
    assert_eq!(stderr, "", "whoami prints to stdout and nowhere else");
    assert!(
        stdout.contains("user id") && stdout.contains("fingerprint"),
        "whoami must still print what F-28 asks for: {stdout:?}"
    );

    // And the line that was kept off the terminal is in the file.
    let body = log_body(&data_dir);
    assert!(body.contains("p2pchat starting"), "log body: {body:?}");
    assert!(body.contains("INFO"), "log body: {body:?}");
}

/// The no-tty launch. `cargo test` gives the child a pipe, so the bare
/// invocation is this path by construction.
#[test]
fn without_a_terminal_it_says_so_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (out, data_dir) = run(dir.path(), "info", &[]);

    assert!(
        !out.status.success(),
        "a launch that cannot draw anything must not report success: {:?}",
        out.status
    );

    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.to_lowercase().contains("terminal"),
        "the reason must say a terminal is required: {stderr:?}"
    );
    assert_eq!(
        stderr.trim().lines().count(),
        1,
        "one line, not a backtrace: {stderr:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "stdout belongs to the subcommands that print a value"
    );
    // The message is not a log line, and the log still went to the file.
    assert_no_log_output("stderr", &stderr);
    assert!(
        log_body(&data_dir).contains("p2pchat starting"),
        "the log guard must flush even on the failing path"
    );
}

/// `RUST_LOG` is honoured: below `info`, the same run logs nothing.
#[test]
fn respects_rust_log() {
    let dir = tempfile::tempdir().unwrap();
    let (out, data_dir) = run(dir.path(), "warn", &["whoami"]);

    assert!(out.status.success());
    let body = log_body(&data_dir);
    assert!(!body.contains("p2pchat starting"), "log body: {body:?}");
}
