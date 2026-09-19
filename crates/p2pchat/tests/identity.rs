//! M1 gate, through the real binary: two runs produce the same user ID, and the
//! key file is created with the permissions `architecture.md` §4 requires.

use std::path::Path;
use std::process::{Command, Output};

fn whoami(config_dir: &Path, data_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .arg("whoami")
        .env("P2PCHAT_CONFIG_DIR", config_dir)
        .env("P2PCHAT_DATA_DIR", data_dir)
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}

#[test]
fn two_runs_produce_an_identical_user_id() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();

    let first = whoami(config.path(), data.path());
    let second = whoami(config.path(), data.path());

    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, b"");
    assert_eq!(second.stderr, b"");

    let printed = String::from_utf8(first.stdout).unwrap();
    let hex = printed
        .lines()
        .find_map(|l| l.strip_prefix("user id     "))
        .unwrap();
    assert_eq!(hex.len(), 64);

    // F-02: the fingerprint is the first 16 hex chars in groups of four.
    let fingerprint = printed
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint "))
        .unwrap();
    assert_eq!(fingerprint, {
        let h = &hex[..16];
        format!("{} {} {} {}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
    });
}

/// The full ID belongs on the profile screen, never in the log — agent.md §2.
#[test]
fn the_log_holds_the_fingerprint_and_not_the_full_id() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();

    let out = whoami(config.path(), data.path());
    let printed = String::from_utf8(out.stdout).unwrap();
    let hex = printed
        .lines()
        .find_map(|l| l.strip_prefix("user id     "))
        .unwrap();

    let log: String = std::fs::read_dir(data.path())
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();

    assert!(log.contains("loaded identity"), "log: {log}");
    assert!(!log.contains(hex), "log leaked the full user id: {log}");
}

#[cfg(unix)]
#[test]
fn a_wider_key_file_stops_the_binary() {
    use std::os::unix::fs::PermissionsExt;

    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    assert!(whoami(config.path(), data.path()).status.success());

    let key = config.path().join("identity.key");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o7777,
        0o600
    );

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let out = whoami(config.path(), data.path());
    assert!(!out.status.success(), "binary started anyway");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("chmod 600"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Where the permission check cannot run, the user is told — OD-2.
#[cfg(not(unix))]
#[test]
fn an_unverifiable_platform_says_so() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();

    let out = whoami(config.path(), data.path());
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("permissions are not verified"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
