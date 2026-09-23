//! M12: `p2pchat check` shows a misconfiguration before anyone dials it.
//!
//! What it cannot show is whether the outside reaches this host, and neither
//! can these tests: that is the real-network run, which is the user's.

use std::net::UdpSocket;
use std::process::{Command, Output};

/// Runs `p2pchat check` in a throwaway directory, with none of the
/// environment overrides a developer's shell might carry.
fn check(args: &[&str]) -> (Output, String) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .arg("check")
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", dir.path().join("config"))
        .env("P2PCHAT_DATA_DIR", dir.path().join("data"))
        .env_remove("P2PCHAT_ADDR")
        .env_remove("P2PCHAT_PRIVATE_ADDR")
        .env_remove("P2PCHAT_BIND_ADDR")
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output, stdout)
}

/// A port free a moment ago. Racy in principle; a collision fails loudly as a
/// bind error rather than passing for the wrong reason.
fn free_port() -> u16 {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.local_addr())
        .expect("a free port")
        .port()
}

/// The three mistakes M12 expects first: a CGNAT address, an advertised port
/// that is not the bound one, and a private port the OS picks anew each run.
#[test]
fn a_misconfigured_node_is_flagged_before_anyone_dials_it() {
    let (output, stdout) = check(&["--addr", "100.64.1.2:47100", "--public-port", "0"]);

    assert!(
        !output.status.success(),
        "problems must fail the check:\n{stdout}"
    );
    for needle in [
        "private  bound 0.0.0.0:",
        "advertised 100.64.1.2:47100",
        "carrier-grade NAT",
        "advertises port 47100 but the public endpoint is on",
        "--private-port is 0",
        "UDP, not TCP",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
}

#[test]
fn a_correct_node_passes_and_names_the_ports_to_open() {
    let (public, private) = (free_port(), free_port());
    let addr = format!("203.0.113.9:{public}");
    let (output, stdout) = check(&[
        "--addr",
        &addr,
        "--public-port",
        &public.to_string(),
        "--private-port",
        &private.to_string(),
    ]);

    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!stdout.contains("problem"), "{stdout}");
    assert!(
        stdout.contains(&format!("advertised 203.0.113.9:{private}")),
        "the private address is derived from --addr and the bound port:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("UDP {public}, UDP {private}")),
        "{stdout}"
    );
}
