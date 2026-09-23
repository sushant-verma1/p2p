//! M7 gate, through the real binary: the invite is one pasteable line, and it
//! carries the identity `whoami` prints — F-04, F-28.

use std::path::Path;
use std::process::{Command, Output};

use p2pchat_crypto::invite;

fn run(config_dir: &Path, data_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_p2pchat"))
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", config_dir)
        .env("P2PCHAT_DATA_DIR", data_dir)
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}

#[test]
fn the_invite_is_one_line_that_carries_this_nodes_identity() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();

    let out = run(
        config.path(),
        data.path(),
        &["invite", "--name", "ada", "--addr", "203.0.113.4:47100"],
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(out.stderr, b"", "the blob must be the only output");

    let printed = String::from_utf8(out.stdout).unwrap();
    let blob = printed.trim_end_matches('\n');
    assert!(!blob.contains('\n'), "more than one line: {printed:?}");
    assert!(blob.starts_with(invite::SCHEME), "{blob}");
    // F-04: short enough to paste into a chat message without wrapping.
    assert!(blob.len() < 300, "{} chars", blob.len());

    let parsed = invite::parse(blob, invite::now()).unwrap();
    assert_eq!(parsed.body.display_name, "ada");
    assert_eq!(
        parsed.body.addrs,
        vec!["203.0.113.4:47100".parse().unwrap()]
    );

    // The same key `whoami` reports, or the fingerprint the recipient compares
    // out of band is a fingerprint of something else.
    let whoami = run(config.path(), data.path(), &["whoami"]);
    let printed = String::from_utf8(whoami.stdout).unwrap();
    let hex = printed
        .lines()
        .find_map(|l| l.strip_prefix("user id "))
        .unwrap()
        .trim();
    assert_eq!(parsed.body.user_id.to_hex(), hex);
}

/// A name past `MAX_DISPLAY_NAME` is refused at the point of creation rather
/// than emitted and refused by every recipient — §3's bounds are outbound too.
#[test]
fn an_over_long_name_fails_rather_than_printing_a_blob() {
    let config = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let long = "n".repeat(p2pchat_core::wire::MAX_DISPLAY_NAME + 1);

    let out = run(config.path(), data.path(), &["invite", "--name", &long]);

    assert!(!out.status.success(), "{out:?}");
    assert_eq!(out.stdout, b"");
}
