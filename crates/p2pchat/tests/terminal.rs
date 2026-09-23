//! M9 gate 9, on a real terminal: `Ctrl-C` and a deliberate panic both leave
//! the tty the way they found it.
//!
//! A `TestBackend` cannot decide this. It has no line discipline, so it cannot
//! say whether raw mode was turned off, and no terminal, so it cannot say
//! whether the alternate screen was left. A pty has both, and `stty` will
//! report on them — so the binary is run as `p2pchat; stty -a` on a pty and
//! the gate is what `stty` says once the process is gone.
//!
//! Unix only: there is no pty on Windows, and CI is Linux.
#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

use rexpect::session::PtySession;

/// Leave the alternate screen — what `terminal::restore` sends, and the thing
/// the pty can see that a unit test cannot.
const LEAVE_ALT: &str = "\x1b[?1049l";

/// Enter it, which is how the test knows the TUI has taken the terminal and
/// there is something to restore.
const ENTER_ALT: &str = "\x1b[?1049h";

/// Generous: the node binds a QUIC socket, opens SQLite and generates a key
/// before the first frame is drawn, and CI machines are slow.
const TIMEOUT: Option<u64> = Some(20_000);

/// `p2pchat` on a pty, with `stty -a` queued behind it in the same shell so
/// that the terminal is interrogated after the process has exited.
///
/// The shell — not the test — reads the tty afterwards, which is the point:
/// whatever the binary did to the terminal is still done when `stty` looks.
fn spawn_on_a_pty(extra: &[(&str, &str)]) -> (PtySession, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("a temporary directory");

    // `stty` twice, for two different reasons. First: rexpect opens the pty
    // with echo off and no window size, and neither is what a person's
    // terminal looks like — with no size ratatui draws into an 80x0 area and
    // with echo already off the gate could not tell a restored terminal from
    // a raw one. Setting them makes the *before* state an ordinary cooked
    // terminal, which is the state the binary has to hand back. Last: the
    // interrogation, after the process is gone.
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "stty rows 24 columns 80 echo; {}; stty -a",
            env!("CARGO_BIN_EXE_p2pchat")
        ))
        .env("P2PCHAT_CONFIG_DIR", dir.path())
        .env("P2PCHAT_DATA_DIR", dir.path())
        // The log is a file (F-29); this only keeps it quiet.
        .env("RUST_LOG", "warn")
        // Loopback, explicitly: the default binds every interface and this
        // gate is about the terminal, not about listening on CI's network.
        .env("P2PCHAT_BIND_ADDR", "127.0.0.1")
        // The panic message is the assertion text, not a backtrace.
        .env("RUST_BACKTRACE", "0");
    for (key, value) in extra {
        command.env(key, value);
    }

    let mut session = rexpect::session::spawn_command(command, TIMEOUT).expect("a pty");
    session
        .exp_string(ENTER_ALT)
        .expect("the TUI takes the alternate screen");
    (session, dir)
}

/// Everything the pty saw, from the first keystroke to end of file.
fn drain(mut session: PtySession) -> String {
    session.exp_eof().expect("the shell exits")
}

/// `stty -a` prints flags as whitespace-separated words, negated ones with a
/// leading `-`. Substrings will not do: `echo` is a prefix of `echoe`,
/// `echok` and `-echonl`, so a `contains("echo")` passes on a terminal that is
/// still raw.
fn flags(stty: &str) -> Vec<&str> {
    stty.split(|c: char| c.is_whitespace() || c == ';')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .collect()
}

/// Everything written after the terminal was *first* restored.
///
/// The first, not the last: a panic restores twice, once from the hook and
/// once from the guard's `Drop` as the stack unwinds. Slicing at the first
/// one is what makes this slice mean "printed on the terminal the user is
/// left with" — the panic message has to be inside it, and so does `stty`.
fn after_restore(output: &str) -> &str {
    let at = output
        .find(LEAVE_ALT)
        .unwrap_or_else(|| panic!("the alternate screen was never left:\n{output:?}"));
    &output[at + LEAVE_ALT.len()..]
}

/// Raw mode off, echo back on, and the tty is a tty again.
fn assert_the_terminal_is_cooked(output: &str) {
    let flags = flags(after_restore(output));

    assert!(
        flags.contains(&"icanon"),
        "the line discipline is still raw (-icanon): {flags:?}"
    );
    assert!(
        !flags.contains(&"-icanon"),
        "the line discipline is still raw: {flags:?}"
    );
    assert!(
        flags.contains(&"echo"),
        "the terminal is not echoing (-echo): {flags:?}"
    );
    assert!(
        !flags.contains(&"-echo"),
        "the terminal is not echoing: {flags:?}"
    );
}

/// F-24: `Ctrl-C` exits cleanly and the shell behind it gets its terminal back.
///
/// In raw mode `ISIG` is off, so this is a keystroke rather than a signal —
/// the TUI's own quit path, which is the one the gate is about.
#[test]
fn ctrl_c_gives_the_terminal_back() {
    let (mut session, _dir) = spawn_on_a_pty(&[]);

    session.send_control('c').expect("Ctrl-C reaches the pty");
    session.flush().expect("the pty takes it");

    let output = drain(session);
    assert_the_terminal_is_cooked(&output);
}

/// F-24 again: a panic restores the terminal *before* printing, or the
/// message lands on the alternate screen and goes with it.
#[test]
fn a_deliberate_panic_gives_the_terminal_back_before_it_prints() {
    let (mut session, _dir) = spawn_on_a_pty(&[("P2PCHAT_PANIC_ON_KEY", "1")]);

    // Any key. The panic is in the loop that reads it.
    session.send("x").expect("a keystroke reaches the pty");
    session.flush().expect("the pty takes it");

    let output = drain(session);
    assert_the_terminal_is_cooked(&output);

    assert!(
        output.contains("deliberate panic"),
        "the process did not panic at all:\n{output:?}"
    );
    assert!(
        after_restore(&output).contains("deliberate panic"),
        "the panic message was printed before the terminal came back, so it \
         went onto the alternate screen and left with it:\n{output:?}"
    );
}

/// The pty harness itself: without it, both tests above would pass against a
/// binary that never took the terminal at all.
#[test]
fn the_tui_really_did_take_the_terminal() {
    let (mut session, _dir) = spawn_on_a_pty(&[]);

    // Drawn by `view::status_bar`, so the screen is up and not merely opened.
    session
        .exp_string("p2pchat")
        .expect("the status bar is drawn");

    std::thread::sleep(Duration::from_millis(100));
    session.send_control('c').expect("Ctrl-C reaches the pty");
    session.flush().expect("the pty takes it");
    drain(session);
}
