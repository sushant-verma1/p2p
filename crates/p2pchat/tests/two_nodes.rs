//! M8's gates 1 and 4, and M8a's gate 3: processes, driven through the debug
//! CLI.
//!
//! These are the reason the CLI is line-oriented. Gate 4 in particular cannot
//! be done in one process — the property is about what survives a process that
//! is *killed*, and a task that is dropped is not that. M8a's restart is here
//! for the same reason: a `Node` has no shutdown, so a node "restarted" in one
//! process would still be listening on the old endpoint.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Long enough for a loopback exchange on a loaded machine.
const PATIENCE: Duration = Duration::from_secs(20);

/// Gate 1's count, from plan.md.
const MESSAGES: usize = 100;

// ---------------------------------------------------------------------------
// Driving a node through a pipe
// ---------------------------------------------------------------------------

struct Driver {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    dir: tempfile::TempDir,
    user_id: String,
    addr: String,
}

/// Starts `p2pchat node` in its own config and data directory.
///
/// `commit_pause` widens §11's window between the store commit and the ACK, so
/// that gate 4 can land a kill inside it. Unset, it is zero and the process
/// behaves exactly as a shipped one does.
async fn start(commit_pause: Option<u64>) -> Driver {
    start_in(
        tempfile::tempdir().expect("a temporary directory"),
        commit_pause,
    )
    .await
}

/// The same, on directories that already exist — a restart.
async fn start_in(dir: tempfile::TempDir, commit_pause: Option<u64>) -> Driver {
    let mut command = Command::new(env!("CARGO_BIN_EXE_p2pchat"));
    command
        .arg("node")
        // Loopback, explicitly: the binary's default is every interface, and a
        // test has no business opening a port on the interfaces of whatever
        // machine CI is running on. M9c's own gates are the exception.
        .arg("--bind")
        .arg("127.0.0.1")
        // M9d: accepting a peer needs an address to tell them to dial, and
        // these nodes accept each other. Loopback, to match the bind.
        .arg("--addr")
        .arg("127.0.0.1:0")
        .env("P2PCHAT_CONFIG_DIR", dir.path().join("config"))
        .env("P2PCHAT_DATA_DIR", dir.path().join("data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    if let Some(ms) = commit_pause {
        command.env("P2PCHAT_DEBUG_COMMIT_PAUSE_MS", ms.to_string());
    }

    let mut child = command.spawn().expect("the binary runs");
    let stdin = child.stdin.take().expect("a pipe to stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("a pipe from stdout")).lines();

    let ready = next_line(&mut stdout).await;
    let fields: Vec<&str> = ready.split('\t').collect();
    assert_eq!(
        fields.first(),
        Some(&"ready"),
        "unexpected first line: {ready}"
    );

    Driver {
        child,
        stdin,
        stdout,
        user_id: fields[1].to_owned(),
        addr: fields[2].to_owned(),
        dir,
    }
}

async fn next_line(stdout: &mut Lines<BufReader<ChildStdout>>) -> String {
    tokio::time::timeout(PATIENCE, stdout.next_line())
        .await
        .expect("a line before the deadline")
        .expect("stdout is readable")
        .expect("the node is still running")
}

impl Driver {
    async fn tell(&mut self, line: &str) {
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .await
            .expect("the node is still reading");
    }

    async fn line(&mut self) -> Vec<String> {
        next_line(&mut self.stdout)
            .await
            .split('\t')
            .map(str::to_owned)
            .collect()
    }

    /// The next line whose first two fields are these, skipping the rest.
    async fn expect(&mut self, kind: &str, tag: &str) -> Vec<String> {
        loop {
            let fields = self.line().await;
            if fields.first().is_some_and(|f| f == kind) && fields.get(1).is_some_and(|f| f == tag)
            {
                return fields;
            }
            assert_ne!(
                fields.first().map(String::as_str),
                Some("err"),
                "{fields:?}"
            );
        }
    }

    /// The stored conversation with `peer`, read by a second process.
    ///
    /// Rows are `msg_seq, status, sender, message_id, body`.
    fn history(&self, peer: &str) -> Vec<Vec<String>> {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_p2pchat"))
            .arg("history")
            .arg(peer)
            .env("P2PCHAT_CONFIG_DIR", self.dir.path().join("config"))
            .env("P2PCHAT_DATA_DIR", self.dir.path().join("data"))
            .output()
            .expect("the binary runs");

        assert!(
            output.status.success(),
            "history failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.split('\t').map(str::to_owned).collect())
            .collect()
    }

    /// Asks the node to stop and waits for the process to be gone, so that
    /// [`Driver::history`] reads a database nobody holds.
    async fn quit(&mut self) {
        let _ = self.stdin.write_all(b"quit\n").await;
        let _ = tokio::time::timeout(PATIENCE, self.child.wait()).await;
    }

    async fn kill(&mut self) {
        self.child.start_kill().expect("the process can be killed");
        let _ = tokio::time::timeout(PATIENCE, self.child.wait()).await;
    }

    /// The user's decision about a peer — §10, F-06.
    async fn accept(&mut self, peer: &str) {
        self.tell(&format!("accept {peer}")).await;
        self.expect("ok", "accept").await;
    }

    /// Stops this process and starts another on the same directories: the same
    /// identity, the same database, a new port.
    async fn restart(mut self) -> Driver {
        self.quit().await;
        let (dir, was) = (self.dir, self.user_id);
        let restarted = start_in(dir, None).await;
        assert_eq!(restarted.user_id, was, "the restart changed identity");
        restarted
    }
}

// ---------------------------------------------------------------------------
// Gate 1
// ---------------------------------------------------------------------------

/// A hundred messages, one session, both stores agreeing at the end.
#[tokio::test(flavor = "multi_thread")]
async fn a_hundred_messages_arrive_once_each_in_order() {
    let mut receiver = start(None).await;
    let mut sender = start(None).await;

    // §10: each side lets the other in first. Over an invite this is the user
    // reading a fingerprint; here it is one line each.
    receiver.accept(&sender.user_id).await;
    sender.accept(&receiver.user_id).await;

    let dial = format!("connect {} {}", receiver.addr, receiver.user_id);
    sender.tell(&dial).await;
    sender.expect("ok", "connect").await;

    for n in 0..MESSAGES {
        sender
            .tell(&format!("send {} message {n}", receiver.user_id))
            .await;
    }

    // The receiving side: one arrival per message, numbered from one, in the
    // order they were sent.
    let mut bodies = Vec::new();
    let mut ids = Vec::new();
    while bodies.len() < MESSAGES {
        let fields = receiver.line().await;
        if fields.first().is_some_and(|f| f == "event") && fields[1] == "recv" {
            ids.push(fields[3].clone());
            assert_eq!(
                fields[4],
                (bodies.len() + 1).to_string(),
                "msg_seq is out of order"
            );
            bodies.push(fields[5].clone());
        }
    }

    let expected: Vec<String> = (0..MESSAGES).map(|n| format!("message {n}")).collect();
    assert_eq!(bodies, expected, "messages arrived out of order");

    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), MESSAGES, "a message arrived twice");

    // The sending side: §11's two transitions, `SENT` on the socket write and
    // `DELIVERED` on the peer's ACK, in that order for every message.
    let mut sent = Vec::new();
    let mut delivered = Vec::new();
    while delivered.len() < MESSAGES {
        let fields = sender.line().await;
        if fields.first().is_none_or(|f| f != "event") {
            continue;
        }
        match fields[1].as_str() {
            "sent" => sent.push(fields[2].clone()),
            "delivered" => {
                assert!(
                    sent.contains(&fields[2]),
                    "a message was DELIVERED before it was SENT"
                );
                assert_eq!(fields[3], "Delivered");
                delivered.push(fields[2].clone());
            }
            _ => {}
        }
    }
    assert_eq!(
        sent, ids,
        "the sender wrote different messages than arrived"
    );
    assert_eq!(delivered.len(), MESSAGES);

    let sender_id = sender.user_id.clone();
    let receiver_id = receiver.user_id.clone();

    // And the two stores agree, once both processes are gone.
    sender.quit().await;
    receiver.quit().await;
    let sent_rows = sender.history(&receiver_id);
    let received_rows = receiver.history(&sender_id);

    assert_eq!(sent_rows.len(), MESSAGES, "the sender stored every message");
    assert_eq!(
        received_rows.len(),
        MESSAGES,
        "the receiver stored every message exactly once"
    );
    for (n, row) in received_rows.iter().enumerate() {
        assert_eq!(row[1], "Delivered");
        assert_eq!(row[4], format!("message {n}"));
    }
    for row in &sent_rows {
        assert_eq!(row[1], "Delivered", "every ACK was applied");
    }
}

// ---------------------------------------------------------------------------
// Gate 4
// ---------------------------------------------------------------------------

/// A killed receiver leaves the two stores consistent in the direction that
/// matters: **a message the sender marked `DELIVERED` exists on the receiver.**
///
/// The other direction is allowed to disagree — a message stored and then lost
/// with its ACK is simply not delivered yet, and M10's resync is what fixes
/// that. This is the direction that loses a message.
///
/// The kill lands at several points, including inside §11's window between the
/// store commit and the ACK, which `P2PCHAT_DEBUG_COMMIT_PAUSE_MS` widens to
/// something a test can aim at.
#[tokio::test(flavor = "multi_thread")]
async fn a_killed_receiver_never_leaves_a_delivered_message_unstored() {
    // (commit pause, how long to let the conversation run before the kill).
    const ROUNDS: [(u64, u64); 6] = [
        (0, 0),     // during the handshake or the first frames
        (0, 40),    // mid-stream, no window widening at all
        (150, 0),   // before anything has been stored
        (150, 200), // inside the first message's commit-to-ACK window
        (150, 700), // inside a later one, several messages in
        (400, 900), // a wide window, well into the conversation
    ];
    const PER_ROUND: usize = 20;

    let mut total_delivered = 0usize;
    let mut cut_short = false;

    for (round, (pause, run_for)) in ROUNDS.iter().enumerate() {
        let mut receiver = start(Some(*pause)).await;
        let mut sender = start(None).await;

        receiver.accept(&sender.user_id).await;
        sender.accept(&receiver.user_id).await;

        let dial = format!("connect {} {}", receiver.addr, receiver.user_id);
        sender.tell(&dial).await;
        sender.expect("ok", "connect").await;

        for n in 0..PER_ROUND {
            sender
                .tell(&format!(
                    "send {} round {round} message {n}",
                    receiver.user_id
                ))
                .await;
        }

        tokio::time::sleep(Duration::from_millis(*run_for)).await;
        receiver.kill().await;

        let sender_id = sender.user_id.clone();
        let receiver_id = receiver.user_id.clone();
        sender.quit().await;

        let sent_rows = sender.history(&receiver_id);
        let received_rows = receiver.history(&sender_id);

        let stored: std::collections::BTreeSet<&String> =
            received_rows.iter().map(|row| &row[3]).collect();
        let delivered: Vec<&Vec<String>> = sent_rows
            .iter()
            .filter(|row| row[1] == "Delivered" && row[2] == sender_id)
            .collect();

        for row in &delivered {
            assert!(
                stored.contains(&row[3]),
                "round {round}: {} is DELIVERED on the sender and absent from the receiver",
                row[4]
            );
        }

        total_delivered += delivered.len();
        cut_short |= received_rows.len() < PER_ROUND;
    }

    // Without these the property above is satisfied by delivering nothing and
    // by never actually interrupting anything.
    assert!(
        total_delivered > 0,
        "no message was ever delivered, so the property was vacuous"
    );
    assert!(
        cut_short,
        "no round was interrupted mid-conversation, so nothing was tested"
    );
}

// ---------------------------------------------------------------------------
// M8a gate 3
// ---------------------------------------------------------------------------

/// Acceptance outlives the process that granted it, so a peer that was let in
/// once does not have to ask again — F-06 would be unusable otherwise, since
/// every restart would drop every peer back behind the queue.
///
/// Both sides restart: the answering node's acceptance is what lets the session
/// in, and the dialling node's is what lets it dial at all.
#[tokio::test(flavor = "multi_thread")]
async fn acceptance_survives_a_restart_and_the_peer_reconnects() {
    let mut receiver = start(None).await;
    let mut sender = start(None).await;
    let (sender_id, receiver_id) = (sender.user_id.clone(), receiver.user_id.clone());

    receiver.accept(&sender_id).await;
    sender.accept(&receiver_id).await;

    sender
        .tell(&format!("connect {} {receiver_id}", receiver.addr))
        .await;
    sender.expect("ok", "connect").await;
    sender
        .tell(&format!("send {receiver_id} before the restart"))
        .await;
    let first = receiver.expect("event", "recv").await;
    assert_eq!(first[5], "before the restart");

    let mut receiver = receiver.restart().await;
    let mut sender = sender.restart().await;

    // The decision is in the database, not in the process that made it.
    receiver.tell("peers").await;
    let summary = receiver.expect("ok", "peers").await;
    assert_eq!(summary[2], "1 peers", "{summary:?}");
    let row = receiver.line().await;
    assert_eq!(row[0], sender_id);
    assert_eq!(row[3], "accepted", "the acceptance did not survive");

    // A plain reconnect: no second request, no second accept, and the new
    // address is the only thing that changed.
    sender
        .tell(&format!("connect {} {receiver_id}", receiver.addr))
        .await;
    sender.expect("ok", "connect").await;
    sender
        .tell(&format!("send {receiver_id} after the restart"))
        .await;
    let second = receiver.expect("event", "recv").await;
    assert_eq!(second[5], "after the restart");

    // And it is one conversation across the two sessions rather than two.
    receiver.quit().await;
    let rows = receiver.history(&sender_id);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0][4], "before the restart");
    assert_eq!(rows[1][4], "after the restart");
}
