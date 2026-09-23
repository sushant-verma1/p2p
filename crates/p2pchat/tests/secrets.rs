//! F-29's second half: an end-to-end run must leave no secret in the log.
//!
//! The log is captured in-process rather than read off disk, because the
//! interesting secrets are the ones only the running code knows. A raw dial
//! into a node hands the test the very `Session` that node derived, so the
//! shared secret and both directional keys are known values here and can be
//! searched for like any other string. Everything else — the two identity
//! seeds, the two full user IDs, the message bodies — the test chooses or
//! reads from disk.
//!
//! Fingerprints are permitted and the log is full of them; the final phase
//! proves the scan would have caught each secret had it been logged, so a
//! clean result in phase two means something.

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hkdf::Hkdf;
use p2pchat::{Config, Event, Node};
use p2pchat_core::UserId;
use p2pchat_crypto::session::SESSION_INFO;
use p2pchat_crypto::Identity;
use p2pchat_net::{client_endpoint, connect, handshake, NodeKind};
use sha2::Sha256;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

const PATIENCE: Duration = Duration::from_secs(10);

/// Distinctive enough that a substring hit is the message and not a coincidence.
const BODY_A: &str = "kumquat-rampart-19 the body from A";
const BODY_B: &str = "sundial-mongoose-44 the body from B";

// ---------------------------------------------------------------------------
// Capturing every log line the process emits
// ---------------------------------------------------------------------------

/// A `MakeWriter` that keeps everything written to it.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("the capture lock").clone()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// One secret and every rendering of it a log line could plausibly carry.
struct Secret {
    what: String,
    bytes: Vec<u8>,
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

impl Secret {
    fn new(what: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            what: what.into(),
            bytes: bytes.into(),
        }
    }

    /// Text forms. Searched against the log decoded as UTF-8.
    fn renderings(&self) -> Vec<(&'static str, String)> {
        vec![
            ("lowercase hex", hex(&self.bytes, false)),
            ("uppercase hex", hex(&self.bytes, true)),
            ("base64", STANDARD.encode(&self.bytes)),
            ("base64url", URL_SAFE_NO_PAD.encode(&self.bytes)),
            // What `{:?}` on a byte slice prints — the accidental `?key`.
            ("debug byte slice", format!("{:?}", self.bytes)),
        ]
    }
}

/// Every hit, named. Empty means the log is clean.
///
/// The raw bytes are searched for in the log's bytes and the text forms in its
/// text, so a secret written straight through a `Write` is caught as well as
/// one that was formatted.
fn scan(log: &[u8], secrets: &[Secret]) -> Vec<String> {
    let text = String::from_utf8_lossy(log);
    let mut hits = Vec::new();

    for secret in secrets {
        if !secret.bytes.is_empty()
            && log
                .windows(secret.bytes.len())
                .any(|window| window == secret.bytes)
        {
            hits.push(format!("{} appears in the log as raw bytes", secret.what));
        }
        for (form, rendered) in secret.renderings() {
            if text.contains(&rendered) {
                hits.push(format!("{} appears in the log as {form}", secret.what));
            }
        }
    }

    hits
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

struct TestNode {
    node: Arc<Node>,
    events: Receiver<Event>,
    dir: tempfile::TempDir,
}

async fn node() -> TestNode {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (node, events) = Node::start(Config {
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        private_bind: "127.0.0.1:0".parse().expect("a literal address"),
        public_bind: None,
        advertise: Vec::new(),
        private_advertise: None,
        display_name: "test".to_owned(),
    })
    .await
    .expect("the node starts");

    TestNode { node, events, dir }
}

impl TestNode {
    fn addr(&self) -> SocketAddr {
        self.node.private_addr().expect("a bound address")
    }

    /// The 32-byte seed as it sits on disk — the one secret with a file.
    fn seed(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("config").join("identity.key"))
            .expect("the identity file exists")
    }

    async fn accept(&self, peer: UserId) {
        self.node
            .store
            .resolve_request(peer, true)
            .await
            .expect("the store answers");
    }

    /// Waits for a message body to arrive, ignoring everything else.
    async fn receives(&mut self, body: &str) {
        tokio::time::timeout(PATIENCE, async {
            while let Some(event) = self.events.recv().await {
                if let Event::Received { body: got, .. } = event {
                    if got == body {
                        return;
                    }
                }
            }
            panic!("the node stopped before the message arrived");
        })
        .await
        .expect("the message arrives in time");
    }
}

/// `architecture.md` §7's HKDF, recomputed from the values the handshake hands
/// back. The first two 32-byte blocks are the directional keys; the third is
/// the session id, which is public and deliberately not scanned for.
fn session_keys(shared_secret: &[u8; 32], transcript_hash: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut okm = [0u8; 96];
    Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret)
        .expand(SESSION_INFO, &mut okm)
        .expect("96 bytes is within HKDF's limit");
    (okm[..32].to_vec(), okm[32..64].to_vec())
}

/// F-29. One test rather than three, because the subscriber is global and the
/// capture buffer is shared: separate tests would interleave.
#[tokio::test(flavor = "multi_thread")]
async fn no_secret_reaches_the_log() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("trace"))
        .with_ansi(false)
        .with_writer(capture.clone())
        .init();

    let mut secrets = Vec::new();

    // Phase 1: two nodes, a session, and a message each way.
    let mut a = node().await;
    let mut b = node().await;
    a.accept(b.node.me).await;
    b.accept(a.node.me).await;

    a.node
        .dial(b.addr(), Some(b.node.me))
        .await
        .expect("the dial succeeds");
    a.node
        .send(b.node.me, BODY_A.to_owned())
        .await
        .expect("the send succeeds");
    b.receives(BODY_A).await;
    b.node
        .send(a.node.me, BODY_B.to_owned())
        .await
        .expect("the send succeeds");
    a.receives(BODY_B).await;

    secrets.push(Secret::new("node A's identity seed", a.seed()));
    secrets.push(Secret::new("node B's identity seed", b.seed()));
    secrets.push(Secret::new(
        "node A's full user id",
        a.node.me.as_bytes().to_vec(),
    ));
    secrets.push(Secret::new(
        "node B's full user id",
        b.node.me.as_bytes().to_vec(),
    ));
    secrets.push(Secret::new(
        "A's message plaintext",
        BODY_A.as_bytes().to_vec(),
    ));
    secrets.push(Secret::new(
        "B's message plaintext",
        BODY_B.as_bytes().to_vec(),
    ));

    // Phase 2: a dial the test drives itself, so that the session keys node A
    // derived are known here. Same code path, same log, known secrets.
    let peer = Identity::generate();
    a.accept(peer.user_id()).await;
    let endpoint = client_endpoint(NodeKind::Private).expect("a client endpoint");
    let connection = connect(&endpoint, a.addr())
        .await
        .expect("the dial succeeds");
    let established = handshake::initiate(&connection, &peer, Some(a.node.me))
        .await
        .expect("the handshake succeeds");
    let shared_secret = **established.session.shared_secret();
    let (k_i2r, k_r2i) = session_keys(&shared_secret, established.session.transcript_hash());

    secrets.push(Secret::new(
        "the X25519 shared secret",
        shared_secret.to_vec(),
    ));
    secrets.push(Secret::new("session key k_i2r", k_i2r));
    secrets.push(Secret::new("session key k_r2i", k_r2i));

    // The scan is only worth something over a log that has something in it.
    let log = capture.bytes();
    let text = String::from_utf8_lossy(&log).into_owned();
    assert!(
        text.lines().count() > 20,
        "too little was logged for the scan to mean anything: {text}"
    );
    assert!(
        text.contains("session established"),
        "the session was never logged, so neither was anything about it: {text}"
    );
    assert!(
        text.contains(&a.node.me.fingerprint()),
        "fingerprints are the permitted form and should be present: {text}"
    );

    let hits = scan(&log, &secrets);
    assert!(
        hits.is_empty(),
        "secrets in the log:\n  {}",
        hits.join("\n  ")
    );

    // And the same scan over a log that does contain them: every secret, in
    // every rendering, through the subscriber the run above wrote to.
    let before = capture.bytes().len();
    for secret in &secrets {
        for (form, rendered) in secret.renderings() {
            tracing::error!(leak = %rendered, "deliberate {}", form);
        }
        // The raw arm of the scan, on the secrets whose raw form is text.
        tracing::error!(leak = %String::from_utf8_lossy(&secret.bytes), "deliberate raw");
    }
    let dirty = capture.bytes();
    assert!(dirty.len() > before, "nothing was written");

    let caught = scan(&dirty, &secrets);
    for secret in &secrets {
        for (form, _) in secret.renderings() {
            let expected = format!("{} appears in the log as {form}", secret.what);
            assert!(
                caught.contains(&expected),
                "the scan missed a deliberately logged secret: {expected}"
            );
        }
    }

    for body in [BODY_A, BODY_B] {
        let expected = format!(
            "{} appears in the log as raw bytes",
            secrets
                .iter()
                .find(|s| s.bytes == body.as_bytes())
                .expect("the body is one of the secrets")
                .what
        );
        assert!(
            caught.contains(&expected),
            "the scan missed a deliberately logged plaintext: {expected}"
        );
    }
}
