//! M9 gate 3: a stalled screen must not stall the node.
//!
//! `architecture.md` §2 says the core never blocks on the UI, and the reason
//! is here rather than in the TUI crate: the thing that would block is the
//! session task, and the channel it would block on is the one the screen
//! reads. So the screen is modelled as what a stalled one is — a receiver
//! nobody calls `recv` on — and the question is whether the messages still
//! land in the store.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pchat::{Config, Event, Node};
use p2pchat_core::UserId;
use p2pchat_crypto::derive_conversation_id;
use tokio::sync::mpsc::Receiver;

/// Four times the event channel's depth, so the channel is full for most of
/// the run and the drop path is what is being measured.
const MESSAGES: usize = 1_000;

/// A thousand round trips over loopback with a SQLite write each way. Long
/// enough for a loaded machine, short enough that a stall fails rather than
/// hangs.
const PATIENCE: Duration = Duration::from_secs(180);

struct TestNode {
    node: Arc<Node>,
    /// Never read. That is the whole point: this is the stalled screen.
    _events: Receiver<Event>,
    _dir: tempfile::TempDir,
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

    TestNode {
        node,
        _events: events,
        _dir: dir,
    }
}

impl TestNode {
    fn addr(&self) -> SocketAddr {
        self.node.private_addr().expect("a bound address")
    }

    async fn accept(&self, peer: UserId) {
        self.node
            .store
            .resolve_request(peer, true)
            .await
            .expect("the store answers");
    }

    async fn stored(&self, peer: UserId) -> i64 {
        self.node
            .store
            .message_count(derive_conversation_id(&self.node.me, &peer))
            .await
            .expect("the store answers")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_thousand_messages_arrive_while_nothing_is_reading_the_events() {
    let sender = node().await;
    let receiver = node().await;

    sender.accept(receiver.node.me).await;
    receiver.accept(sender.node.me).await;
    sender
        .node
        .dial(receiver.addr(), Some(receiver.node.me))
        .await
        .expect("the session opens");

    // Every await below is one the core would never come back from if it
    // waited on the screen — `send` included, since the sender's own events go
    // unread too. So the whole run sits under one timeout: a core that waits
    // fails this test instead of hanging the suite.
    let work = async {
        for i in 0..MESSAGES {
            sender
                .node
                .send(receiver.node.me, format!("message {i}"))
                .await
                .expect("the message is queued");
        }
        while receiver.stored(sender.node.me).await != MESSAGES as i64 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    if tokio::time::timeout(PATIENCE, work).await.is_err() {
        let stored = receiver.stored(sender.node.me).await;
        panic!("only {stored} of {MESSAGES} were stored: the core is waiting on the screen");
    }

    // And the channel really did overflow, so what passed above was the drop
    // path and not a channel that happened to be big enough. Everything the
    // dropped events described is in the store, which is why dropping them is
    // allowed: they are notifications, not payloads.
    let mut receiver = receiver;
    let mut drained = 0;
    while receiver._events.try_recv().is_ok() {
        drained += 1;
    }
    assert!(
        drained < MESSAGES,
        "the events all fitted, so this proves nothing about a stalled screen"
    );
}
