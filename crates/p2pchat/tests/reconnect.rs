//! M10: `architecture.md` §10's reconnection, resync and retransmission.
//!
//! Every gate here needs a node to *stop* — the peer going away is the whole
//! subject — and `Node` has no shutdown of its own: it is kept alive by the
//! tasks it spawned. So each node gets its own runtime and stopping one is
//! dropping that runtime, which is also what makes a restart possible at all:
//! the port has to be free before anything can bind it again.
//!
//! That is why these are plain `#[test]`s. A `#[tokio::test]` is one runtime
//! for the whole test, and a node that cannot be stopped cannot come back.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::sync::mpsc::Receiver;

use p2pchat::{Config, Event, Node};
use p2pchat_core::wire::DeliveryStatus;
use p2pchat_core::{MessageId, MsgSeq, UserId};
use p2pchat_crypto::derive_conversation_id;

/// Long enough for a dial that has to wait out a backoff or two on a loaded
/// machine, short enough that a stuck flow fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(60);

/// What the gates scale §10's backoff to. The shape is asserted on in
/// `node`'s own unit tests; here it only has to be short enough to watch.
const BACKOFF_MS: &str = "100";

/// A dial to a port nothing answers on has to give up before the next attempt
/// is due, or the schedule below is the dial's timeout rather than the
/// backoff.
const DIAL_TIMEOUT_MS: &str = "2000";

/// How many messages F-20's gate sends while the peer is away.
const FIFTY: usize = 50;

// ---------------------------------------------------------------------------
// A node that can be stopped and started again on the same files
// ---------------------------------------------------------------------------

struct Peer {
    node: Arc<Node>,
    events: Receiver<Event>,
    /// Dropped to stop the node: there is no other stop. `None` once it has
    /// been.
    ///
    /// Never dropped implicitly. Dropping a runtime waits for its blocking
    /// tasks; the store's actor is one, and it ends when the last
    /// `Arc<Node>` does — which includes the one above, still alive while
    /// this is dropping. That is a deadlock, and it is what [`Drop`] below is
    /// for.
    runtime: Option<Runtime>,
    /// Kept across a restart — every restart gate starts from populated state.
    dir: PathBuf,
    /// Fixed, because a peer that reconnects dials the address it last
    /// handshaked on and a new ephemeral port would not be it.
    private: SocketAddr,
    /// Everything the node has reported since the last drain.
    seen: Vec<Event>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// §10's clocks, scaled once per test binary. Process-wide, so every gate in
/// this file uses the same numbers — which they do.
fn scale_the_clocks() {
    std::env::set_var("P2PCHAT_BACKOFF_MS", BACKOFF_MS);
    std::env::set_var("P2PCHAT_DIAL_TIMEOUT_MS", DIAL_TIMEOUT_MS);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

fn start(dir: &Path, private: SocketAddr) -> Peer {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let (node, events) = runtime
        .block_on(Node::start(Config {
            config_dir: dir.join("config"),
            data_dir: dir.join("data"),
            private_bind: private,
            public_bind: None,
            advertise: Vec::new(),
            private_advertise: None,
            display_name: "test".to_owned(),
        }))
        .expect("the node starts");

    Peer {
        node,
        events,
        runtime: Some(runtime),
        dir: dir.to_path_buf(),
        private,
        seen: Vec::new(),
    }
}

/// Stops the node and gives back what it takes to start it again.
///
/// `shutdown_timeout` rather than a plain drop: the store actor is a blocking
/// task, and a test that hangs here would be indistinguishable from one that
/// hangs in the code under test.
fn stop(mut peer: Peer) -> (PathBuf, SocketAddr) {
    let (dir, private) = (peer.dir.clone(), peer.private);
    let runtime = peer.runtime.take().expect("a node that is still running");
    // The node and its events first, so the store's actor has some chance of
    // ending on its own; the timeout is what makes sure a test never hangs
    // here either way.
    drop(peer);
    runtime.shutdown_timeout(Duration::from_secs(5));
    (dir, private)
}

fn restart(peer: Peer) -> Peer {
    let (dir, private) = stop(peer);
    start(&dir, private)
}

impl Peer {
    fn rt(&self) -> &Runtime {
        self.runtime.as_ref().expect("a node that is still running")
    }

    /// §10's acceptance, as the user's decision would have recorded it.
    fn accept(&self, who: UserId) {
        self.rt()
            .block_on(self.node.store.resolve_request(who, true))
            .expect("the store answers");
    }

    fn sessions(&self) -> HashSet<UserId> {
        self.rt().block_on(self.node.sessions())
    }

    fn session_id(&self, peer: UserId) -> Option<[u8; 32]> {
        self.rt().block_on(self.node.session_id(&peer))
    }

    fn dial(&self, addr: SocketAddr, peer: UserId) {
        self.rt()
            .block_on(self.node.dial(addr, Some(peer)))
            .expect("the dial succeeds");
    }

    fn disconnect(&self, peer: UserId) {
        self.rt().block_on(self.node.disconnect(peer));
    }

    fn send(&self, peer: UserId, body: &str) {
        self.rt()
            .block_on(self.node.send(peer, body.to_owned()))
            .expect("the message is queued or sent");
    }

    /// Everything `sender` sent in this store's copy of that conversation,
    /// oldest first — the receiving side of the gate, and the ordering
    /// assertion.
    fn from(&self, sender: UserId) -> Vec<(String, DeliveryStatus)> {
        self.rows(sender, sender)
    }

    /// Everything *this* node sent to `peer`. The same conversation from the
    /// other end, and the only end where `PENDING` and `SENT` exist.
    fn mine(&self, peer: UserId) -> Vec<(String, DeliveryStatus)> {
        self.rows(peer, self.node.me)
    }

    fn rows(&self, peer: UserId, sender: UserId) -> Vec<(String, DeliveryStatus)> {
        let conversation_id = derive_conversation_id(&self.node.me, &peer);
        self.rt()
            .block_on(
                self.node
                    .store
                    .after(conversation_id, sender, MsgSeq::ZERO, 10_000),
            )
            .expect("the store answers")
            .into_iter()
            .map(|message| {
                (
                    String::from_utf8_lossy(&message.body).into_owned(),
                    message.status,
                )
            })
            .collect()
    }

    /// The bodies only, which is what the order is asserted on.
    fn bodies(&self, sender: UserId) -> Vec<String> {
        self.from(sender)
            .into_iter()
            .map(|(body, _)| body)
            .collect()
    }

    /// Everything reported so far. Accumulated rather than drained, because
    /// the gates that read this are watching for an order between two events.
    fn events(&mut self) -> Vec<Event> {
        while let Ok(event) = self.events.try_recv() {
            self.seen.push(event);
        }
        self.seen.clone()
    }

    /// Whether this node still has a request out — gate 3's other half.
    fn outbound(&self) -> usize {
        self.rt()
            .block_on(self.node.store.outbound_requests())
            .expect("the store answers")
            .len()
    }
}

/// Polls until `done`, or fails. Never a hang.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A free UDP port, so that a restart can ask for the same one.
fn free_port() -> u16 {
    std::net::UdpSocket::bind(("127.0.0.1", 0))
        .expect("a socket")
        .local_addr()
        .expect("a bound address")
        .port()
}

fn addr() -> SocketAddr {
    format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("a literal address")
}

/// Two nodes that have accepted each other and have a session, with the
/// requester — the one that dialled, and so the one that redials — second.
fn pair(dir: &Path) -> (Peer, Peer) {
    scale_the_clocks();

    let host = start(&dir.join("host"), addr());
    let bob = start(&dir.join("bob"), addr());

    host.accept(bob.node.me);
    bob.accept(host.node.me);
    bob.dial(host.private, host.node.me);

    let host_id = host.node.me;
    let bob_id = bob.node.me;
    until("both sides to have the session", || {
        bob.sessions().contains(&host_id) && host.sessions().contains(&bob_id)
    });

    (host, bob)
}

// ---------------------------------------------------------------------------
// Gate 1 — F-20, cut at three different points
// ---------------------------------------------------------------------------

/// Where the connection is cut. The three points a resync can be interrupted
/// at, and the three that have been wrong in this code at least once.
#[derive(Clone, Copy, Debug)]
enum Cut {
    /// Between two messages, with everything before it delivered.
    BetweenMessages,
    /// In the middle of the stream, with sends still in flight.
    MidMessage,
    /// While the retransmission the last cut caused is still going out.
    DuringResync,
}

fn fifty_messages_survive(cut: Cut) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (host, bob) = pair(dir.path());
    let host_id = host.node.me;
    let bob_id = bob.node.me;

    // Populated state before anything is cut: a conversation with history in
    // it is what a reconnection actually happens to.
    for i in 0..10 {
        bob.send(host_id, &format!("before {i}"));
    }
    if matches!(cut, Cut::BetweenMessages) {
        until("the first ten to arrive", || {
            host.bodies(bob_id).len() == 10
        });
    }

    let (dir_host, port_host) = match cut {
        Cut::MidMessage => {
            // Cut with sends still in flight: fire everything and take the
            // peer away as soon as the stream is moving.
            for i in 0..FIFTY {
                bob.send(host_id, &format!("m{i:02}"));
            }
            until("the stream to be moving", || {
                host.bodies(bob_id).len() > 10 + 3
            });
            stop(host)
        }
        _ => stop(host),
    };

    until("bob to notice the session is gone", || {
        !bob.sessions().contains(&host_id)
    });

    if !matches!(cut, Cut::MidMessage) {
        // F-20: fifty messages composed with nowhere to send them.
        for i in 0..FIFTY {
            bob.send(host_id, &format!("m{i:02}"));
        }
    }

    let host = start(&dir_host, port_host);

    if matches!(cut, Cut::DuringResync) {
        // Cut again while the retransmission the reconnection started is
        // still going out.
        until("the retransmission to be moving", || {
            host.bodies(bob_id).len() >= 10 + 5
        });
        bob.disconnect(host_id);
    }

    let expected: Vec<String> = (0..FIFTY).map(|i| format!("m{i:02}")).collect();
    until("all fifty to arrive", || {
        host.bodies(bob_id).len() == 10 + FIFTY
    });

    let arrived = host.bodies(bob_id);
    assert_eq!(
        &arrived[10..],
        &expected[..],
        "the fifty did not arrive once each, in order ({cut:?})",
    );

    // And the sender agrees they went out: nothing is left pending once the
    // peer has acknowledged it.
    until("bob's rows to be acknowledged", || {
        let mine = bob.mine(host_id);
        mine.len() == 10 + FIFTY
            && mine
                .iter()
                .all(|(_, status)| *status == DeliveryStatus::Delivered)
    });
}

/// Gate 1, cut between messages.
#[test]
fn fifty_messages_sent_while_the_peer_is_down_all_arrive_once_and_in_order() {
    fifty_messages_survive(Cut::BetweenMessages);
}

/// Gate 1, cut mid-stream: some of the fifty were written to a socket that was
/// already going away, which is the case `have_through` off by one loses.
#[test]
fn fifty_messages_survive_a_cut_in_the_middle_of_the_stream() {
    fifty_messages_survive(Cut::MidMessage);
}

/// Gate 1, cut during the resync itself: the retransmission is interrupted and
/// has to be repeated, without repeating what got through.
#[test]
fn fifty_messages_survive_a_cut_during_the_resync() {
    fifty_messages_survive(Cut::DuringResync);
}

// ---------------------------------------------------------------------------
// Gate 2 — the queued rows
// ---------------------------------------------------------------------------

/// Gate 2. M9g stores what is typed with no session as `PENDING` and leaves it
/// there; M10 is what takes it out again.
///
/// The statuses are asserted in their order, not just their end state: §11
/// says `SENT` on the write and `DELIVERED` on the acknowledgement, and a
/// retransmission that jumped straight to `DELIVERED` would be reporting
/// something it has not been told.
#[test]
fn queued_pending_rows_go_out_when_a_session_opens() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    scale_the_clocks();

    let host = start(&dir.path().join("host"), addr());
    let mut bob = start(&dir.path().join("bob"), addr());
    host.accept(bob.node.me);
    bob.accept(host.node.me);
    let host_id = host.node.me;
    let bob_id = bob.node.me;

    // No session has ever existed, so these go nowhere — F-18.
    for i in 0..3 {
        bob.send(host_id, &format!("q{i}"));
    }
    assert_eq!(
        bob.mine(host_id)
            .iter()
            .filter(|(_, status)| *status == DeliveryStatus::Pending)
            .count(),
        3,
        "the queued messages are not pending",
    );

    bob.dial(host.private, host_id);

    until("the queued rows to be delivered", || {
        let mine = bob.mine(host_id);
        mine.len() == 3
            && mine
                .iter()
                .all(|(_, status)| *status == DeliveryStatus::Delivered)
    });
    assert_eq!(
        host.bodies(bob_id),
        vec!["q0".to_owned(), "q1".to_owned(), "q2".to_owned()],
        "the queued messages did not arrive",
    );

    // §11's order, per message: written, then acknowledged.
    let ids = stored_ids(&bob, host_id);
    let events = bob.events();
    for message_id in ids {
        let sent = position(
            &events,
            |event| matches!(event, Event::Sent { message_id: id, .. } if *id == message_id),
        );
        let delivered = position(
            &events,
            |event| matches!(event, Event::Delivered { message_id: id, .. } if *id == message_id),
        );
        let (Some(sent), Some(delivered)) = (sent, delivered) else {
            panic!("{message_id:?} was not reported sent and delivered: {events:?}");
        };
        assert!(
            sent < delivered,
            "{message_id:?} was delivered before it was sent",
        );
    }
}

fn stored_ids(peer: &Peer, other: UserId) -> Vec<MessageId> {
    let conversation_id = derive_conversation_id(&peer.node.me, &other);
    peer.rt()
        .block_on(
            peer.node
                .store
                .after(conversation_id, peer.node.me, MsgSeq::ZERO, 10_000),
        )
        .expect("the store answers")
        .into_iter()
        .map(|message| message.message_id)
        .collect()
}

fn position(events: &[Event], matches: impl FnMut(&Event) -> bool) -> Option<usize> {
    events.iter().position(matches)
}

// ---------------------------------------------------------------------------
// Gate 3 — the dial on startup
// ---------------------------------------------------------------------------

/// Gate 3. A node that comes back up with an accepted peer and no request
/// outstanding dials it. M9d resumes a request that is still being decided;
/// this is the case after that, which nothing did until now.
#[test]
fn a_restarted_node_dials_the_peer_it_had_accepted() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (host, bob) = pair(dir.path());
    let host_id = host.node.me;
    let bob_id = bob.node.me;

    // Populated: history, and a peer that was connected when we stopped.
    bob.send(host_id, "before the restart");
    until("the message to arrive", || host.bodies(bob_id).len() == 1);

    let bob = restart(bob);
    assert_eq!(
        bob.outbound(),
        0,
        "this gate is about the peer with no request pending",
    );

    until("the restarted node to dial its accepted peer", || {
        bob.sessions().contains(&host_id) && host.sessions().contains(&bob_id)
    });
}

// ---------------------------------------------------------------------------
// Gates 4 and 8 — the keys
// ---------------------------------------------------------------------------

/// Gates 4 and 8. Every reconnection is a new session, and what it retransmits
/// is encrypted under the new key.
///
/// The key itself never leaves the cipher; `session_id` is the name of it, and
/// it is derived from the same HKDF output, so two sessions that shared a key
/// would share an id. The retransmission is the second half: a frame sealed
/// under the *old* key fails the receiver's tag check and ends the session, so
/// a body that arrives after the reconnection arrived under the new one.
#[test]
fn a_reconnection_is_a_new_session_and_retransmits_under_its_key() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (host, bob) = pair(dir.path());
    let host_id = host.node.me;
    let bob_id = bob.node.me;

    let first = bob.session_id(host_id).expect("a live session");
    assert_eq!(
        host.session_id(bob_id),
        Some(first),
        "the two sides of one session named it differently",
    );

    // Composed with no session: the only way out is the retransmission.
    bob.disconnect(host_id);
    until("bob to notice the session is gone", || {
        !bob.sessions().contains(&host_id)
    });
    bob.send(host_id, "across the gap");

    until("the reconnection", || {
        bob.session_id(host_id).is_some_and(|id| id != first)
    });
    let second = bob.session_id(host_id).expect("the second session");
    assert_ne!(first, second, "the reconnection reused the session's keys");

    until("the retransmission to arrive", || {
        host.bodies(bob_id).contains(&"across the gap".to_owned())
    });
    assert_eq!(
        host.session_id(bob_id),
        Some(second),
        "the message arrived on a session the peer does not agree about",
    );
}

// ---------------------------------------------------------------------------
// Gate 5 — the failure that is not retried
// ---------------------------------------------------------------------------

/// Gate 5. §10: a peer that fails to authenticate is not dialled again.
///
/// Staged as the address being taken over by somebody else, which is the case
/// the rule exists for — retrying it is asking an impostor the same question
/// every thirty seconds for ten minutes, and it is an impostor who decides how
/// long each answer takes.
#[test]
fn a_peer_that_fails_the_handshake_is_not_retried() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (host, bob) = pair(dir.path());
    let host_id = host.node.me;

    // The peer goes away and somebody else comes up on its address.
    let (_, port) = stop(host);
    until("bob to start reconnecting", || {
        bob.node.phases().contains_key(&host_id)
    });
    let _impostor = start(&dir.path().join("impostor"), port);

    // §6 check 3 fails, and the loop ends rather than backing off.
    until("the reconnect loop to give up", || {
        !bob.node.phases().contains_key(&host_id)
    });

    // And stays ended. Long enough for several of §10's intervals at the scale
    // this binary runs them at.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !bob.node.phases().contains_key(&host_id),
        "the loop started dialling an impostor again",
    );
    assert!(
        !bob.sessions().contains(&host_id),
        "a session with the impostor was established",
    );
}
