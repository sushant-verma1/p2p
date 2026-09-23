//! M8a's gate — `architecture.md` §10, F-06: the private node holds a session
//! only with a peer the user accepted.
//!
//! Five of the six gates are here; gate 3's restart needs a process that really
//! ends, and lives in `two_nodes.rs` with the other one that does.
//!
//! The two tests that matter most are the last two. Everything else asserts
//! that the door is shut; those assert that the door does not say *who* it is
//! shut against — a probe with a claimed-accepted ID and a probe with a
//! claimed-unaccepted ID have to be answered identically, at the same point in
//! the exchange, because otherwise anyone can read the accepted list without
//! holding a single key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pchat::{Config, Event, Node};
use p2pchat_core::wire::{HelloConfirm, HelloResp, RequestState, Signature};
use p2pchat_core::UserId;
use p2pchat_crypto::handshake::Initiator;
use p2pchat_crypto::Identity;
use p2pchat_net::{
    channel_binding, client_endpoint, connect, handshake, recv_frame, send_frame, NodeKind,
};
use p2pchat_store::{PendingRequest, MAX_PENDING};
use tokio::sync::mpsc::Receiver;

/// Long enough for a loopback round trip on a loaded machine, short enough that
/// a test that is actually stuck fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(10);

/// Long enough to be sure an event is not merely late.
const QUIET: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// A node in a temporary directory
// ---------------------------------------------------------------------------

struct TestNode {
    node: Arc<Node>,
    events: Receiver<Event>,
    /// Deleted when the test ends, so it has to outlive the node.
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
        events,
        _dir: dir,
    }
}

impl TestNode {
    fn addr(&self) -> SocketAddr {
        self.node.private_addr().expect("a bound address")
    }

    /// The user's decision, made exactly as the TUI will make it — F-06.
    async fn decide(&self, peer: UserId, accepted: bool) {
        self.node
            .store
            .resolve_request(peer, accepted)
            .await
            .expect("the store answers");
    }

    /// The next event, or a failure — never a hang.
    ///
    /// `Phase` is skipped throughout. It says only "ask again", several times
    /// per dial, and every assertion here is on what happened rather than on
    /// what is being attempted.
    async fn event(&mut self) -> Event {
        loop {
            let event = tokio::time::timeout(PATIENCE, self.events.recv())
                .await
                .expect("an event before the deadline")
                .expect("the node is still running");
            if !matches!(event, Event::Phase { .. }) {
                return event;
            }
        }
    }
    /// The next event that is not a redraw hint — see [`Self::event`]. Never
    /// returns if there is none, which is what the timeout above is for.
    async fn session_event(&mut self) -> Option<Event> {
        loop {
            match self.events.recv().await {
                Some(Event::Phase { .. }) => continue,
                other => return other,
            }
        }
    }

    /// Nothing happened, and not merely nothing yet.
    async fn stays_quiet(&mut self) {
        assert!(
            tokio::time::timeout(QUIET, self.session_event())
                .await
                .is_err(),
            "the node reported something about a session it must not have"
        );
    }
}

// ---------------------------------------------------------------------------
// Callers that are not nodes
// ---------------------------------------------------------------------------

/// A real identity running a real §6 handshake, and nothing after it.
///
/// These gates are about what the private node does with a handshake that
/// *succeeded*, so the dialling side has to stop there rather than go on to be
/// a session.
async fn handshake_only(addr: SocketAddr, expect: UserId, caller: &Identity) -> String {
    let endpoint = client_endpoint(NodeKind::Private).expect("a client endpoint");
    let connection = connect(&endpoint, addr).await.expect("the dial succeeds");

    tokio::time::timeout(
        PATIENCE,
        handshake::initiate(&connection, caller, Some(expect)),
    )
    .await
    .expect("the handshake resolves before the deadline")
    .expect("the handshake itself succeeds: this is not a §6 failure");

    tokio::time::timeout(PATIENCE, connection.closed())
        .await
        .expect("the node closed the connection")
        .to_string()
}

/// What a prober can observe, and all of it.
#[derive(Debug, PartialEq, Eq)]
struct Probe {
    /// Whether `HELLO_RESP` came back — where in the exchange this ended.
    answered: bool,
    /// What the connection closed with.
    told: String,
}

/// Claims `claimed`'s identity in `HELLO_INIT` without holding its key.
///
/// The user ID and the identity key are both public — an invite carries them,
/// and §6 check 2 forces a claim to carry the matching key anyway. What the
/// prober cannot produce is `sig_i`, so this is every impersonation attempt
/// that is available to someone who has only read an invite.
async fn probe(addr: SocketAddr, claimed: &Identity) -> Probe {
    let throwaway = Identity::generate();
    let endpoint = client_endpoint(NodeKind::Private).expect("a client endpoint");
    let connection = connect(&endpoint, addr).await.expect("the dial succeeds");

    let cb = channel_binding(&connection).expect("a channel binding");
    let (_state, mut hello) = Initiator::start(&throwaway, &cb, None).expect("a HELLO_INIT");
    hello.user_id_i = claimed.user_id();
    hello.identity_pk_i = claimed.identity_pk();

    let (mut send, mut recv) = connection.open_bi().await.expect("a stream");
    send_frame(&mut send, &hello).await.expect("the write");

    let answered = tokio::time::timeout(PATIENCE, recv_frame::<HelloResp>(&mut recv))
        .await
        .expect("the responder answered or closed before the deadline")
        .is_ok();
    if answered {
        // Something has to be sent, or the two probes would differ in which
        // side gave up first rather than in what the node did.
        let confirm = HelloConfirm {
            sig_i: Signature::from_bytes([0u8; 64]),
        };
        let _ = send_frame(&mut send, &confirm).await;
    }

    let told = tokio::time::timeout(PATIENCE, connection.closed())
        .await
        .expect("the node closed the connection")
        .to_string();

    Probe { answered, told }
}

fn assert_generic(told: &str) {
    assert!(
        told.contains("handshake failed"),
        "the peer was told more than a handshake failure: {told}"
    );
}

// ---------------------------------------------------------------------------
// Gate 1
// ---------------------------------------------------------------------------

/// The hole M8a closes: an invite holder who never asked, or who asked and was
/// refused, can reach the private node directly. §6 lets them in; §10 does not.
#[tokio::test(flavor = "multi_thread")]
async fn an_unaccepted_peer_that_completes_the_handshake_is_closed() {
    let mut host = node().await;
    let caller = Identity::generate();

    let told = handshake_only(host.addr(), host.node.me, &caller).await;

    assert_generic(&told);
    assert_eq!(host.node.session_count().await, 0, "a session survived");
    assert!(
        host.node
            .store
            .peer(caller.user_id())
            .await
            .expect("the store answers")
            .is_none(),
        "an unaccepted peer was recorded as one"
    );
    host.stays_quiet().await;
}

// ---------------------------------------------------------------------------
// Gate 2
// ---------------------------------------------------------------------------

/// The other half: the check is not a way of never talking to anyone.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_peers_session_succeeds() {
    let mut host = node().await;
    let guest = node().await;

    host.decide(guest.node.me, true).await;
    guest.decide(host.node.me, true).await;

    let peer = guest
        .node
        .dial(host.addr(), Some(host.node.me))
        .await
        .expect("an accepted peer connects");
    assert_eq!(peer, host.node.me);

    guest
        .node
        .send(host.node.me, "let me in".to_owned())
        .await
        .expect("the session takes a message");

    match host.event().await {
        Event::Connected { peer, .. } => assert_eq!(peer, guest.node.me),
        other => panic!("expected the session first, got {other:?}"),
    }
    match host.event().await {
        Event::Received { body, .. } => assert_eq!(body, "let me in"),
        other => panic!("expected the message, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Gate 4
// ---------------------------------------------------------------------------

/// F-06's reject, made to mean something. The full path: the request is queued,
/// the user says no, and the caller dials the private node anyway.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_peer_cannot_open_a_session() {
    let mut host = node().await;
    let caller = Identity::generate();

    host.node
        .store
        .enqueue_request(
            PendingRequest {
                from_user_id: caller.user_id(),
                from_identity_pk: caller.identity_pk(),
                display_name: "not to be trusted".to_owned(),
                created_at: 1_700_000_000,
                received_at: 1_700_000_000,
                state: RequestState::Pending,
            },
            MAX_PENDING,
        )
        .await
        .expect("the request queues");
    host.decide(caller.user_id(), false).await;
    assert_eq!(
        host.node
            .store
            .request_state(caller.user_id())
            .await
            .expect("the store answers"),
        RequestState::Rejected
    );

    let told = handshake_only(host.addr(), host.node.me, &caller).await;

    assert_generic(&told);
    assert_eq!(host.node.session_count().await, 0, "a session survived");
    host.stays_quiet().await;
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// §10 runs in both directions: we do not open a session with a peer we have
/// not accepted, whether or not we know in advance who we are dialling.
#[tokio::test(flavor = "multi_thread")]
async fn we_do_not_open_a_session_with_a_peer_we_have_not_accepted() {
    let mut us = node().await;
    let them = node().await;

    // They would have us — the refusal has to be ours.
    them.decide(us.node.me, true).await;

    us.node
        .dial(them.addr(), Some(them.node.me))
        .await
        .expect_err("dialling an unaccepted peer must fail");
    us.node
        .dial(them.addr(), None)
        .await
        .expect_err("not knowing who we dialled is not a way around the check");

    assert_eq!(us.node.session_count().await, 0, "a session survived");
    us.stays_quiet().await;
}

// ---------------------------------------------------------------------------
// Gate 5
// ---------------------------------------------------------------------------

/// Acceptance is on the ID §6 authenticated, so borrowing an accepted ID buys
/// nothing: the key is what the transcript signature proves, and the prober
/// does not have it.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_claiming_an_accepted_id_without_its_key_is_rejected() {
    let mut host = node().await;
    let accepted = Identity::generate();
    host.decide(accepted.user_id(), true).await;

    let seen = probe(host.addr(), &accepted).await;

    assert_generic(&seen.told);
    assert_eq!(host.node.session_count().await, 0, "a session survived");
    host.stays_quiet().await;

    // The acceptance row is still the one the user made, with no key in it: a
    // failed impersonation must not leave the claimed key behind as though a
    // handshake had proved it.
    let peer = host
        .node
        .store
        .peer(accepted.user_id())
        .await
        .expect("the store answers")
        .expect("the accepted peer is still there");
    assert!(peer.accepted);
    assert_eq!(peer.identity_pk, [0u8; 32], "an unproven key was stored");
}

// ---------------------------------------------------------------------------
// Gate 6
// ---------------------------------------------------------------------------

/// The reason the check is not done early, as a test.
///
/// Both probes claim an ID whose key they do not hold; one of those IDs is
/// accepted and the other is not. If the node decided anything before the
/// handshake completed, the two would differ — in the close code, or in how far
/// the exchange got — and the difference is a free read of the accepted list
/// for anyone who can open a QUIC connection.
///
/// `answered` is the half that catches an early close specifically: two
/// identical close strings prove nothing if one connection was cut before
/// `HELLO_RESP` and the other was not.
#[tokio::test(flavor = "multi_thread")]
async fn probing_an_accepted_id_and_an_unaccepted_one_is_indistinguishable() {
    let host = node().await;
    let accepted = Identity::generate();
    let unaccepted = Identity::generate();
    host.decide(accepted.user_id(), true).await;

    let claimed_accepted = probe(host.addr(), &accepted).await;
    let claimed_unaccepted = probe(host.addr(), &unaccepted).await;

    assert!(
        claimed_accepted.answered && claimed_unaccepted.answered,
        "the exchange ended at different points, which is the oracle itself: \
         accepted {claimed_accepted:?}, unaccepted {claimed_unaccepted:?}"
    );
    assert_eq!(
        claimed_accepted, claimed_unaccepted,
        "the node can be asked whether an ID is accepted, without a key"
    );
    assert_generic(&claimed_accepted.told);
    assert_eq!(host.node.session_count().await, 0, "a session survived");
}
