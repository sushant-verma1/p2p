//! M8's in-process gates: §7's receiver rules and §10's simultaneous dial.
//!
//! Gates 1 and 4 need two real processes and live in `two_nodes.rs`. These
//! three do not, and are sharper here: a peer that sends a frame no honest
//! sender would send has to be hand-built, and driving it through a pipe would
//! add nothing but distance.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pchat::{Config, Event, Node};
use p2pchat_core::wire::{
    Ack, DeliveryStatus, MessageFrame, MessageHeader, MsgType, PROTOCOL_VERSION,
};
use p2pchat_core::{decode, ConversationId, MessageId, MsgSeq, UserId};
use p2pchat_crypto::{derive_conversation_id, Identity, SessionCipher};
use p2pchat_net::{client_endpoint, connect, handshake, recv_frame, send_frame, NodeKind};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::sync::mpsc::Receiver;

/// Long enough for a loopback round trip on a loaded machine, short enough that
/// a test that is actually stuck fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(10);

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

    /// §10: without the user's acceptance there is no session to test §7 on.
    /// M8a's own gates are in `access.rs`; here it is setup.
    async fn accept(&self, peer: UserId) {
        self.node
            .store
            .resolve_request(peer, true)
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

    async fn message_count(&self, peer: UserId) -> i64 {
        self.node
            .store
            .message_count(derive_conversation_id(&self.node.me, &peer))
            .await
            .expect("the store answers")
    }
}

// ---------------------------------------------------------------------------
// A peer that is not a Node
// ---------------------------------------------------------------------------

/// A real §6 handshake and a hand-driven cipher.
///
/// Gates 2 and 5 are both about frames an honest sender never produces — a
/// `message_id` sent twice, a `sender_id` that is someone else's — so the
/// sending side has to be something other than the code under test.
struct RawPeer {
    me: UserId,
    conversation_id: ConversationId,
    cipher: SessionCipher,
    send: SendStream,
    recv: RecvStream,
    connection: Connection,
    /// Dropping the endpoint would take the connection with it.
    _endpoint: Endpoint,
}

impl RawPeer {
    async fn dial(host: &TestNode) -> Self {
        let identity = Identity::generate();
        host.accept(identity.user_id()).await;
        let expect = host.node.me;

        let endpoint = client_endpoint(NodeKind::Private).expect("a client endpoint");
        let connection = connect(&endpoint, host.addr())
            .await
            .expect("the dial succeeds");
        let established = handshake::initiate(&connection, &identity, Some(expect))
            .await
            .expect("the handshake succeeds");

        Self {
            me: identity.user_id(),
            conversation_id: derive_conversation_id(&identity.user_id(), &expect),
            cipher: SessionCipher::derive(established.session).expect("the keys derive"),
            send: established.send,
            recv: established.recv,
            connection,
            _endpoint: endpoint,
        }
    }

    /// One text frame, with every header field chosen by the caller.
    async fn text(
        &mut self,
        sender_id: UserId,
        message_id: MessageId,
        msg_seq: MsgSeq,
        body: &str,
    ) {
        let header = MessageHeader {
            version: PROTOCOL_VERSION,
            msg_type: MsgType::Text,
            message_id,
            conversation_id: self.conversation_id,
            sender_id,
            msg_seq,
            created_at: 1_700_000_000_000,
        };
        let frame = self
            .cipher
            .seal(&header, body.as_bytes())
            .expect("sealing succeeds");
        send_frame(&mut self.send, &frame)
            .await
            .expect("the frame is written");
    }

    /// The next ACK back.
    ///
    /// §10 opens every session with a RESYNC, which these tests have nothing
    /// to answer — this peer's store is a struct with no rows in it.
    async fn ack(&mut self) -> Ack {
        let frame: MessageFrame = loop {
            let frame: MessageFrame = tokio::time::timeout(PATIENCE, recv_frame(&mut self.recv))
                .await
                .expect("an answer before the deadline")
                .expect("the session is still open");
            if frame.header.msg_type != MsgType::Resync {
                break frame;
            }
            self.cipher.open(&frame).expect("the resync verifies");
        };

        assert_eq!(frame.header.msg_type, MsgType::Ack);
        let plaintext = self.cipher.open(&frame).expect("the ACK verifies");
        decode(&plaintext).expect("the ACK decodes")
    }
}

// ---------------------------------------------------------------------------
// Gate 2
// ---------------------------------------------------------------------------

/// A sender that never saw the ACK sends the message again. §7 rule 4: the
/// second copy is acknowledged and not stored.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_resent_after_a_lost_ack_is_stored_once_and_re_acked() {
    let mut receiver = node().await;
    let mut peer = RawPeer::dial(&receiver).await;

    let message_id = MessageId::now_v7();
    let seq = MsgSeq::new(1);

    peer.text(peer.me, message_id, seq, "only once").await;
    let first = peer.ack().await;

    // The same message again: same ID, same number, same body. Only the frame
    // is new.
    peer.text(peer.me, message_id, seq, "only once").await;
    let second = peer.ack().await;

    assert_eq!(first.message_id, message_id, "the first ACK names it");
    assert_eq!(second.message_id, message_id, "and so does the re-ack");
    assert_eq!(first.status, DeliveryStatus::Delivered);
    assert_eq!(second.status, DeliveryStatus::Delivered);

    assert_eq!(
        receiver.message_count(peer.me).await,
        1,
        "the resend must not store a second row"
    );

    // Exactly one arrival, too: the duplicate is not news.
    match receiver.event().await {
        Event::Connected { .. } => {}
        other => panic!("expected the session first, got {other:?}"),
    }
    match receiver.event().await {
        Event::Received { body, .. } => assert_eq!(body, "only once"),
        other => panic!("expected the message, got {other:?}"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(500), receiver.session_event())
            .await
            .is_err(),
        "the duplicate must not be reported as a second arrival"
    );
}

// ---------------------------------------------------------------------------
// Gate 5
// ---------------------------------------------------------------------------

/// §7 rule 3. The peer is authenticated by §6; a frame it sends claiming to be
/// someone else is the peer writing history under another name.
#[tokio::test(flavor = "multi_thread")]
async fn a_frame_whose_sender_is_not_the_authenticated_peer_is_rejected() {
    let receiver = node().await;
    let mut peer = RawPeer::dial(&receiver).await;

    // Everything else about the frame is perfect, including the tag: the
    // sender holds the session key, because it is the session's peer.
    let third_party = UserId::from_bytes([0x5a; 32]);
    peer.text(third_party, MessageId::now_v7(), MsgSeq::new(1), "not mine")
        .await;

    tokio::time::timeout(PATIENCE, peer.connection.closed())
        .await
        .expect("the session is closed rather than left open");

    assert_eq!(
        receiver.message_count(peer.me).await,
        0,
        "nothing attributed to a third party may be stored"
    );
}

// ---------------------------------------------------------------------------
// Gate 3
// ---------------------------------------------------------------------------

/// §10. Both sides compare the same two IDs, so both keep the same session
/// without another round trip.
#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_dial_leaves_one_session_and_it_is_the_lower_initiators() {
    let a = node().await;
    let b = node().await;
    let (addr_a, addr_b) = (a.addr(), b.addr());

    // §10 twice over: the tiebreak only arises between peers who have each
    // accepted the other, since a dial to an unaccepted peer never happens.
    a.accept(b.node.me).await;
    b.accept(a.node.me).await;

    let (dialled_b, dialled_a) = tokio::join!(
        a.node.dial(addr_b, Some(b.node.me)),
        b.node.dial(addr_a, Some(a.node.me)),
    );
    dialled_b.expect("a dials b");
    dialled_a.expect("b dials a");

    let winner = a.node.me.min(b.node.me);

    // Both nodes see two sessions for a moment: the one they dialled and the
    // one they answered. Closing the loser is a round trip away.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let settled = a.node.session_count().await == 1
            && b.node.session_count().await == 1
            && a.node.session_initiator(&b.node.me).await == Some(winner)
            && b.node.session_initiator(&a.node.me).await == Some(winner);

        if settled {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the duplicate session never resolved: a kept {:?}, b kept {:?}",
            a.node.session_initiator(&b.node.me).await,
            b.node.session_initiator(&a.node.me).await
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // And the surviving session works, in the direction the loser would have
    // carried if the wrong one had been kept.
    a.node
        .send(b.node.me, "after the tiebreak".to_owned())
        .await
        .expect("the surviving session takes a message");

    let mut b = b;
    loop {
        if let Event::Received { body, .. } = b.event().await {
            assert_eq!(body, "after the tiebreak");
            break;
        }
    }
}
