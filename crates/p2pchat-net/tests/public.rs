//! The M7 gate over a real QUIC endpoint — `architecture.md` §3.
//!
//! Gate 6 (a connection request reaches the peer; accept and reject both work)
//! and gate 8 (a flood from one source is rate-limited rather than queued) are
//! here, along with the profile exchange. The queue's own gates — persistence
//! and the cap — are in `p2pchat-store`, which this crate may not depend on
//! (§2); the consumer below is a `HashMap` standing in for it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pchat_core::wire::{
    ConnectionRequest, ConnectionStatus, Invite, ProfileRequest, PublicRequest, PublicResponse,
    RequestState, PROTOCOL_VERSION,
};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, Identity};
use p2pchat_net::public::{self, Ask, Incoming, Limits, PublicNode};
use p2pchat_net::{client_endpoint, server_endpoint, NodeKind};
use tokio::sync::mpsc;

/// Every wait in this file is bounded; a public-node test that hangs has told
/// nobody anything.
const PATIENCE: Duration = Duration::from_secs(10);

const NOW: u64 = 1_700_000_000;

/// What the node under test advertises as its private endpoint — M9d. Not a
/// loopback address, so an answer carrying it could not have come from
/// anywhere else by accident.
const PRIVATE: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
    47101,
);

fn loopback() -> SocketAddr {
    (std::net::Ipv4Addr::LOCALHOST, 0).into()
}

/// The queue, as far as these tests need one: what the store does, in memory.
#[derive(Clone, Default)]
struct Queue(Arc<Mutex<HashMap<UserId, RequestState>>>);

impl Queue {
    fn enqueue(&self, from: UserId) -> RequestState {
        let mut guard = self.0.lock().unwrap();
        *guard.entry(from).or_insert(RequestState::Pending)
    }

    fn state(&self, from: UserId) -> RequestState {
        *self
            .0
            .lock()
            .unwrap()
            .get(&from)
            .unwrap_or(&RequestState::Unknown)
    }

    /// The user's decision, made out of band exactly as the TUI will make it.
    fn resolve(&self, from: UserId, accepted: bool) {
        self.0.lock().unwrap().insert(
            from,
            if accepted {
                RequestState::Accepted
            } else {
                RequestState::Rejected
            },
        );
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

/// A running public node: its address, its owner's invite, and the queue behind
/// it. Dropping the returned `Node` leaves the tasks to die with the runtime.
struct Node {
    addr: SocketAddr,
    invite: Invite,
    owner: UserId,
    queue: Queue,
    /// Every `Ask` the node forwarded, in order — what "reached the peer" means.
    seen: Arc<Mutex<Vec<Ask>>>,
}

fn start(limits: Limits) -> Node {
    let identity = Identity::generate();
    let endpoint = server_endpoint(loopback(), NodeKind::Public).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let invite = invite::create(&identity, "advisory", vec![addr], NOW).unwrap();

    let (tx, mut rx) = mpsc::channel::<Incoming>(8);
    let queue = Queue::default();
    let seen = Arc::new(Mutex::new(Vec::new()));

    tokio::spawn(public::serve(
        endpoint,
        PublicNode {
            invite: invite.clone(),
            limits,
            requests: tx,
        },
    ));

    // The consumer: the binary's job in M8, a task here.
    let (consumer_queue, consumer_seen) = (queue.clone(), Arc::clone(&seen));
    tokio::spawn(async move {
        while let Some(Incoming { ask, reply }) = rx.recv().await {
            consumer_seen.lock().unwrap().push(ask.clone());
            let state = match ask {
                Ask::Connect(request) => consumer_queue.enqueue(request.from_user_id),
                Ask::Status(from) => consumer_queue.state(from),
            };
            // Deliberately offered with *every* answer: M9d puts the rule that
            // it rides only with `Accepted` in the crate, not in the consumer,
            // and this is the consumer that would otherwise leak it.
            let _ = reply.send((state, Some(PRIVATE)));
        }
    });

    Node {
        addr,
        owner: identity.user_id(),
        invite,
        queue,
        seen,
    }
}

async fn ask(
    node: &Node,
    request: &PublicRequest,
) -> Result<PublicResponse, p2pchat_net::NetError> {
    let endpoint = client_endpoint(NodeKind::Public).unwrap();
    public::request(&endpoint, node.addr, request, PATIENCE).await
}

fn connection_request(caller: &Identity) -> PublicRequest {
    PublicRequest::Connection(ConnectionRequest {
        version: PROTOCOL_VERSION,
        from_user_id: caller.user_id(),
        from_identity_pk: caller.identity_pk(),
        display_name: "not to be trusted".into(),
        created_at: NOW,
    })
}

fn status_request(caller: &Identity) -> PublicRequest {
    PublicRequest::Status(ConnectionStatus {
        version: PROTOCOL_VERSION,
        from_user_id: caller.user_id(),
    })
}

fn state(response: PublicResponse) -> RequestState {
    let (state, addr) = match response {
        PublicResponse::State(state, addr) => (state, addr),
        other => panic!("expected a state, got {other:?}"),
    };

    // M9d, §3: the address rides with `Accepted` and with nothing else. Checked
    // on every answer these tests read, so no test can pass while leaking it.
    match state {
        RequestState::Accepted => assert_eq!(addr, Some(PRIVATE), "the address was dropped"),
        _ => assert_eq!(addr, None, "{state:?} carried an address"),
    }
    state
}

/// The profile answer is a signed invite, and the caller verifies it rather
/// than trusting the node that handed it over — §3.
#[tokio::test]
async fn a_profile_request_is_answered_with_the_owners_signed_invite() {
    let node = start(Limits::default());

    let response = ask(
        &node,
        &PublicRequest::Profile(ProfileRequest {
            version: PROTOCOL_VERSION,
            user_id: node.owner,
        }),
    )
    .await
    .unwrap();

    let PublicResponse::Profile(answer) = response else {
        panic!("expected a profile");
    };
    invite::verify(&answer, NOW).unwrap();
    assert_eq!(*answer, node.invite);
    assert_eq!(answer.body.user_id, node.owner);
}

/// "A node that is not that owner answers nothing" — §3. Silence, not a
/// correction: answering would confirm a guess about who lives at an address.
#[tokio::test]
async fn a_profile_request_for_someone_else_is_not_answered() {
    let node = start(Limits::default());

    let response = ask(
        &node,
        &PublicRequest::Profile(ProfileRequest {
            version: PROTOCOL_VERSION,
            user_id: UserId::from_bytes([0x5a; 32]),
        }),
    )
    .await;

    assert!(response.is_err(), "{response:?}");
}

/// M7 gate 6, accept. The request reaches the peer, the peer decides out of
/// band, and the caller learns the decision by asking.
#[tokio::test]
async fn a_connection_request_reaches_the_peer_and_can_be_accepted() {
    let node = start(Limits::default());
    let caller = Identity::generate();

    let first = state(ask(&node, &connection_request(&caller)).await.unwrap());
    assert_eq!(first, RequestState::Pending);

    match node.seen.lock().unwrap().first() {
        Some(Ask::Connect(request)) => {
            assert_eq!(request.from_user_id, caller.user_id());
            assert_eq!(request.from_identity_pk, caller.identity_pk());
        }
        other => panic!("the request did not reach the peer: {other:?}"),
    }

    node.queue.resolve(caller.user_id(), true);

    let after = state(ask(&node, &status_request(&caller)).await.unwrap());
    assert_eq!(after, RequestState::Accepted);
}

/// M7 gate 6, reject — F-06: reported to the sender, and it stays rejected.
#[tokio::test]
async fn a_connection_request_can_be_rejected() {
    let node = start(Limits::default());
    let caller = Identity::generate();

    assert_eq!(
        state(ask(&node, &connection_request(&caller)).await.unwrap()),
        RequestState::Pending
    );
    node.queue.resolve(caller.user_id(), false);

    assert_eq!(
        state(ask(&node, &status_request(&caller)).await.unwrap()),
        RequestState::Rejected
    );
    // Asking again does not reopen it.
    assert_eq!(
        state(ask(&node, &connection_request(&caller)).await.unwrap()),
        RequestState::Rejected
    );
}

/// A caller who never asked gets `Unknown`, from a node that keeps no other
/// record of them.
#[tokio::test]
async fn a_status_query_for_an_unknown_caller_says_so() {
    let node = start(Limits::default());
    let stranger = Identity::generate();

    assert_eq!(
        state(ask(&node, &status_request(&stranger)).await.unwrap()),
        RequestState::Unknown
    );
}

/// M7 gate 8. The limit is per source address and applies before the TLS
/// handshake, so a flood is refused at the door rather than queued.
#[tokio::test]
async fn a_flood_from_one_source_is_rate_limited_rather_than_queued() {
    let allowance = 3;
    let node = start(Limits {
        per_source: allowance,
        ..Limits::default()
    });

    // One client endpoint, so every connection carries the same source address
    // — which is the case the limit exists for.
    let endpoint = client_endpoint(NodeKind::Public).unwrap();
    let mut answered = 0;
    for _ in 0..allowance * 4 {
        let caller = Identity::generate();
        if public::request(&endpoint, node.addr, &connection_request(&caller), PATIENCE)
            .await
            .is_ok()
        {
            answered += 1;
        }
    }

    assert_eq!(
        answered,
        allowance,
        "the limiter served {answered} of {} requests",
        allowance * 4
    );
    assert_eq!(
        node.seen.lock().unwrap().len(),
        allowance as usize,
        "requests past the limit still reached the queue"
    );
    assert_eq!(node.queue.len(), allowance as usize);
}

/// The public node is reachable by anyone, so a caller who sends nonsense must
/// cost one connection and nothing more — the next caller is still served.
#[tokio::test]
async fn nonsense_from_one_caller_does_not_stop_the_node() {
    let node = start(Limits::default());

    let endpoint = client_endpoint(NodeKind::Public).unwrap();
    let connection = p2pchat_net::connect(&endpoint, node.addr).await.unwrap();
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    // A length prefix announcing a gigabyte, then nothing to back it up.
    send.write_all(&(1024u32 * 1024 * 1024).to_be_bytes())
        .await
        .unwrap();
    let _ = send.finish();
    drop(connection);

    let caller = Identity::generate();
    assert_eq!(
        state(ask(&node, &connection_request(&caller)).await.unwrap()),
        RequestState::Pending
    );
}
