//! M7's store half: the pending-request queue — `architecture.md` §8, F-07.
//!
//! Gate 7 (pending requests survive restart) and gate 9 (a full queue rejects
//! rather than growing) live here. Gate 6's accept and reject are tested end to
//! end over QUIC in `p2pchat-net`; what is tested here is that the decision is
//! recorded, final, and readable by the caller afterwards.
//!
//! M8a adds the other half of a decision: `peers.accepted`, which is what the
//! private node checks in §10. The session-level gates are in
//! `p2pchat/tests/access.rs`; these are the storage ones.

use std::net::SocketAddr;

use p2pchat_core::wire::RequestState;
use p2pchat_core::UserId;
use p2pchat_store::{db_path, PendingRequest, Store, MAX_PENDING};
use tempfile::TempDir;

const NOW: u64 = 1_700_000_000;

fn caller(tag: u8) -> UserId {
    UserId::from_bytes([tag; 32])
}

fn request(tag: u8) -> PendingRequest {
    PendingRequest {
        from_user_id: caller(tag),
        from_identity_pk: [tag ^ 0xff; 32],
        display_name: "not to be trusted".into(),
        created_at: NOW - 5,
        received_at: NOW + u64::from(tag),
        state: RequestState::Pending,
    }
}

async fn fixture() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(db_path(dir.path())).await.unwrap();
    (dir, store)
}

/// M7 gate 7. The IPv6 address is in there because the queue stores addresses
/// as text: a bracketed address that came back mangled would be a silent
/// corruption of the only field that says where to dial back.
#[tokio::test]
async fn pending_requests_survive_a_restart() {
    let (dir, store) = fixture().await;

    for tag in [1, 2, 3] {
        assert_eq!(
            store
                .enqueue_request(request(tag), MAX_PENDING)
                .await
                .unwrap(),
            RequestState::Pending
        );
    }
    store.resolve_request(caller(2), true).await.unwrap();
    store.close().await.unwrap();

    let reopened = Store::open(db_path(dir.path())).await.unwrap();
    let pending = reopened.pending_requests().await.unwrap();

    assert_eq!(pending.len(), 2, "{pending:#?}");
    assert_eq!(pending[0], request(1), "oldest first, fields intact");
    assert_eq!(pending[1].from_user_id, caller(3));
    assert_eq!(
        reopened.request_state(caller(2)).await.unwrap(),
        RequestState::Accepted,
        "the decision did not survive either"
    );
}

/// M7 gate 9. The cap is on rows in state 0, and a request that arrives at a
/// full queue is answered `Rejected` without a row being written.
#[tokio::test]
async fn a_full_queue_rejects_rather_than_growing() {
    let (_dir, store) = fixture().await;
    let cap = 4;

    for tag in 0..cap {
        assert_eq!(
            store
                .enqueue_request(request(tag as u8), cap)
                .await
                .unwrap(),
            RequestState::Pending
        );
    }

    for tag in cap..cap + 8 {
        assert_eq!(
            store
                .enqueue_request(request(tag as u8), cap)
                .await
                .unwrap(),
            RequestState::Rejected,
            "the queue grew past its cap"
        );
    }

    assert_eq!(store.pending_requests().await.unwrap().len(), cap);
    // Not merely absent from the pending list: never stored at all, or a
    // flood would fill the table with rows the cap no longer counts.
    assert_eq!(
        store.request_state(caller(cap as u8)).await.unwrap(),
        RequestState::Unknown
    );

    // Resolving one makes room for exactly one more.
    store.resolve_request(caller(0), false).await.unwrap();
    assert_eq!(
        store
            .enqueue_request(request(cap as u8 + 1), cap)
            .await
            .unwrap(),
        RequestState::Pending
    );
}

/// F-06: the decision is reported to the sender, and does not change under a
/// retry. A rejected caller who asks again is told the same thing rather than
/// being queued a second time.
#[tokio::test]
async fn a_decision_is_final_and_a_retry_does_not_requeue() {
    let (_dir, store) = fixture().await;

    store
        .enqueue_request(request(1), MAX_PENDING)
        .await
        .unwrap();
    assert!(store.resolve_request(caller(1), false).await.unwrap());
    assert_eq!(
        store.request_state(caller(1)).await.unwrap(),
        RequestState::Rejected
    );

    // A second decision has nothing to decide.
    assert!(!store.resolve_request(caller(1), true).await.unwrap());
    assert_eq!(
        store.request_state(caller(1)).await.unwrap(),
        RequestState::Rejected,
        "a resolved request was re-decided"
    );

    // And the caller asking again learns the same, without a new row.
    assert_eq!(
        store
            .enqueue_request(request(1), MAX_PENDING)
            .await
            .unwrap(),
        RequestState::Rejected
    );
    assert!(store.pending_requests().await.unwrap().is_empty());
}

/// M8a gate 3, the storage half: the decision outlives the process, so a peer
/// accepted before a restart does not have to ask again.
#[tokio::test]
async fn acceptance_survives_a_restart() {
    let (dir, store) = fixture().await;

    store
        .enqueue_request(request(1), MAX_PENDING)
        .await
        .unwrap();
    assert!(!store.is_accepted(caller(1)).await.unwrap(), "before");
    store.resolve_request(caller(1), true).await.unwrap();
    store.close().await.unwrap();

    let reopened = Store::open(db_path(dir.path())).await.unwrap();
    assert!(reopened.is_accepted(caller(1)).await.unwrap());

    // And it is the peer row that carries it, holding no key: §8's distinction
    // between a claim that arrived and a peer §6 has authenticated survives
    // the acceptance, which is made before any handshake.
    let peer = reopened.peer(caller(1)).await.unwrap().unwrap();
    assert!(peer.accepted);
    assert_eq!(peer.identity_pk, [0u8; 32], "an unproven key was stored");
}

/// A rejection is the opposite decision, not the absence of one: it has to
/// leave the peer unaccepted even though the caller never had a peer row.
#[tokio::test]
async fn a_rejection_leaves_the_peer_unaccepted() {
    let (_dir, store) = fixture().await;

    store
        .enqueue_request(request(1), MAX_PENDING)
        .await
        .unwrap();
    store.resolve_request(caller(1), false).await.unwrap();

    assert!(!store.is_accepted(caller(1)).await.unwrap());

    // And a user who changes their mind is not blocked by the queue row being
    // final: the row is history, `peers.accepted` is the policy.
    assert!(!store.resolve_request(caller(1), true).await.unwrap());
    assert!(store.is_accepted(caller(1)).await.unwrap());
    assert_eq!(
        store.request_state(caller(1)).await.unwrap(),
        RequestState::Rejected
    );
}

/// A peer that turns up and handshakes must not be able to grant itself
/// access: `upsert_peer` runs on every session and leaves the column alone.
#[tokio::test]
async fn a_peer_sighting_does_not_change_acceptance() {
    let (_dir, store) = fixture().await;
    let sighting = |accepted| p2pchat_store::Peer {
        user_id: caller(1),
        identity_pk: [1; 32],
        display_name: None,
        first_seen: NOW,
        last_seen: Some(NOW),
        verified: false,
        accepted,
    };

    // The insert path: a first session cannot arrive already accepted.
    store.upsert_peer(sighting(true)).await.unwrap();
    assert!(!store.is_accepted(caller(1)).await.unwrap(), "on insert");

    // And the update path cannot take an acceptance away either.
    store.resolve_request(caller(1), true).await.unwrap();
    store.upsert_peer(sighting(false)).await.unwrap();
    assert!(store.is_accepted(caller(1)).await.unwrap(), "on update");
}

/// A caller who never wrote is `Unknown`, which is also what a cleared request
/// answers — §3's `CONNECTION_STATUS` has no fifth state to distinguish them.
#[tokio::test]
async fn an_unheard_of_caller_is_unknown() {
    let (_dir, store) = fixture().await;
    assert_eq!(
        store.request_state(caller(9)).await.unwrap(),
        RequestState::Unknown
    );
    assert!(!store.resolve_request(caller(9), true).await.unwrap());
}

/// M9d gate 7, the storage half: a request *we* sent is remembered across a
/// restart, so the poller that asks about it can be started again.
///
/// The IPv6 address is in there because the row stores the address as text: a
/// bracketed address that came back mangled would be a silent corruption of the
/// only field saying where to ask.
#[tokio::test]
async fn outbound_requests_survive_a_restart() {
    let (dir, store) = fixture().await;
    let one: SocketAddr = "203.0.113.7:47100".parse().unwrap();
    let two: SocketAddr = "[2001:db8::1]:47100".parse().unwrap();

    store
        .add_outbound_request(caller(1), one, NOW)
        .await
        .unwrap();
    store
        .add_outbound_request(caller(2), two, NOW + 1)
        .await
        .unwrap();
    // Asking the same peer twice is one row, not two.
    store
        .add_outbound_request(caller(1), one, NOW + 2)
        .await
        .unwrap();
    store.close().await.unwrap();

    let reopened = Store::open(db_path(dir.path())).await.unwrap();
    assert_eq!(
        reopened.outbound_requests().await.unwrap(),
        vec![(caller(1), one), (caller(2), two)],
        "oldest first, addresses intact"
    );

    // Answered, and therefore forgotten.
    reopened.remove_outbound_request(caller(1)).await.unwrap();
    assert_eq!(
        reopened.outbound_requests().await.unwrap(),
        vec![(caller(2), two)]
    );
}
