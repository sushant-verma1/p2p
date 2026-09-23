//! M4 gate — `architecture.md` §6 over a real QUIC connection.
//!
//! The happy path, then every way it is supposed to fail, one test each:
//!
//!  1. a bad signature on `HELLO_RESP`;
//!  2. a bad signature on `HELLO_CONFIRM`;
//!  3. `BLAKE3(domain ‖ identity_pk) != user_id`;
//!  4. an outbound connection to an unexpected peer ID;
//!  5. a `HELLO_INIT` replayed from a completed session;
//!  6. a `HELLO_CONFIRM` injected into a different connection;
//!  7. a QUIC-level proxy between the parties (F-10);
//!  8. an all-zero ephemeral public key, and its small-order cousin;
//!  9. a handshake abandoned after `HELLO_INIT`, which must abort within 10 s;
//! 10. no failure path telling the peer which check failed.
//!
//! Every test but (9) runs under [`PATIENCE`], which is deliberately shorter
//! than the handshake deadline: a check that "fails" only by letting the
//! exchange time out is not the check the gate asked for, and should show up
//! as a hang, not as a slow pass.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pchat_core::wire::{HelloConfirm, HelloInit, HelloResp, Signature};
use p2pchat_core::UserId;
use p2pchat_crypto::handshake::{Initiator, Responder};
use p2pchat_crypto::Identity;
use p2pchat_net::handshake::{initiate, respond, Established, HANDSHAKE_TIMEOUT};
use p2pchat_net::{
    channel_binding, client_endpoint, connect, recv_frame, send_frame, server_endpoint, NetError,
    NodeKind,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::task::JoinHandle;

/// Shorter than [`HANDSHAKE_TIMEOUT`] on purpose — see the module comment.
const PATIENCE: Duration = Duration::from_secs(5);

async fn patiently<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("the handshake should have resolved long before PATIENCE")
}

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// A private-node endpoint that accepts one connection and runs `logic` on it.
///
/// The endpoint is returned as well as spawned: dropping it would tear down the
/// connection, and several of these tests are about what the peer sees *after*
/// a rejection.
fn listen<F, Fut, T>(logic: F) -> (Endpoint, SocketAddr, JoinHandle<T>)
where
    F: FnOnce(Connection) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let endpoint = server_endpoint(loopback(), NodeKind::Private).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();
    let handle = tokio::spawn(async move {
        let connection = accepting.accept().await.unwrap().await.unwrap();
        logic(connection).await
    });
    (endpoint, addr, handle)
}

/// The honest responder.
fn listen_responder(
    identity: Arc<Identity>,
) -> (
    Endpoint,
    SocketAddr,
    JoinHandle<Result<Established, NetError>>,
) {
    listen(move |connection| async move { respond(&connection, &identity).await })
}

/// The client endpoint comes back too, for the same reason as in [`listen`].
async fn dial(addr: SocketAddr) -> (Endpoint, Connection) {
    let endpoint = client_endpoint(NodeKind::Private).unwrap();
    let connection = connect(&endpoint, addr).await.unwrap();
    (endpoint, connection)
}

/// A well-formed `HELLO_INIT` for this identity on this connection, which the
/// caller is free to bend out of shape.
///
/// The initiator state is dropped: these tests need the message, not the rest
/// of the exchange. Built by the real code so that "well-formed" cannot drift.
fn hello_init(identity: &Identity, cb: &[u8; 32]) -> HelloInit {
    Initiator::start(identity, cb, None).unwrap().1
}

/// One flipped bit in `R`. Enough to make Ed25519 verification fail, without
/// straying into the separate question of what a malformed signature does.
fn corrupt(signature: Signature) -> Signature {
    let mut bytes = *signature.as_bytes();
    bytes[0] ^= 1;
    Signature::from_bytes(bytes)
}

fn assert_generic(error: NetError) {
    assert_eq!(
        error.to_string(),
        "handshake failed",
        "the local error should be the generic one"
    );
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_peers_complete_the_handshake_and_agree() {
    patiently(async {
        let initiator = Identity::generate();
        let responder = Arc::new(Identity::generate());
        let responder_id = responder.user_id();

        let (_endpoint, addr, task) = listen_responder(responder.clone());
        let (_client, connection) = dial(addr).await;

        // The conversation stream comes back with the session; M8 is what
        // uses it.
        let session_i = initiate(&connection, &initiator, Some(responder_id))
            .await
            .unwrap()
            .session;
        let session_r = task.await.unwrap().unwrap().session;

        assert_eq!(
            session_i.shared_secret().as_slice(),
            session_r.shared_secret().as_slice(),
            "the two sides derived different secrets"
        );
        assert_eq!(session_i.transcript_hash(), session_r.transcript_hash());
        assert_eq!(session_i.peer_user_id(), responder_id);
        assert_eq!(session_r.peer_user_id(), initiator.user_id());
        assert_eq!(session_i.peer_identity_pk(), responder.identity_pk());
    })
    .await;
}

// ---------------------------------------------------------------------------
// 1. Bad signature on HELLO_RESP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bad_signature_on_hello_resp_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let responder = Arc::new(Identity::generate());
        let responder_id = responder.user_id();

        // An otherwise perfect responder with one bit wrong in `sig_r`.
        let (_endpoint, addr, _task) = listen(move |connection| async move {
            let cb = channel_binding(&connection).unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let hello: HelloInit = recv_frame(&mut recv).await.unwrap();
            let (_state, mut resp) = Responder::respond(&responder, &cb, &hello).unwrap();
            resp.sig_r = corrupt(resp.sig_r);
            send_frame(&mut send, &resp).await.unwrap();
            connection.closed().await;
        });

        let (_client, connection) = dial(addr).await;
        let error = initiate(&connection, &initiator, Some(responder_id))
            .await
            .expect_err("a corrupt sig_r must not produce a session");
        assert_generic(error);
    })
    .await;
}

// ---------------------------------------------------------------------------
// 2. Bad signature on HELLO_CONFIRM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bad_signature_on_hello_confirm_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let (_endpoint, addr, task) = listen_responder(Arc::new(Identity::generate()));
        let (_client, connection) = dial(addr).await;

        let cb = channel_binding(&connection).unwrap();
        let (state, hello) = Initiator::start(&initiator, &cb, None).unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_frame(&mut send, &hello).await.unwrap();

        let resp: HelloResp = recv_frame(&mut recv).await.unwrap();
        let (_session, mut confirm) = state.finish(&resp).unwrap();
        confirm.sig_i = corrupt(confirm.sig_i);
        send_frame(&mut send, &confirm).await.unwrap();

        assert_generic(task.await.unwrap().expect_err("a corrupt sig_i must not"));
    })
    .await;
}

// ---------------------------------------------------------------------------
// 3. The claimed user ID does not bind to the identity key
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_user_id_that_does_not_bind_to_the_key_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let (_endpoint, addr, task) = listen_responder(Arc::new(Identity::generate()));
        let (_client, connection) = dial(addr).await;

        let cb = channel_binding(&connection).unwrap();
        let mut hello = hello_init(&initiator, &cb);
        // Everything else is genuine; the ID is simply someone else's.
        hello.user_id_i = UserId::from_bytes([9; 32]);

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_frame(&mut send, &hello).await.unwrap();

        // Rejected on receipt: no HELLO_RESP comes back at all.
        recv_frame::<HelloResp>(&mut recv)
            .await
            .expect_err("the responder answered a forged identity");
        assert_generic(task.await.unwrap().expect_err("check 2 must reject this"));
    })
    .await;
}

// ---------------------------------------------------------------------------
// 4. Outbound connection to an unexpected peer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_outbound_connection_to_the_wrong_peer_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let (_endpoint, addr, _task) = listen_responder(Arc::new(Identity::generate()));
        let (_client, connection) = dial(addr).await;

        // Whoever answers, it is not the peer from the invite.
        let expected = Identity::generate().user_id();
        let error = initiate(&connection, &initiator, Some(expected))
            .await
            .expect_err("check 3 must reject a peer that is not the expected one");
        assert_generic(error);
    })
    .await;
}

// ---------------------------------------------------------------------------
// 5. A completed session replayed wholesale
// ---------------------------------------------------------------------------

/// Captures the two initiator messages of a real, successful handshake.
async fn capture_session(
    initiator: &Identity,
    responder: Arc<Identity>,
) -> (HelloInit, HelloConfirm) {
    let (_endpoint, addr, task) = listen_responder(responder);
    let (_client, connection) = dial(addr).await;

    let cb = channel_binding(&connection).unwrap();
    let (state, hello) = Initiator::start(initiator, &cb, None).unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send_frame(&mut send, &hello).await.unwrap();
    let resp: HelloResp = recv_frame(&mut recv).await.unwrap();
    let (_session, confirm) = state.finish(&resp).unwrap();
    send_frame(&mut send, &confirm).await.unwrap();

    task.await.unwrap().expect("the captured session was real");
    (hello, confirm)
}

#[tokio::test]
async fn a_recorded_session_replayed_wholesale_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let responder = Arc::new(Identity::generate());
        let (hello, confirm) = capture_session(&initiator, responder.clone()).await;

        // A new connection to the same peer, with both recorded messages. The
        // attacker holds no secret key, so this is everything it has.
        let (_endpoint, addr, task) = listen_responder(responder);
        let (_client, connection) = dial(addr).await;
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send_frame(&mut send, &hello).await.unwrap();

        // The replayed HELLO_INIT is accepted — it is well formed, and there is
        // nothing in it to be stale against. The session it belongs to is what
        // cannot be replayed: this connection has a different channel binding
        // and a fresh nonce_r, so the recorded sig_i covers the wrong bytes.
        let _resp: HelloResp = recv_frame(&mut recv).await.unwrap();
        send_frame(&mut send, &confirm).await.unwrap();

        assert_generic(task.await.unwrap().expect_err("a replay must not succeed"));
    })
    .await;
}

// ---------------------------------------------------------------------------
// 6. A HELLO_CONFIRM spliced into another connection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_hello_confirm_from_another_connection_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let responder = Arc::new(Identity::generate());

        // Two live handshakes, same two identities, running at once.
        let mut sides = Vec::new();
        for _ in 0..2 {
            let (endpoint, addr, task) = listen_responder(responder.clone());
            let (client, connection) = dial(addr).await;
            let cb = channel_binding(&connection).unwrap();
            let (state, hello) = Initiator::start(&initiator, &cb, None).unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send_frame(&mut send, &hello).await.unwrap();
            let resp: HelloResp = recv_frame(&mut recv).await.unwrap();
            let (_session, confirm) = state.finish(&resp).unwrap();
            sides.push((endpoint, client, connection, send, task, confirm));
        }

        // Swap the confirmations over.
        let confirm_a = sides[0].5;
        let confirm_b = sides[1].5;
        send_frame(&mut sides[0].3, &confirm_b).await.unwrap();
        send_frame(&mut sides[1].3, &confirm_a).await.unwrap();

        for side in sides {
            assert_generic(
                side.4
                    .await
                    .unwrap()
                    .expect_err("a spliced HELLO_CONFIRM must not verify"),
            );
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// 7. A QUIC-level proxy — F-10
// ---------------------------------------------------------------------------

/// Copies one stream into another until either end stops.
async fn relay(mut from: RecvStream, mut to: SendStream) {
    let mut buf = [0u8; 2048];
    while let Ok(Some(n)) = from.read(&mut buf).await {
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A man in the middle at the QUIC layer: it terminates the initiator's
/// connection, opens its own to the real responder, and forwards the handshake
/// bytes verbatim in both directions.
///
/// The permissive certificate verifier is what lets it get this far, and that
/// is the point — the certificate was never the defence. Both connections are
/// real and independent, so each has its own channel binding, which is the one
/// thing the proxy cannot forge its way around.
fn proxy(target: SocketAddr) -> (Endpoint, SocketAddr) {
    let endpoint = server_endpoint(loopback(), NodeKind::Private).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();

    tokio::spawn(async move {
        let victim = accepting.accept().await.unwrap().await.unwrap();
        let (_client, upstream) = dial(target).await;

        let (to_victim, from_victim) = victim.accept_bi().await.unwrap();
        let (to_upstream, from_upstream) = upstream.open_bi().await.unwrap();

        // `select!`, not `join!`: when one direction dies the connection is
        // over, and a real proxy would not sit holding the other half open.
        tokio::select! {
            _ = relay(from_victim, to_upstream) => {}
            _ = relay(from_upstream, to_victim) => {}
        }
    });

    (endpoint, addr)
}

#[tokio::test]
async fn a_quic_level_proxy_between_the_parties_is_rejected() {
    patiently(async {
        let initiator = Identity::generate();
        let responder = Arc::new(Identity::generate());
        let responder_id = responder.user_id();

        let (_endpoint, real_addr, task) = listen_responder(responder);
        let (_proxy_endpoint, proxy_addr) = proxy(real_addr);

        let (_client, connection) = dial(proxy_addr).await;
        let error = initiate(&connection, &initiator, Some(responder_id))
            .await
            .expect_err("the channel binding must break a relayed handshake");
        assert_generic(error);

        // And the responder gets no session either: it signed over its own
        // channel binding, so the confirmation it is waiting for can never
        // arrive.
        assert!(task.await.unwrap().is_err());
    })
    .await;
}

// ---------------------------------------------------------------------------
// 8. Degenerate ephemeral keys
// ---------------------------------------------------------------------------

/// Sends a `HELLO_INIT` whose ephemeral public key is `eph_pk_i` and asserts
/// that the responder refuses it without answering.
async fn reject_ephemeral(eph_pk_i: [u8; 32]) {
    let initiator = Identity::generate();
    let (_endpoint, addr, task) = listen_responder(Arc::new(Identity::generate()));
    let (_client, connection) = dial(addr).await;

    let cb = channel_binding(&connection).unwrap();
    let mut hello = hello_init(&initiator, &cb);
    hello.eph_pk_i = eph_pk_i;

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send_frame(&mut send, &hello).await.unwrap();

    recv_frame::<HelloResp>(&mut recv)
        .await
        .expect_err("the responder answered a degenerate ephemeral key");
    assert_generic(task.await.unwrap().expect_err("check 5 must reject this"));
}

#[tokio::test]
async fn an_all_zero_ephemeral_key_is_rejected() {
    patiently(reject_ephemeral([0u8; 32])).await;
}

/// The all-zero key is the famous one, but it is not the only point of small
/// order. `u = 1` has order 4 and is not caught by any "is it zero" test —
/// only by `was_contributory()`, which is why §6 names that function.
#[tokio::test]
async fn a_small_order_ephemeral_key_is_rejected() {
    let mut order_four = [0u8; 32];
    order_four[0] = 1;
    patiently(reject_ephemeral(order_four)).await;
}

// ---------------------------------------------------------------------------
// 9. Abandoned after HELLO_INIT
// ---------------------------------------------------------------------------

/// Not wrapped in [`PATIENCE`]: this one is about the deadline itself.
#[tokio::test]
async fn a_handshake_abandoned_after_hello_init_times_out() {
    let initiator = Identity::generate();
    let (_endpoint, addr, task) = listen_responder(Arc::new(Identity::generate()));
    let (_client, connection) = dial(addr).await;

    let cb = channel_binding(&connection).unwrap();
    let hello = hello_init(&initiator, &cb);
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send_frame(&mut send, &hello).await.unwrap();

    // The connection stays open and healthy; the peer simply stops talking.
    let start = Instant::now();
    let error = tokio::time::timeout(HANDSHAKE_TIMEOUT * 2, task)
        .await
        .expect("the responder waited past twice the deadline")
        .unwrap()
        .expect_err("an unfinished handshake must not produce a session");
    let waited = start.elapsed();

    assert!(
        matches!(error, NetError::HandshakeTimeout),
        "expected a timeout, got {error}"
    );
    assert!(
        waited < HANDSHAKE_TIMEOUT + Duration::from_secs(2),
        "the abort took {waited:?}, which is past the 10 s in §6"
    );
    eprintln!("responder aborted after {waited:?}");
}

// ---------------------------------------------------------------------------
// 10. No oracle
// ---------------------------------------------------------------------------

/// Runs a doomed handshake and returns what the peer was told about it.
///
/// `bend` breaks the `HELLO_INIT`; a handshake that survives that is finished
/// off with a garbage `HELLO_CONFIRM`, so the four scenarios below fail at four
/// different checks.
async fn peer_visible_failure(bend: impl FnOnce(&mut HelloInit)) -> String {
    let initiator = Identity::generate();
    let (_endpoint, addr, task) = listen_responder(Arc::new(Identity::generate()));
    let (_client, connection) = dial(addr).await;

    let cb = channel_binding(&connection).unwrap();
    let mut hello = hello_init(&initiator, &cb);
    bend(&mut hello);

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send_frame(&mut send, &hello).await.unwrap();
    if recv_frame::<HelloResp>(&mut recv).await.is_ok() {
        let confirm = HelloConfirm {
            sig_i: Signature::from_bytes([0u8; 64]),
        };
        let _ = send_frame(&mut send, &confirm).await;
    }

    let told = connection.closed().await.to_string();
    assert!(task.await.unwrap().is_err());
    told
}

#[tokio::test]
async fn no_failure_tells_the_peer_which_check_failed() {
    patiently(async {
        let told = [
            // Check 1.
            peer_visible_failure(|hello| hello.version = 2).await,
            // Check 2.
            peer_visible_failure(|hello| hello.user_id_i = UserId::from_bytes([9; 32])).await,
            // Check 5.
            peer_visible_failure(|hello| hello.eph_pk_i = [0u8; 32]).await,
            // Check 4, at HELLO_CONFIRM.
            peer_visible_failure(|_| {}).await,
        ];

        assert!(
            told.iter().all(|seen| *seen == told[0]),
            "the peer can tell these failures apart: {told:#?}"
        );
        assert!(
            told[0].contains("handshake failed"),
            "unexpected close: {}",
            told[0]
        );
    })
    .await;
}
