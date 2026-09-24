//! Carrying `architecture.md` §6 over a QUIC connection.
//!
//! The state machine is in `p2pchat-crypto`; this is the stream, the deadline,
//! and the generic close. Two rules live here rather than there:
//!
//! - **Fourteen seconds, from the connection opening.** A peer that connects and
//!   stops holds a connection, a stream and an ephemeral key pair for free
//!   otherwise. Every await below is against the same deadline, so no
//!   individual read can extend the total.
//! - **One error code out.** Whatever went wrong, the peer sees
//!   [`HANDSHAKE_ERROR_CODE`] and the same reason string. Which check failed is
//!   an oracle; it goes to the local log instead.

use std::future::Future;
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::time::{timeout_at, Instant};

use p2pchat_core::wire::{HelloConfirm, HelloInit, HelloResp};
use p2pchat_core::UserId;
use p2pchat_crypto::handshake::{Initiator, Responder, Session};
use p2pchat_crypto::Identity;

use crate::{channel_binding, recv_frame, send_frame, NetError};

/// `architecture.md` §6: the whole exchange, measured from the connection
/// opening.
///
/// Fourteen seconds: the slowest of 150 handshakes over an 800 ms round trip
/// with bursty loss took 13.22 s, and the next 8.47 s (M12b). The link lost
/// 16.95% of pings round trip, about 8.9% a leg against the 8% intended, so
/// the figure is conservative.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(14);

/// The one code a failed handshake closes with.
pub const HANDSHAKE_ERROR_CODE: u32 = 1;

/// The one reason string it closes with. Identical for every failure,
/// including a timeout: the peer learns that it failed and nothing else.
pub const HANDSHAKE_ERROR_REASON: &[u8] = b"handshake failed";

/// A finished handshake, and the stream it ran on.
///
/// The stream stays open: `architecture.md` §10 continues on "the conversation
/// stream", and this is it. One stream per session is what makes QUIC's
/// ordering the conversation's ordering (F-14), and reusing the one both sides
/// already hold avoids the alternative — a second stream that QUIC does not
/// deliver to the peer until something is written on it, so whichever side
/// opened it would have to speak first.
pub struct Established {
    pub session: Session,
    pub send: SendStream,
    pub recv: RecvStream,
}

/// The peer, and deliberately nothing else: [`Session`] holds the shared
/// secret, and a derived `Debug` would print it the first time a test wrote
/// `expect_err` — agent.md §2.
impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established")
            .field("peer", &self.session.peer_user_id())
            .finish_non_exhaustive()
    }
}

/// Dial side. Opens the handshake stream and runs I → R.
///
/// `expected_peer` is the user ID from the invite. Pass it whenever there is
/// one: it is check 3, and it is the difference between talking to the right
/// peer and talking to a peer.
pub async fn initiate(
    connection: &Connection,
    identity: &Identity,
    expected_peer: Option<UserId>,
) -> Result<Established, NetError> {
    finish(
        connection,
        run_initiator(connection, identity, expected_peer).await,
    )
}

/// Accept side. Takes the handshake stream the initiator opened.
pub async fn respond(
    connection: &Connection,
    identity: &Identity,
) -> Result<Established, NetError> {
    finish(connection, run_responder(connection, identity).await)
}

/// Close the connection on any failure, with the generic code.
fn finish(
    connection: &Connection,
    result: Result<Established, NetError>,
) -> Result<Established, NetError> {
    if let Err(error) = &result {
        tracing::warn!(%error, "handshake failed");
        connection.close(
            VarInt::from_u32(HANDSHAKE_ERROR_CODE),
            HANDSHAKE_ERROR_REASON,
        );
    }
    result
}

async fn run_initiator(
    connection: &Connection,
    identity: &Identity,
    expected_peer: Option<UserId>,
) -> Result<Established, NetError> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let cb = channel_binding(connection)?;

    let (state, hello) = Initiator::start(identity, &cb, expected_peer)?;
    let (mut send, mut recv) = by(deadline, connection.open_bi()).await??;
    by(deadline, send_frame(&mut send, &hello)).await??;

    let resp: HelloResp = by(deadline, recv_frame(&mut recv)).await??;
    let (session, confirm) = state.finish(&resp)?;
    by(deadline, send_frame(&mut send, &confirm)).await??;

    tracing::info!(peer = %session.peer_user_id(), "session established");
    Ok(Established {
        session,
        send,
        recv,
    })
}

async fn run_responder(
    connection: &Connection,
    identity: &Identity,
) -> Result<Established, NetError> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let cb = channel_binding(connection)?;

    let (mut send, mut recv) = by(deadline, connection.accept_bi()).await??;
    let hello: HelloInit = by(deadline, recv_frame(&mut recv)).await??;

    let (state, resp) = Responder::respond(identity, &cb, &hello)?;
    by(deadline, send_frame(&mut send, &resp)).await??;

    let confirm: HelloConfirm = by(deadline, recv_frame(&mut recv)).await??;
    let session = state.finish(&confirm)?;

    tracing::info!(peer = %session.peer_user_id(), "session established");
    Ok(Established {
        session,
        send,
        recv,
    })
}

/// Every await in the handshake goes through here, against the deadline the
/// connection opened with — so the exchange cannot outlive
/// [`HANDSHAKE_TIMEOUT`] by waiting in a different place each time.
async fn by<F: Future>(deadline: Instant, future: F) -> Result<F::Output, NetError> {
    timeout_at(deadline, future)
        .await
        .map_err(|_| NetError::HandshakeTimeout)
}
