//! Carrying `architecture.md` §6 over a QUIC connection.
//!
//! The state machine is in `p2pchat-crypto`; this is the stream, the deadline,
//! and the generic close. Two rules live here rather than there:
//!
//! - **Ten seconds, from the connection opening.** A peer that connects and
//!   stops holds a connection, a stream and an ephemeral key pair for free
//!   otherwise. Every await below is against the same deadline, so no
//!   individual read can extend the total.
//! - **One error code out.** Whatever went wrong, the peer sees
//!   [`HANDSHAKE_ERROR_CODE`] and the same reason string. Which check failed is
//!   an oracle; it goes to the local log instead.

use std::future::Future;
use std::time::Duration;

use quinn::{Connection, VarInt};
use tokio::time::{timeout_at, Instant};

use p2pchat_core::wire::{HelloConfirm, HelloInit, HelloResp};
use p2pchat_core::UserId;
use p2pchat_crypto::handshake::{Initiator, Responder, Session};
use p2pchat_crypto::Identity;

use crate::{channel_binding, recv_frame, send_frame, NetError};

/// `architecture.md` §6: the whole exchange, measured from the connection
/// opening.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The one code a failed handshake closes with.
pub const HANDSHAKE_ERROR_CODE: u32 = 1;

/// The one reason string it closes with. Identical for every failure,
/// including a timeout: the peer learns that it failed and nothing else.
pub const HANDSHAKE_ERROR_REASON: &[u8] = b"handshake failed";

/// Dial side. Opens the handshake stream and runs I → R.
///
/// `expected_peer` is the user ID from the invite. Pass it whenever there is
/// one: it is check 3, and it is the difference between talking to the right
/// peer and talking to a peer.
pub async fn initiate(
    connection: &Connection,
    identity: &Identity,
    expected_peer: Option<UserId>,
) -> Result<Session, NetError> {
    finish(
        connection,
        run_initiator(connection, identity, expected_peer).await,
    )
}

/// Accept side. Takes the handshake stream the initiator opened.
pub async fn respond(connection: &Connection, identity: &Identity) -> Result<Session, NetError> {
    finish(connection, run_responder(connection, identity).await)
}

/// Close the connection on any failure, with the generic code.
fn finish(connection: &Connection, result: Result<Session, NetError>) -> Result<Session, NetError> {
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
) -> Result<Session, NetError> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let cb = channel_binding(connection)?;

    let (state, hello) = Initiator::start(identity, &cb, expected_peer)?;
    let (mut send, mut recv) = by(deadline, connection.open_bi()).await??;
    by(deadline, send_frame(&mut send, &hello)).await??;

    let resp: HelloResp = by(deadline, recv_frame(&mut recv)).await??;
    let (session, confirm) = state.finish(&resp)?;
    by(deadline, send_frame(&mut send, &confirm)).await??;

    tracing::info!(peer = %session.peer_user_id(), "session established");
    Ok(session)
}

async fn run_responder(connection: &Connection, identity: &Identity) -> Result<Session, NetError> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let cb = channel_binding(connection)?;

    let (mut send, mut recv) = by(deadline, connection.accept_bi()).await??;
    let hello: HelloInit = by(deadline, recv_frame(&mut recv)).await??;

    let (state, resp) = Responder::respond(identity, &cb, &hello)?;
    by(deadline, send_frame(&mut send, &resp)).await??;

    let confirm: HelloConfirm = by(deadline, recv_frame(&mut recv)).await??;
    let session = state.finish(&confirm)?;

    tracing::info!(peer = %session.peer_user_id(), "session established");
    Ok(session)
}

/// Every await in the handshake goes through here, against the deadline the
/// connection opened with — so the exchange cannot outlive
/// [`HANDSHAKE_TIMEOUT`] by waiting in a different place each time.
async fn by<F: Future>(deadline: Instant, future: F) -> Result<F::Output, NetError> {
    timeout_at(deadline, future)
        .await
        .map_err(|_| NetError::HandshakeTimeout)
}
