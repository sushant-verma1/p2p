//! The public node — `architecture.md` §3.
//!
//! It answers three requests and nothing else: `PROFILE_REQUEST`,
//! `CONNECTION_REQUEST`, `CONNECTION_STATUS`. There is no authentication here
//! and there cannot be: this is the surface anyone with the address can reach,
//! and it exists so that a stranger holding an invite can ask to be let in.
//!
//! What follows from that:
//!
//! - **It asserts nothing about identity.** The profile answer is the owner's
//!   *signed* invite, so the caller verifies it rather than trusting this node
//!   (`p2pchat_crypto::invite::verify`). A `CONNECTION_REQUEST` is entirely
//!   self-declared — `display_name` most of all — and the private node
//!   re-authenticates the peer from scratch in §6.
//! - **Every caller is rate-limited** before a TLS handshake is done on their
//!   behalf; see [`Limits`].
//! - **Every wait is bounded** by [`Limits::request_timeout`], and every
//!   allocation from peer-supplied bytes is bounded by M2's frame and field
//!   limits, which [`recv_frame`] applies on the way in.
//! - **One request per connection.** A connection that has had its answer is
//!   closed rather than left open for a second question, so the cost of asking
//!   n things is n connections and n trips through the rate limiter.
//!
//! The queue itself lives in `p2pchat-store`, which this crate may not depend
//! on (§2). Requests arrive here and leave over [`PublicNode::requests`] with a
//! oneshot for the answer; the binary is what joins the two.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout_at, Instant};

use p2pchat_core::wire::{
    ConnectionRequest, Invite, PublicRequest, PublicResponse, RequestState, PROTOCOL_VERSION,
};
use p2pchat_core::UserId;

use crate::{connect, recv_frame, send_frame, NetError};

/// What the public node is allowed to spend on callers it knows nothing about.
///
/// The defaults: **ten requests per source IP per minute**, at most 1024
/// distinct sources tracked, and twenty seconds for a whole exchange. Ten a
/// minute is far above what a person pasting an invite generates — one profile
/// request, one connection request, then a status poll every few seconds — and
/// far below what a flood needs to be useful.
///
/// Twenty seconds because QUIC's loss recovery doubles its timer on every
/// consecutive loss: on an 800 ms round trip with 8% loss, four losses in a
/// row land an answer at 14.5–17.4 s and five at about 25 s (M12b, 200
/// samples, 16.35% round-trip ping loss). Twenty fails 0.5% of those, the same
/// as the 18.2 s the samples alone would give, and makes a request's give-up
/// and a dial's give-up one number — `architecture.md` §6.
///
/// The address is an IP, not an IP and port: a caller who reconnects gets a new
/// port every time, so a per-port limit would limit nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub per_source: u32,
    pub window: Duration,
    /// Sources tracked at once. The table is peer-controlled in its keys, so
    /// it has a cap of its own; see [`RateLimiter::allow`] for what happens
    /// when it is reached.
    pub max_sources: usize,
    /// Accept, read, answer: the lot.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_source: 10,
            window: Duration::from_secs(60),
            max_sources: 1024,
            request_timeout: Duration::from_secs(20),
        }
    }
}

/// A question from an unauthenticated caller, and somewhere to put the answer.
///
/// The receiver decides; this crate only carries. If the receiver is gone or
/// drops the `reply`, the caller is told nothing and the connection closes.
#[derive(Debug)]
pub struct Incoming {
    pub ask: Ask,
    /// The state, and where to dial this node privately — M9d, §10. The
    /// address is dropped here unless the state is `Accepted`, so a receiver
    /// that always fills it in still cannot leak it to a stranger.
    pub reply: oneshot::Sender<(RequestState, Option<SocketAddr>)>,
}

#[derive(Clone, Debug)]
pub enum Ask {
    /// "Let me open a private session." Every field is self-declared.
    Connect(ConnectionRequest),
    /// "What became of my request?" — keyed by the caller's claimed user ID.
    Status(UserId),
}

/// The owner's half: what to answer profile requests with, and where to send
/// the rest.
pub struct PublicNode {
    /// `architecture.md` §9, signed by the owner. Handed over verbatim.
    pub invite: Invite,
    pub limits: Limits,
    pub requests: mpsc::Sender<Incoming>,
}

impl PublicNode {
    /// The user ID this node claims to speak for. Taken from the invite so the
    /// two cannot disagree.
    pub fn owner(&self) -> UserId {
        self.invite.body.user_id
    }
}

/// Serves until `endpoint` stops accepting, which happens when it is closed or
/// dropped.
///
/// Never returns an error: a failure is one caller's problem, and a public node
/// that stopped listening because someone sent a bad frame would be a denial of
/// service with extra steps.
pub async fn serve(endpoint: Endpoint, node: PublicNode) {
    let node = Arc::new(node);
    let mut limiter = RateLimiter::new(node.limits);

    tracing::info!(owner = %node.owner(), "public node listening");

    while let Some(incoming) = endpoint.accept().await {
        let source = incoming.remote_address().ip();
        if !limiter.allow(source, Instant::now()) {
            // Refused before the TLS handshake: a flood costs us one table
            // lookup each, and never a queue slot.
            tracing::debug!(%source, "rate limited");
            incoming.refuse();
            continue;
        }

        let node = Arc::clone(&node);
        tokio::spawn(async move {
            if let Err(error) = handle(incoming, &node).await {
                tracing::debug!(%source, %error, "public request failed");
            }
        });
    }
}

/// One connection, one request, one answer, all inside the timeout.
async fn handle(incoming: quinn::Incoming, node: &PublicNode) -> Result<(), NetError> {
    let deadline = Instant::now() + node.limits.request_timeout;

    let connection = by(deadline, async { incoming.await }).await??;
    let (mut send, mut recv) = by(deadline, connection.accept_bi()).await??;
    let request: PublicRequest = by(deadline, recv_frame(&mut recv)).await??;

    // `None` is a deliberate silence: see `answer`.
    if let Some(response) = answer(node, request, deadline).await {
        by(deadline, send_frame(&mut send, &response)).await??;
        // A caller who hung up mid-answer is not an error worth a variant.
        let _ = send.finish();
        // Let the answer drain before the connection goes.
        let _ = by(deadline, send.stopped()).await?;
    }

    Ok(())
}

/// The three answers, or silence.
///
/// Silence rather than an error variant, in every case where the request is
/// not one this node can answer: `PublicResponse` is a closed enum with no
/// "no" in it (§3), and inventing one would be a wire change. The caller sees
/// a closed connection, which is all they are owed.
async fn answer(
    node: &PublicNode,
    request: PublicRequest,
    deadline: Instant,
) -> Option<PublicResponse> {
    match request {
        PublicRequest::Profile(profile) => {
            if profile.version != PROTOCOL_VERSION || profile.user_id != node.owner() {
                // "A node that is not that owner answers nothing" — §3. It also
                // means this node cannot be used to confirm a guess at who
                // lives at an address.
                return None;
            }
            Some(PublicResponse::Profile(Box::new(node.invite.clone())))
        }

        PublicRequest::Connection(connection) => {
            if connection.version != PROTOCOL_VERSION {
                return None;
            }
            tracing::info!(
                caller = %connection.from_user_id,
                "connection request received"
            );
            ask(node, Ask::Connect(connection), deadline).await
        }

        PublicRequest::Status(status) => {
            if status.version != PROTOCOL_VERSION {
                return None;
            }
            ask(node, Ask::Status(status.from_user_id), deadline).await
        }
    }
}

/// Hands the question to whoever owns the queue and waits for the answer,
/// inside the caller's deadline.
///
/// The one place the address rule of §3 is applied: it rides along only with
/// `Accepted`, so a `Pending` or `Rejected` caller learns nothing about where
/// this node listens privately.
async fn ask(node: &PublicNode, ask: Ask, deadline: Instant) -> Option<PublicResponse> {
    let (reply, answer) = oneshot::channel();
    by(deadline, node.requests.send(Incoming { ask, reply }))
        .await
        .ok()?
        .ok()?;
    let (state, addr) = by(deadline, answer).await.ok()?.ok()?;
    let addr = match state {
        RequestState::Accepted => addr,
        _ => None,
    };
    Some(PublicResponse::State(state, addr))
}

/// Every await in a public exchange goes through here, against one deadline
/// fixed when the connection arrived — so a caller cannot hold a task open by
/// being slow at each step in turn.
async fn by<F: Future>(deadline: Instant, future: F) -> Result<F::Output, NetError> {
    timeout_at(deadline, future)
        .await
        .map_err(|_| NetError::RequestTimeout)
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/// A fixed window per source IP.
///
/// ponytail: fixed window, so a caller who times it right gets up to
/// `2 * per_source` across a window boundary. A sliding window or a token
/// bucket fixes that and costs a timestamp per request; not worth it while the
/// limit is "ten a minute" and the cost of exceeding it is one refused QUIC
/// connection.
struct RateLimiter {
    limits: Limits,
    seen: HashMap<IpAddr, Window>,
}

#[derive(Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

impl RateLimiter {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            seen: HashMap::new(),
        }
    }

    /// `true` if this source may be served now.
    ///
    /// The table is keyed by something the peer chooses, so it is capped. At
    /// capacity, expired windows are dropped; if that frees nothing, a source
    /// that is not already tracked is refused — the alternative is letting a
    /// spray of forged sources evict the entries that are holding a flood
    /// back, which is the attack the cap exists for.
    fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        if self.seen.len() >= self.limits.max_sources {
            self.seen
                .retain(|_, window| now.duration_since(window.started) < self.limits.window);
        }
        let full = self.seen.len() >= self.limits.max_sources;
        let window = self.limits.window;
        let per_source = self.limits.per_source;

        match self.seen.get_mut(&source) {
            Some(existing) if now.duration_since(existing.started) >= window => {
                *existing = Window {
                    started: now,
                    count: 1,
                };
                true
            }
            Some(existing) if existing.count < per_source => {
                existing.count += 1;
                true
            }
            Some(_) => false,
            None if full => false,
            None => {
                self.seen.insert(
                    source,
                    Window {
                        started: now,
                        count: 1,
                    },
                );
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Asks a public node one question and reads the answer.
///
/// The response is *not* trusted: a `Profile` carries a signed invite that the
/// caller must verify, and a `State` is a claim by a node that has no way to
/// prove anything. `timeout` bounds the whole exchange.
pub async fn request(
    endpoint: &Endpoint,
    addr: SocketAddr,
    request: &PublicRequest,
    timeout: Duration,
) -> Result<PublicResponse, NetError> {
    let deadline = Instant::now() + timeout;

    let connection = by(deadline, connect(endpoint, addr)).await??;
    let (mut send, mut recv) = by(deadline, connection.open_bi()).await??;
    by(deadline, send_frame(&mut send, request)).await??;
    let _ = send.finish();

    let response = by(deadline, recv_frame(&mut recv)).await??;
    connection.close(0u32.into(), b"done");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    fn limits(per_source: u32, max_sources: usize) -> Limits {
        Limits {
            per_source,
            max_sources,
            ..Limits::default()
        }
    }

    fn source(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, n))
    }

    #[test]
    fn a_source_gets_its_allowance_and_no_more() {
        let mut limiter = RateLimiter::new(limits(3, 16));
        let now = Instant::now();

        for _ in 0..3 {
            assert!(limiter.allow(SOURCE, now));
        }
        assert!(!limiter.allow(SOURCE, now));
        // Still refused later in the same window.
        assert!(!limiter.allow(SOURCE, now + Duration::from_secs(59)));
    }

    #[test]
    fn one_source_does_not_spend_anothers_allowance() {
        let mut limiter = RateLimiter::new(limits(2, 16));
        let now = Instant::now();

        assert!(limiter.allow(source(1), now));
        assert!(limiter.allow(source(1), now));
        assert!(!limiter.allow(source(1), now));
        assert!(limiter.allow(source(2), now));
    }

    #[test]
    fn the_window_reopens() {
        let mut limiter = RateLimiter::new(limits(1, 16));
        let now = Instant::now();

        assert!(limiter.allow(SOURCE, now));
        assert!(!limiter.allow(SOURCE, now + Duration::from_secs(59)));
        assert!(limiter.allow(SOURCE, now + Duration::from_secs(60)));
    }

    /// The table is keyed by an attacker-chosen value, so it must not grow
    /// without bound — and filling it must not evict a source that is being
    /// held back.
    #[test]
    fn the_source_table_is_capped_and_does_not_evict_a_live_limit() {
        let mut limiter = RateLimiter::new(limits(1, 4));
        let now = Instant::now();

        for n in 0..4 {
            assert!(limiter.allow(source(n), now));
        }
        assert_eq!(limiter.seen.len(), 4);

        // A fifth source finds no room, and the four tracked ones stay refused.
        assert!(!limiter.allow(source(9), now));
        assert!(!limiter.allow(source(0), now));
        assert_eq!(limiter.seen.len(), 4);

        // Once the windows lapse, the table clears itself.
        let later = now + Duration::from_secs(61);
        assert!(limiter.allow(source(9), later));
        assert!(limiter.seen.len() <= 4);
    }
}
