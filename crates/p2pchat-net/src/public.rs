//! The public node — `architecture.md` §3.
//!
//! It answers six requests and nothing else: `PROFILE_REQUEST`,
//! `CONNECTION_REQUEST`, `CONNECTION_STATUS`, M14's `DIAL_BACK`, M14b's
//! `FORWARD_DIAL_BACK`, and M16's DHT queries, which it hands to [`Dht`] when
//! this node is a member. There is no authentication here
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
    ConnectionRequest, ForwardDialBack, Invite, PublicRequest, PublicResponse, RequestState,
    DIAL_BACK_NONCE_LEN, PROTOCOL_VERSION,
};
use p2pchat_core::UserId;

use crate::dht::Dht;
use crate::{
    client_config_offering, connect_as, recv_frame, send_frame, NetError, NodeKind, DIAL_BACK_ALPN,
    SERVER_NAME,
};

/// What the public node is allowed to spend on callers it knows nothing about.
///
/// The defaults: **ten requests per source IP per minute**, at most 1024
/// distinct sources tracked, and twenty seconds for a whole exchange.
///
/// Ten is the stranger allowance. A passed forwarded dial-back earns the
/// separate member allowance below; an on-wire `Member` claim or routing-table
/// entry earns nothing. The 30-second-refresh simulation has a harness-only
/// allowance override because it runs maintenance thirty times faster than the
/// product's shipped refresh.
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
    /// How long a dial-back may take, connect to close — M14. Since M14b it
    /// is the second member's dial. The asked member waits for the whole
    /// forward inside its own `request_timeout` instead, so that a blocked
    /// dial-back reads as "forwarded, not reached" rather than timing the
    /// forward out as "no second member".
    pub dial_back_timeout: Duration,
    /// Forwarded dial-backs a member performs for one target IP per
    /// `window`, whoever forwards them — M14b. A reachability test is one
    /// request per network change or per `reach::RETEST`, so two leaves room
    /// for a retry and caps what anyone can aim at one address at two QUIC
    /// attempts a minute from this member.
    pub forward_per_target: u32,
    /// How long the asked member waits for one other member to take a
    /// forward, dial, and answer — M14b. It covers that member's
    /// `dial_back_timeout` plus a connect each way, and it is what stops a
    /// dead member costing the requester its whole request.
    pub forward_timeout: Duration,
    /// Requests a member's IP may make per `window`, in place of
    /// `per_source` — M14b. A member here is an IP in `PublicNode::members`,
    /// or one this node has seen pass a forwarded dial-back ([`PROVEN_FOR`],
    /// M16a) — never one that merely names itself a member or holds a slot
    /// in the routing table. Counted before the TLS handshake like every
    /// other source, so it is the per-forwarder limit on forwarded
    /// dial-backs: thirty covers a busy member forwarding for many
    /// requesters, and bounds what one member that lies about what it
    /// observed can make this one dial.
    pub forward_per_member: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_source: 10,
            window: Duration::from_secs(60),
            max_sources: 1024,
            request_timeout: Duration::from_secs(20),
            // Twelve seconds, from `netem/tail.py --dialbacks` with the
            // limits raised. Under `bad` (800 ms round trip, 8% loss a leg)
            // the dial alone took p99 9.04 s, max 13.41 s over M14a's 200
            // samples (member dialling directly), and p99 10.42 s, max 11.54 s
            // over M14b's 200 (second member dialling, on the forwarded path).
            // Twelve misses 1 of those 400. That tail rests on very few
            // samples — the one miss and M14b's four over 10 s — so it is an
            // estimate, not a bound. A miss makes a node a client, the safe
            // way to be wrong, and it is asked again at the next network
            // change or `reach::RETEST`. `poor` never came near it: max 4.45 s.
            dial_back_timeout: Duration::from_secs(12),
            forward_per_target: 2,
            // The dial-back plus four seconds to reach the second member and
            // hear back. M14b, `bad`, 200 samples: the whole forward took p99
            // 14.72 s, max 17.68 s, so sixteen misses 1 in 200. It stays at
            // sixteen because the requester's 20 s covers this and its own
            // connect and answer, which took about 3 s at the median; a longer
            // forward would mostly finish after the requester had given up.
            forward_timeout: Duration::from_secs(16),
            // Three times `per_source`, so a passed dial-back meaningfully
            // changes the allowance. The compressed-clock harness sets its
            // own higher value, without changing product defaults.
            forward_per_member: 30,
        }
    }
}

/// How long a passed dial-back keeps its IP on the member allowance — M16a.
/// Twice the requester's re-test interval (`reach::RETEST`, 30 minutes), so
/// one missed re-test does not drop a member to a stranger's allowance.
pub const PROVEN_FOR: Duration = Duration::from_secs(60 * 60);

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
    /// Other members' public nodes — M14b. A dial-back request is forwarded
    /// to one of these, and a forwarded one is accepted only from one of
    /// these IPs. Empty: this node answers every dial-back request with
    /// "not forwarded" and refuses every forward.
    pub members: Vec<SocketAddr>,
    /// The DHT, when this node is a member — M16. `None`: DHT queries get
    /// silence, as any request this node will not answer does.
    pub dht: Option<Arc<Dht>>,
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
    serve_with_proven(endpoint, node, []).await;
}

/// Serves a public node with IPs that the caller has independently established
/// as having passed a forwarded dial-back. Production starts with no such
/// fixture; `p2pchat dht` uses it only to model the already-proven member
/// population in its network harness.
pub async fn serve_with_proven(
    endpoint: Endpoint,
    node: PublicNode,
    initially_proven: impl IntoIterator<Item = IpAddr>,
) {
    let mut limiter = RateLimiter::new(node.limits);
    let mut from_members = RateLimiter::new(Limits {
        per_source: node.limits.forward_per_member,
        ..node.limits
    });
    let serving = Arc::new(Serving {
        by_target: std::sync::Mutex::new(RateLimiter::new(Limits {
            per_source: node.limits.forward_per_target,
            ..node.limits
        })),
        proven: std::sync::Mutex::new(Proven::with(
            node.limits.max_sources,
            initially_proven,
            Instant::now(),
        )),
        dialler: dial_back_endpoint(&endpoint),
        own: endpoint.local_addr().ok(),
        node,
    });

    tracing::info!(owner = %serving.node.owner(), "public node listening");

    while let Some(incoming) = endpoint.accept().await {
        let source = incoming.remote_address().ip();
        // A member's IP has its own allowance, so the members' forwards are
        // limited by `forward_per_member` rather than by a stranger's ten.
        // A member is one the config names, or one that has shown it can be
        // reached — M16a. Not one that says so: a `Member` in a DHT request
        // is the sender's word, and a routing-table slot is one request's
        // worth of that word, so neither raises anything here.
        let member = serving.node.members.iter().any(|m| m.ip() == source)
            || serving.proven().holds(source, Instant::now());
        let allowed = if member {
            from_members.allow(source, Instant::now())
        } else {
            limiter.allow(source, Instant::now())
        };
        if !allowed {
            // Refused before the TLS handshake: a flood costs us one table
            // lookup each, and never a queue slot.
            tracing::debug!(%source, member, "rate limited");
            incoming.refuse();
            continue;
        }
        // What `netem/dht.py demand` counts: every request the limiter let
        // through, per source, as the limiter saw it.
        tracing::debug!(%source, member, "admitted");

        let serving = Arc::clone(&serving);
        tokio::spawn(async move {
            if let Err(error) = handle(incoming, &serving).await {
                tracing::debug!(%source, %error, "public request failed");
            }
        });
    }
}

/// Everything the per-connection tasks share.
struct Serving {
    node: PublicNode,
    /// Where forwards and dial-backs leave from.
    dialler: Option<Endpoint>,
    /// The public endpoint's own address, so a member does not forward to
    /// itself when its own entry is in `members`.
    own: Option<SocketAddr>,
    /// Forwarded dial-backs per target IP — `Limits::forward_per_target`.
    by_target: std::sync::Mutex<RateLimiter>,
    /// IPs that passed a forwarded dial-back this node took part in.
    proven: std::sync::Mutex<Proven>,
}

impl Serving {
    fn proven(&self) -> std::sync::MutexGuard<'_, Proven> {
        self.proven
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Where forwards and forwarded dial-backs leave from: a socket of its own, on
/// the public endpoint's IP — M14, M14b.
///
/// Not the public endpoint's socket, so that nothing this node sends looks
/// like a reply to anything a requester sent it. Since M14b a member never
/// dials a requester that asked it: a NAT that filters on IP alone has this
/// member's IP open for that requester, whatever the port. The dial comes from
/// the second member, whose IP the requester never sent to.
fn dial_back_endpoint(endpoint: &Endpoint) -> Option<Endpoint> {
    let made = endpoint
        .local_addr()
        .and_then(|addr| Endpoint::client(SocketAddr::new(addr.ip(), 0)));
    match made {
        Ok(dialler) => Some(dialler),
        Err(error) => {
            // Dial-back requests then go unanswered, which a requester reads
            // as "not shown reachable": the safe reading.
            tracing::warn!(%error, "no dial-back socket; dial-back requests go unanswered");
            None
        }
    }
}

/// One connection, one request, one answer, all inside the timeout.
async fn handle(incoming: quinn::Incoming, serving: &Serving) -> Result<(), NetError> {
    let deadline = Instant::now() + serving.node.limits.request_timeout;

    let connection = by(deadline, async { incoming.await }).await??;
    let (mut send, mut recv) = by(deadline, connection.accept_bi()).await??;
    let request: PublicRequest = by(deadline, recv_frame(&mut recv)).await??;

    // Taken from the connection, never from the request: see `DialBackRequest`.
    let from = connection.remote_address();
    // The IP the caller sent to, which on a wildcard bind the socket's own
    // address does not say — M17, and see `forward`.
    let to = connection.local_ip();

    // `None` is a deliberate silence: see `answer`.
    if let Some(response) = answer(serving, request, deadline, from, to).await {
        by(deadline, send_frame(&mut send, &response)).await??;
        // A caller who hung up mid-answer is not an error worth a variant.
        let _ = send.finish();
        // Let the answer drain before the connection goes.
        let _ = by(deadline, send.stopped()).await?;
    }

    Ok(())
}

/// The six answers, or silence.
///
/// Silence rather than an error variant, in every case where the request is
/// not one this node can answer: `PublicResponse` is a closed enum with no
/// "no" in it (§3), and inventing one would be a wire change. The caller sees
/// a closed connection, which is all they are owed.
async fn answer(
    serving: &Serving,
    request: PublicRequest,
    deadline: Instant,
    from: SocketAddr,
    to: Option<IpAddr>,
) -> Option<PublicResponse> {
    let node = &serving.node;
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

        PublicRequest::DialBack(request) => {
            if request.version != PROTOCOL_VERSION {
                return None;
            }
            // The one address a dial-back goes to is `from`: where this
            // connection came from, which the QUIC handshake has already
            // proved answers, since nobody completes one from a forged
            // source. The request names no address, so there is none for a
            // requester to choose. This member never dials it itself — see
            // `dial_back_endpoint` — and never falls back to doing so when no
            // second member answers: that answer is "not forwarded".
            let started = Instant::now();
            let reached = forward(serving, from, to, request.nonce, deadline).await;
            if reached == Some(true) {
                // B's word, and B is a member: this node forwarded, B dialled
                // `from` from a fresh socket and was answered with the nonce.
                serving.proven().prove(from.ip(), Instant::now());
            }
            // `elapsed_ms` is what `netem/tail.py --dialbacks` measures the
            // timeout against: the whole forwarded attempt.
            tracing::info!(
                %from,
                forwarded = reached.is_some(),
                reached = reached.unwrap_or(false),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "dial-back"
            );
            Some(PublicResponse::DialBack {
                observed: from,
                forwarded: reached.is_some(),
                reached: reached.unwrap_or(false),
            })
        }

        PublicRequest::ForwardDialBack(forwarded) => {
            if forwarded.version != PROTOCOL_VERSION {
                return None;
            }
            // `target` is the forwarder's word for what it observed, and
            // cannot be checked from here. So only a member this node already
            // knows may give it, and only as often as the per-member and
            // per-target limits allow: a member that lies can aim at most
            // that many single QUIC attempts, and anyone else aims nothing.
            // A non-member gets silence, as for any request this node will
            // not answer.
            if !node.members.iter().any(|member| member.ip() == from.ip()) {
                tracing::debug!(%from, "a forwarded dial-back from a non-member");
                return None;
            }
            let allowed = serving
                .by_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .allow(forwarded.target.ip(), Instant::now());
            if !allowed {
                // Answered, not silent: the forwarder is a member, and
                // silence would read to it as "no second member", which is
                // not what happened. Nothing is dialled either way.
                tracing::debug!(%from, target = %forwarded.target, "forwarded dial-back rate limited");
                return Some(PublicResponse::Forwarded { reached: false });
            }
            let started = Instant::now();
            let until = deadline.min(started + node.limits.dial_back_timeout);
            // From a socket made for this one dial-back. A reused socket is
            // one the target may have answered before, and an
            // endpoint-dependent NAT keeps that mapping open for minutes, so
            // a re-test inside that time would pass on the last test's hole.
            let reached = match serving
                .own
                .map(|own| Endpoint::client(SocketAddr::new(own.ip(), 0)))
            {
                Some(Ok(dialler)) => {
                    dial_back(&dialler, forwarded.target, forwarded.nonce, until).await
                }
                _ => false,
            };
            if reached {
                // Seen here: this node dialled it, from a socket the target
                // never sent to, and it took the nonce.
                serving
                    .proven()
                    .prove(forwarded.target.ip(), Instant::now());
            }
            tracing::info!(
                forwarder = %from,
                target = %forwarded.target,
                reached,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "forwarded dial-back"
            );
            Some(PublicResponse::Forwarded { reached })
        }

        // `from` is the connection's address: a member asking is entered at
        // that IP, whatever it claims.
        PublicRequest::Dht(request) => node
            .dht
            .as_ref()?
            .answer(request, from)
            .map(PublicResponse::Dht),
    }
}

/// Hands `target`'s dial-back to another member, trying each in turn until
/// one answers — M14b. `None` when none did: no second member, which the
/// requester reads as inconclusive. Never a dial from here instead.
///
/// A member at the IP the request was sent to is skipped: this one, and any
/// other member sharing its IP, would be dialling from an address the
/// requester has, by definition, sent to. `asked` is that IP, from the
/// connection. Comparing against the socket's own address is not enough: on a
/// wildcard bind that is `0.0.0.0`, which matches no member entry, and until
/// M17 a member bound that way (the default) that listed itself forwarded to
/// itself, and every requester came out a client. `None`, where the platform
/// does not say, falls back to the socket's address. A member whose IP is the
/// requester's is skipped as well.
async fn forward(
    serving: &Serving,
    target: SocketAddr,
    asked: Option<IpAddr>,
    nonce: [u8; DIAL_BACK_NONCE_LEN],
    until: Instant,
) -> Option<bool> {
    let dialler = serving.dialler.as_ref()?;
    let forward = PublicRequest::ForwardDialBack(ForwardDialBack {
        version: PROTOCOL_VERSION,
        nonce,
        target,
    });
    for &member in &serving.node.members {
        if Some(member) == serving.own || Some(member.ip()) == asked || member.ip() == target.ip() {
            continue;
        }
        let left = until
            .saturating_duration_since(Instant::now())
            .min(serving.node.limits.forward_timeout);
        if left.is_zero() {
            break;
        }
        match request(dialler, member, &forward, left).await {
            Ok(PublicResponse::Forwarded { reached }) => return Some(reached),
            Ok(_) => tracing::debug!(%member, "the member answered a different question"),
            Err(error) => tracing::debug!(%member, %error, "the member took no forward"),
        }
    }
    None
}

/// Dials `to` from `endpoint` offering [`DIAL_BACK_ALPN`], hands over `nonce`,
/// and reports whether the requester took it — M14.
///
/// "Took it" is the requester closing with code 0, which it does once it has
/// read and recognised the nonce. The answer to the request goes out after
/// that close, so by the time the requester reads the answer it has already
/// seen, or not seen, the dial-back itself.
///
/// Public so that a test can play a responder that breaks the rules.
pub async fn dial_back(
    endpoint: &Endpoint,
    to: SocketAddr,
    nonce: [u8; DIAL_BACK_NONCE_LEN],
    until: Instant,
) -> bool {
    let attempt = async {
        let connection = endpoint
            .connect_with(client_config_offering(DIAL_BACK_ALPN)?, to, SERVER_NAME)?
            .await?;
        let mut send = connection.open_uni().await?;
        send.write_all(&nonce).await?;
        let _ = send.finish();
        let taken = matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0u32.into()
        );
        Ok::<_, NetError>(taken)
    };
    matches!(timeout_at(until, attempt).await, Ok(Ok(true)))
}

/// The requester's half: reads the nonce off a connection that negotiated
/// [`DIAL_BACK_ALPN`]. The caller decides whether it is one of its own, and
/// closes with 0 if so — the close [`dial_back`] waits for.
pub async fn read_dial_back(
    connection: &quinn::Connection,
    timeout: Duration,
) -> Result<[u8; DIAL_BACK_NONCE_LEN], NetError> {
    let deadline = Instant::now() + timeout;
    let mut recv = by(deadline, connection.accept_uni()).await??;
    let mut nonce = [0u8; DIAL_BACK_NONCE_LEN];
    by(deadline, recv.read_exact(&mut nonce)).await??;
    Ok(nonce)
}

/// A fresh nonce for a `DialBackRequest`.
pub fn dial_back_nonce() -> [u8; DIAL_BACK_NONCE_LEN] {
    use rand::RngCore;
    let mut nonce = [0u8; DIAL_BACK_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
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

/// IPs shown reachable by a forwarded dial-back this node took part in, as
/// the member that forwarded it or the one that dialled — M16a. Only these,
/// and the configured members, get `forward_per_member`.
///
/// Local knowledge, deliberately: nothing here is taken from anyone but the
/// member that dialled. So the allowance exists where the proof happened —
/// the bootstrap members a node tests against, and the members they forward
/// to — and everywhere else a member is a stranger, whatever it claims.
///
/// Keyed by IP, which a requester chooses only by passing a dial-back from
/// it, and capped at `max_sources` like the limiter. At the cap, lapsed
/// entries go first, and then a newcomer is not recorded, which costs it
/// nothing but the larger allowance.
struct Proven {
    cap: usize,
    until: HashMap<IpAddr, Instant>,
}

impl Proven {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            until: HashMap::new(),
        }
    }

    fn with(cap: usize, ips: impl IntoIterator<Item = IpAddr>, now: Instant) -> Self {
        let mut proven = Self::new(cap);
        for ip in ips {
            proven.prove(ip, now);
        }
        proven
    }

    fn prove(&mut self, ip: IpAddr, now: Instant) {
        if !self.until.contains_key(&ip) && self.until.len() >= self.cap {
            self.until.retain(|_, until| *until > now);
            if self.until.len() >= self.cap {
                return;
            }
        }
        tracing::debug!(%ip, "member allowance: a forwarded dial-back reached it");
        self.until.insert(ip, now + PROVEN_FOR);
    }

    fn holds(&self, ip: IpAddr, now: Instant) -> bool {
        self.until.get(&ip).is_some_and(|until| now < *until)
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

    let connection = by(deadline, connect_as(endpoint, NodeKind::Public, addr)).await??;
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

    #[test]
    fn passed_dial_back_earns_a_meaningful_allowance() {
        let limits = Limits::default();
        assert_eq!(limits.per_source, 10);
        assert_eq!(limits.forward_per_member, 30);
        assert_eq!(limits.forward_per_member / limits.per_source, 3);
    }

    #[test]
    fn a_proof_lapses_and_the_set_is_capped() {
        let now = Instant::now();
        let mut proven = Proven::new(2);
        proven.prove(source(1), now);
        assert!(proven.holds(source(1), now));
        assert!(!proven.holds(source(2), now));
        assert!(!proven.holds(source(1), now + PROVEN_FOR));

        proven.prove(source(2), now);
        proven.prove(source(3), now);
        assert!(!proven.holds(source(3), now), "past the cap");
        // Lapsed entries make room.
        proven.prove(source(3), now + PROVEN_FOR);
        assert!(proven.holds(source(3), now + PROVEN_FOR));
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
