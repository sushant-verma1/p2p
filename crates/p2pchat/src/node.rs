//! One running node: the private endpoint, the public endpoint, the store, and
//! the sessions between them.
//!
//! The private node is the whole of `architecture.md` §6, §7 and §11 joined up:
//! a QUIC connection is handshaked, the session cipher is derived from it, the
//! conversation stream runs on the stream the handshake used, and every message
//! it carries lands in the store.
//!
//! The public node (§3, M7) is wired to the same store, so a connection request
//! outlives the process that received it — and the private node reads the same
//! table: a session is established only with a peer the user accepted (§10,
//! F-06). Without that, the reject in F-06 does nothing, because anyone holding
//! an invite can skip the public node and dial the private one directly.
//!
//! The check is in [`Node::establish`], where both directions meet, and it is
//! on the user ID §6 *authenticated* — never on the one `HELLO_INIT` claims.
//! §10 says why at length; briefly, deciding anything before the handshake
//! completes turns the handshake into an oracle for the accepted list.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use quinn::{Connection, Endpoint, VarInt};
use tokio::sync::{mpsc, Mutex};
use tracing::Instrument;

use p2pchat_core::wire::{ConnectionRequest, DeliveryStatus, RequestState, PROTOCOL_VERSION};
use p2pchat_core::{MessageId, UserId};
use p2pchat_crypto::{
    derive_conversation_id, invite, keystore, CryptoError, Identity, SessionCipher,
};
use p2pchat_net::handshake::Established;
use p2pchat_net::public::{self, Ask, Incoming, Limits, PublicNode};
use p2pchat_net::{client_endpoint, connect, handshake, server_endpoint, NetError, NodeKind};
use p2pchat_store::{db_path, Message, Peer, PendingRequest, Store, MAX_PENDING};

use crate::registry::{Admit, Handle, Registry};
use crate::session::{self, Conversation, Outgoing};
use crate::Event;

/// Depth of the event channel. Events are printed or asserted on, never
/// batched; this is slack for a burst, not a buffer.
const EVENTS: usize = 256;

/// Depth of the public node's request channel. `public::serve` drops a caller
/// whose request does not fit rather than queueing it, which is the right
/// answer for an unauthenticated surface.
const REQUESTS: usize = 32;

/// How soon a sent request is asked about, and how seldom it ends up being
/// asked about — M9d. The first is short because most decisions are made while
/// the user is still looking at the request; the second is long because the
/// rest are made the next time somebody opens the client.
const POLL_MIN: Duration = Duration::from_secs(2);
const POLL_MAX: Duration = Duration::from_secs(60);

/// How long a whole dial may take — M9f, `architecture.md` §6.
///
/// `handshake::HANDSHAKE_TIMEOUT` starts once the QUIC connection is open, so
/// it covers none of the connect. Without a deadline over both, an unreachable
/// peer is bounded only by whatever QUIC eventually decides, and a peer that
/// answers packets but never finishes opening is not bounded at all.
///
/// Twenty seconds: §6's fourteen for the handshake plus `USUAL_CONNECT_BUDGET`,
/// and short enough that the screen stops saying `connecting`. The same twenty
/// a connection request waits, so both give-ups are one number.
const DIAL_TIMEOUT_MS: u64 = 20_000;

/// What a dial leaves the connect once §6 has its fourteen seconds — M12c.
/// A budget that covers almost every connect, not the slowest one seen. Over
/// an 800 ms round trip with 8% loss, independent or bursty, M12b's slowest of
/// 180 connects was 3.80 s, and M12c's was 3.23 s bar one: a single 8.02 s
/// connect under bursty loss, whose handshake then took 2.40 s. Raising the
/// dial deadline to cover that one would make every unreachable peer wait
/// longer for it. Nothing enforces this alone; the test holding the two
/// timeouts under the dial deadline reads it.
#[cfg(test)]
const USUAL_CONNECT_BUDGET: Duration = Duration::from_secs(6);

/// What to check when a peer's node does not answer — M12, `project.md` §7.
///
/// A peer behind carrier-grade NAT, a closed UDP port and a wrong address all
/// look the same from this side: packets go out and nothing comes back. So the
/// message cannot say which it was, only what to check, most likely first. One
/// line, because the debug node prints it inside a tab-separated record.
pub fn no_answer(addr: SocketAddr, waited: Duration) -> String {
    format!(
        "no answer from {addr} after {waited:?}. An unreachable node and a wrong address \
         look the same from here, so check: that {addr} is what `p2pchat check` on the \
         owner's machine lists as advertised; that UDP port {port} is open inbound on the \
         owner's firewall and cloud security group (QUIC is UDP, a TCP rule does nothing); \
         and that the owner is not behind carrier-grade NAT (a 100.64.x.x WAN address on \
         their router) - if they are, nobody can reach them, and their node needs a VPS, a \
         LAN or a forwarded port",
        port = addr.port()
    )
}

/// Where an accepted requester is told to dial — §10, M9d. An explicit
/// address wins; otherwise the host comes from the first `--addr` and the port
/// from the endpoint that was actually bound, since `--private-port 0` is a
/// real port once it is bound and an advertised 0 would be a lie.
///
/// Public so that `p2pchat check` reports the address the node would hand
/// out, rather than a second derivation that could drift from this one.
pub fn derive_private_advertise(
    explicit: Option<SocketAddr>,
    advertise: &[SocketAddr],
    bound_port: u16,
) -> Option<SocketAddr> {
    explicit.or_else(|| {
        advertise
            .first()
            .map(|addr| SocketAddr::new(addr.ip(), bound_port))
    })
}

/// `architecture.md` §10's reconnect backoff, in seconds. After the last entry
/// the interval stops growing and starts scattering — see [`jitter`].
const BACKOFF: [u32; 6] = [1, 2, 4, 8, 16, 30];

/// What [`BACKOFF`] counts in, and how long the whole loop may run — §10's ten
/// minutes.
const BACKOFF_UNIT_MS: u64 = 1_000;
const RECONNECT_BUDGET_MS: u64 = 10 * 60 * 1_000;

/// A duration in milliseconds, overridable by an environment variable.
///
/// Every one of these is a schedule the gates have to observe: ten minutes of
/// backoff is right for a running node and impossible to assert on, so the
/// tests scale the clock and assert on the shape.
fn env_ms(name: &str, default: u64) -> Duration {
    Duration::from_millis(match std::env::var(name) {
        Ok(value) => value.parse().unwrap_or(default),
        Err(_) => default,
    })
}

/// `P2PCHAT_DIAL_TIMEOUT_MS` overrides [`DIAL_TIMEOUT_MS`], in milliseconds.
/// The gates set it low, so that the timeout rather than QUIC's own is what
/// they are measuring.
fn dial_timeout() -> Duration {
    env_ms("P2PCHAT_DIAL_TIMEOUT_MS", DIAL_TIMEOUT_MS)
}

/// How long to wait before attempt `attempt` (counting from 0), or `None` once
/// §10's budget has run out and the loop is to give up.
fn schedule(attempt: usize, elapsed: Duration) -> Option<Duration> {
    if elapsed >= env_ms("P2PCHAT_RECONNECT_BUDGET_MS", RECONNECT_BUDGET_MS) {
        return None;
    }

    let unit = env_ms("P2PCHAT_BACKOFF_MS", BACKOFF_UNIT_MS);
    match BACKOFF.get(attempt) {
        Some(&secs) => Some(unit * secs),
        None => Some(jitter(unit * BACKOFF[BACKOFF.len() - 1])),
    }
}

/// `base` give or take a fifth of it — §10.
///
/// The constant part of the schedule is the part every peer of a node that
/// just came back would otherwise redial it on, all on the same half-second.
fn jitter(base: Duration) -> Duration {
    // ponytail: clock and counter, mixed. Scattering retries needs values that
    // differ, not values nobody can predict, and `rand` is a dependency this
    // crate does not otherwise have.
    let spread = (mix() % 401) as i64 - 200;
    let millis = base.as_millis() as i64;
    Duration::from_millis((millis + millis * spread / 1_000).max(1) as u64)
}

/// A different number every call, on any clock granularity.
fn mix() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    // splitmix64's finaliser over the clock and the call count. The counter is
    // what keeps two calls inside one clock tick apart.
    let mut x = nanos ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// §10's refusal, as a type so that [`fatal`] can tell it from a peer that is
/// merely down. Neither is worth retrying, and only one of them is an attack.
#[derive(Debug, thiserror::Error)]
#[error("peer has not been accepted")]
pub struct NotAccepted;

/// Is this failure one that dialling again cannot fix — §10?
///
/// A handshake that failed verification is the whole of it: the peer is not
/// who the invite said it was, or the transcript did not bind, and the next
/// attempt gets the same answer. Retrying an authentication failure turns a
/// wrong peer into a peer that gets asked every thirty seconds for ten
/// minutes, which is a thing an attacker can answer.
fn fatal(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        // Both shapes: `handshake::initiate` returns the net crate's wrapper,
        // and `#[error(transparent)]` forwards the *message* without putting
        // the inner error in the chain.
        matches!(
            cause.downcast_ref::<NetError>(),
            Some(NetError::Crypto(CryptoError::Handshake))
        ) || matches!(
            cause.downcast_ref::<CryptoError>(),
            Some(CryptoError::Handshake)
        ) || cause.is::<NotAccepted>()
    })
}

/// Where an attempt to reach a peer has got to — `architecture.md` §10, F-25.
///
/// Reported, not remembered: a phase exists while some task is inside it and
/// is gone when that task returns. M9e's bug was a state written once that
/// only an event could clear, and there is no event on the failing paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// A dial is open: the QUIC connection is being made.
    Connecting,
    /// The connection is up and §6 is running on it.
    Handshaking,
    /// A session ended and the backoff loop is trying to replace it.
    Reconnecting,
}

impl Phase {
    /// Which phase is reported when two are in progress at once: the most
    /// specific. A reconnect dials, so `Connecting` says nothing the outer
    /// `Reconnecting` did not; reaching the handshake is a step forward from
    /// either.
    fn rank(self) -> u8 {
        match self {
            Phase::Connecting => 0,
            Phase::Reconnecting => 1,
            Phase::Handshaking => 2,
        }
    }
}

/// Reports a [`Phase`] for as long as it is held.
pub struct Reporting {
    node: Arc<Node>,
    peer: UserId,
    previous: Option<Phase>,
}

impl Drop for Reporting {
    fn drop(&mut self) {
        if let Ok(mut phases) = self.node.phases.lock() {
            match self.previous {
                Some(phase) => phases.insert(self.peer, phase),
                None => phases.remove(&self.peer),
            };
        }
        let _ = self.node.events.try_send(Event::Phase { peer: self.peer });
    }
}

pub struct Config {
    /// Holds `identity.key`.
    pub config_dir: PathBuf,
    /// Holds the database.
    pub data_dir: PathBuf,
    /// Where the private endpoint binds — not what it advertises. The two are
    /// different addresses answering different questions: the bind address is
    /// which of this host's interfaces will accept packets, and the advertised
    /// one is what a peer somewhere else has to dial. Binding loopback is what
    /// makes a node unreachable from any other machine, which is right for a
    /// test and wrong for a running node.
    pub private_bind: SocketAddr,
    /// `None` runs no public node at all — which is what a node behind a NAT
    /// that nobody can reach should do, and what most of the tests want.
    pub public_bind: Option<SocketAddr>,
    /// What the invite the public node hands out advertises. Never derived
    /// from the bind address: this process cannot work out which of its
    /// addresses is reachable from outside, so it is told.
    pub advertise: Vec<SocketAddr>,
    /// Where an accepted requester is told to dial us privately — M9d, §10.
    ///
    /// `None` derives it from [`Config::advertise`]: the same host, with the
    /// private endpoint's port. The host is the only part that cannot be
    /// worked out here, and `--addr` has already supplied it. Nothing to
    /// derive from means no private address, and then no request can be
    /// accepted — there would be nowhere to send the requester.
    pub private_advertise: Option<SocketAddr>,
    /// Ours, in our own connection requests and invites. Advisory: every peer
    /// that receives it is required to treat it as decoration.
    pub display_name: String,
}

pub struct Node {
    pub me: UserId,
    /// Public because the debug CLI and the tests read history straight out of
    /// it. Wrapping every query in a method here would be a second API for the
    /// one underneath.
    pub store: Arc<Store>,
    identity: Identity,
    display_name: String,
    /// Dials only, on an ephemeral port. Separate from the listener because a
    /// QUIC endpoint is one socket and the listener's is the advertised one.
    client: Endpoint,
    /// Asks public nodes, and only that. A QUIC endpoint carries one ALPN and
    /// §2 separates the two protocols by ALPN, so `client` cannot be reused
    /// here: a public node answering a private-ALPN dial rejects it.
    asker: Endpoint,
    private: Endpoint,
    public_addr: Option<SocketAddr>,
    /// What an accepted requester is told to dial — M9d. Checked once, at
    /// startup, so a node that cannot answer a request says so before it takes
    /// any.
    private_advertise: Option<SocketAddr>,
    /// Peers with a status poller already running, so that re-sending a
    /// request, or a resume racing a fresh send, does not start a second one.
    pollers: Mutex<HashSet<UserId>>,
    /// Peers with a reconnect loop already running — M10. Same guard, same
    /// reason: a session that drops while startup is still dialling would
    /// otherwise have two loops racing to replace it.
    reconnecting: Mutex<HashSet<UserId>>,
    /// F-25's missing states, for as long as some task is in them — see
    /// [`Phase`]. A `std::sync` mutex: held for a hash lookup, never across an
    /// await, and dropped from [`Reporting`], which cannot await.
    phases: std::sync::Mutex<HashMap<UserId, Phase>>,
    registry: Mutex<Registry>,
    events: mpsc::Sender<Event>,
    /// §11's commit-to-ACK window, stretched only when a test asks — see
    /// [`session::commit_pause`].
    pause: Duration,
}

impl Node {
    /// Loads the identity, opens the store, binds the endpoints and starts
    /// listening.
    ///
    /// The returned receiver is the only copy: drop it and the node runs on
    /// with nowhere to report, so whoever starts a node keeps it.
    pub async fn start(config: Config) -> Result<(Arc<Self>, mpsc::Receiver<Event>)> {
        let identity = keystore::load_or_create(&keystore::key_path(&config.config_dir))
            .context("load the identity")?;
        let store = Store::open(db_path(&config.data_dir))
            .await
            .context("open the database")?;

        let private = server_endpoint(config.private_bind, NodeKind::Private)
            .context("bind the private endpoint")?;
        let client = client_endpoint(NodeKind::Private).context("bind the dialling endpoint")?;
        let asker = client_endpoint(NodeKind::Public).context("bind the asking endpoint")?;
        let public = config
            .public_bind
            .map(|addr| server_endpoint(addr, NodeKind::Public))
            .transpose()
            .context("bind the public endpoint")?;

        // M9f: where the four sockets really are, said rather than deduced,
        // and before anything that can refuse to start. Every address bug in
        // this project has been found by discovering where a socket actually
        // is — and all four are here because a dial leaves from the client
        // endpoint, not from the listener the peer was told about.
        let private_addr = private.local_addr()?;
        let public_addr = public.as_ref().map(Endpoint::local_addr).transpose()?;
        tracing::info!(
            me = %identity.user_id(),
            private = %private_addr,
            public = ?public_addr,
            dialling_from = %client.local_addr()?,
            asking_from = %asker.local_addr()?,
            "endpoints bound",
        );

        let private_advertise = derive_private_advertise(
            config.private_advertise,
            &config.advertise,
            private_addr.port(),
        );
        if let Some(addr) = private_advertise.filter(|addr| addr.ip().is_unspecified()) {
            // The same refusal the invite gives, for the same reason: a bind
            // address names no host, and by the time it has been handed to a
            // requester it is too late to notice.
            return Err(p2pchat_crypto::CryptoError::InviteUnspecifiedAddr(addr).into());
        }

        let (events, incoming) = mpsc::channel(EVENTS);
        let node = Arc::new(Self {
            me: identity.user_id(),
            store: Arc::new(store),
            display_name: config.display_name,
            client,
            asker,
            public_addr,
            private: private.clone(),
            private_advertise,
            pollers: Mutex::new(HashSet::new()),
            reconnecting: Mutex::new(HashSet::new()),
            phases: std::sync::Mutex::new(HashMap::new()),
            registry: Mutex::new(Registry::default()),
            events,
            pause: session::commit_pause(),
            identity,
        });

        // M9e: the two addresses a peer is *told* to dial, in the log of the
        // node that hands them out. Diagnosing a stalled connection across two
        // machines starts by comparing this line with the one the other side
        // dialled, and neither the TUI nor the invite prints it anywhere else.
        //
        // Advertised, and named so: the line above is where the sockets are,
        // and the two answer different questions — M9f. A bound address and an
        // advertised one on one line under one word is how a whole evening
        // goes into deciding which of them `private` meant.
        tracing::info!(
            me = %node.me,
            public_advertised = ?config.advertise,
            private_advertised = ?node.private_advertise,
            "node started",
        );

        tokio::spawn(accept(Arc::clone(&node), private));
        // Requests we sent before the last shutdown are still unanswered, and
        // the acceptor may have decided while we were gone — M9d. Polled at
        // once rather than after the first interval, for that reason.
        //
        // Both sweeps are awaited, not spawned: each reads the store, and it
        // has to read it *before* `start` returns. Spawned, the read could land
        // after a caller's first `request_connection` had written its row, and
        // the sweep would adopt a request from this run as one from the last —
        // a second poller settling the same answer, and on `Accepted` a second
        // dial. Each only reads and spawns, so the wait is two store queries.
        resume_polling(Arc::clone(&node)).await;
        // And the peers that had got past that before the last shutdown — §10,
        // M10. A session is not resumed, it is made again from nothing: this
        // dials, and everything below §6 starts over.
        reconnect_accepted(Arc::clone(&node)).await;

        if let Some(endpoint) = public {
            let invite = invite::create(
                &node.identity,
                &node.display_name,
                config.advertise,
                invite::now(),
            )
            .context("build the invite the public node hands out")?;

            let (requests, queue) = mpsc::channel(REQUESTS);
            tokio::spawn(public::serve(
                endpoint,
                PublicNode {
                    invite,
                    limits: Limits::default(),
                    requests,
                },
            ));
            tokio::spawn(answer_requests(Arc::clone(&node), queue));
        }

        Ok((node, incoming))
    }

    /// The address the private endpoint is *bound* to, with the port the OS
    /// settled on — `Config::private_bind` may name port 0, which is how the
    /// tests avoid fighting over ports.
    ///
    /// Not an advertised address: bound to `0.0.0.0` this reports `0.0.0.0`,
    /// which no peer elsewhere can dial. `Config::advertise` is the answer to
    /// that question.
    pub fn private_addr(&self) -> Result<SocketAddr> {
        Ok(self.private.local_addr()?)
    }

    pub fn public_addr(&self) -> Option<SocketAddr> {
        self.public_addr
    }

    /// What an accepted requester is told to dial — M9d. `None` if this node
    /// was given no address to advertise, which is also the node that cannot
    /// accept a request.
    pub fn private_advertise(&self) -> Option<SocketAddr> {
        self.private_advertise
    }

    /// Dials a private node and runs §6 against it.
    ///
    /// `expected` is the user ID from the invite. Pass it whenever there is
    /// one: it is the difference between talking to the right peer and talking
    /// to a peer.
    pub async fn dial(
        self: &Arc<Self>,
        addr: SocketAddr,
        expected: Option<UserId>,
    ) -> Result<UserId> {
        // §10: dial only accepted peers. Checked here when we know who we are
        // dialling, so an unaccepted peer costs no connection at all; when we
        // do not, the same check in `establish` catches it once §6 has said who
        // answered. Nothing leaks either way — this is our own decision about
        // where to dial, not an answer to anybody.
        if let Some(peer) = expected {
            if !self.store.is_accepted(peer).await? {
                return Err(NotAccepted.into());
            }
        }

        // F-25: the two phases of a dial, reported while they are happening.
        // Nothing to report them under when there is no `expected` — a dial to
        // an unknown peer belongs to no row on the screen.
        let _connecting = expected.map(|peer| self.report(peer, Phase::Connecting));

        // One deadline over the connect *and* the handshake — M9f. Inside it
        // so that a peer that is merely slow gets the whole budget for both,
        // rather than a fast connect buying a second handshake timeout.
        let timeout = dial_timeout();
        let opened = tokio::time::timeout(timeout, async {
            let connection = connect(&self.client, addr).await.context("dial")?;
            let _handshaking = expected.map(|peer| self.report(peer, Phase::Handshaking));
            let established = handshake::initiate(&connection, &self.identity, expected)
                .await
                .context("handshake")?;
            Ok::<_, anyhow::Error>((connection, established))
        })
        .await;

        let (connection, established) = opened.map_err(|_| anyhow!(no_answer(addr, timeout)))??;

        // We dialled, so the tiebreak candidate for this session is us.
        let peer = self.establish(connection, established, self.me).await?;

        // Where to dial again — §10, M10. Written only now, because §6 has
        // just proved who answers at this address. A failure to record it
        // costs a reconnect, not the session, so it is not worth failing over.
        if let Err(error) = self.store.set_peer_addr(peer, addr).await {
            tracing::warn!(%peer, %addr, %error, "the peer's address was not recorded");
        }
        Ok(peer)
    }

    /// Reports `phase` for `peer` until the returned value is dropped.
    fn report(self: &Arc<Self>, peer: UserId, phase: Phase) -> Reporting {
        let previous = match self.phases.lock() {
            Ok(mut phases) => {
                let previous = phases.get(&peer).copied();
                if previous.is_none_or(|old| phase.rank() >= old.rank()) {
                    phases.insert(peer, phase);
                }
                previous
            }
            Err(_) => None,
        };

        // The screen re-reads on a notice and never on a timer, so a phase
        // nobody is told about is a phase nobody sees — F-25.
        let _ = self.events.try_send(Event::Phase { peer });

        Reporting {
            node: Arc::clone(self),
            peer,
            previous,
        }
    }

    /// Everyone part way through §10's state machine, and where — F-25.
    pub fn phases(&self) -> HashMap<UserId, Phase> {
        match self.phases.lock() {
            Ok(phases) => phases.clone(),
            Err(_) => HashMap::new(),
        }
    }

    /// Dials `peer` until it answers or §10's budget runs out — M10.
    ///
    /// Started by the side that *dialled* the session that just ended, and by
    /// startup for a peer that was accepted before the last shutdown. The
    /// acceptor never starts one: §10's V0.1 limitation, recorded there.
    fn reconnect(self: &Arc<Self>, peer: UserId) {
        let node = Arc::clone(self);
        let span = tracing::info_span!("reconnecting", %peer);
        tokio::spawn(
            async move {
                if !node.reconnecting.lock().await.insert(peer) {
                    tracing::debug!("a reconnect loop is already running for this peer");
                    return;
                }
                let phase = node.report(peer, Phase::Reconnecting);
                reconnect_loop(&node, peer).await;
                drop(phase);
                node.reconnecting.lock().await.remove(&peer);
            }
            .instrument(span),
        );
    }

    /// Ends the session with `peer`, if there is one.
    ///
    /// The same path as a peer that goes away: the connection closes, and on
    /// the side that dialled it, the cleanup in [`Node::establish`] starts the
    /// reconnect loop. The gates pull the cable with this.
    pub async fn disconnect(&self, peer: UserId) {
        let handle = self.registry.lock().await.get(&peer).cloned();
        if let Some(handle) = handle {
            let _ = handle.outgoing.send(Outgoing::Close).await;
        }
    }

    /// Queues a message for the peer. Returns once it is queued; §11's `SENT`
    /// is later, on the socket write, and arrives as an [`Event::Sent`].
    ///
    /// With no session — or with one that has just ended — the row is written
    /// here instead, as `PENDING` (F-18). What the user typed is never thrown
    /// away because there was nothing to write it to: the writer's own first
    /// act is this same insert, and the only difference is that nothing
    /// follows it yet.
    pub async fn send(&self, peer: UserId, body: String) -> Result<()> {
        let handle = self.registry.lock().await.get(&peer).cloned();
        if let Some(handle) = handle {
            // The clone is the price of not losing the body when the channel
            // is closed — the session ended between the lookup and here.
            if handle
                .outgoing
                .send(Outgoing::Text(body.clone()))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        self.queue(peer, body).await
    }

    /// Stores an outbound message that has no socket to go out on — F-18.
    ///
    /// It goes out on the next session without anything rescanning for it:
    /// the peer's `RESYNC` names what it has, and everything above that is
    /// retransmitted — which is this row, since the peer has never seen it.
    async fn queue(&self, peer: UserId, body: String) -> Result<()> {
        let conversation_id = derive_conversation_id(&self.me, &peer);
        // The conversation row may not exist: `establish` opens it, and there
        // has been no session. `next_seq` counts in it, so it has to.
        self.store
            .open_conversation(conversation_id, peer, now_s())
            .await?;

        let message_id = MessageId::now_v7();
        self.store
            .insert_message(Message {
                message_id,
                conversation_id,
                sender_id: self.me,
                msg_seq: self.store.next_seq(conversation_id).await?,
                body: body.into_bytes(),
                created_at: session::now_ms(),
                received_at: None,
                status: DeliveryStatus::Pending,
            })
            .await?;

        tracing::info!(%peer, "no session: the message is stored pending");
        Ok(())
    }

    /// The name of the live session's keys, if there is one — §10, M10.
    ///
    /// Every reconnection is a new session: new ephemerals, new directional
    /// keys, `frame_seq` back to zero. This is how that is asserted on from
    /// outside without a key ever leaving the cipher.
    pub async fn session_id(&self, peer: &UserId) -> Option<[u8; 32]> {
        self.registry.lock().await.get(peer).map(|h| h.session_id)
    }

    /// Who dialled the surviving session with `peer`, if there is one — §10.
    pub async fn session_initiator(&self, peer: &UserId) -> Option<UserId> {
        self.registry.lock().await.get(peer).map(|h| h.initiator)
    }

    pub async fn session_count(&self) -> usize {
        self.registry.lock().await.len()
    }

    /// Everyone there is a live session with — M9e, and the answer to "is this
    /// peer connected". Read, never remembered: see [`Registry::peers`].
    pub async fn sessions(&self) -> HashSet<UserId> {
        self.registry.lock().await.peers()
    }

    /// Everyone this node is part way through reaching — M9e.
    ///
    /// The stored outbound request, which exists from the moment the request
    /// is sent until a session answers it or it is refused — M12c. So it
    /// covers the whole attempt, retries included, and it survives a restart:
    /// a node that comes up still polling says `connecting`, because it is.
    pub async fn connecting(&self) -> HashSet<UserId> {
        match self.store.outbound_requests().await {
            Ok(pending) => pending.into_iter().map(|(peer, _)| peer).collect(),
            Err(error) => {
                tracing::warn!(%error, "reading the outbound requests failed");
                HashSet::new()
            }
        }
    }

    /// Asks a public node to be let in — F-06. The answer is that node's
    /// claim about a queue it owns, and is not evidence of anything.
    ///
    /// `peer` is the owner from the invite; `addr` is that invite's public
    /// node. Sending records our own acceptance of `peer`, because §10 lets us
    /// dial only accepted peers and we have just decided we want to — a
    /// `Rejected` answer takes it back. The answer to a request is rarely
    /// immediate, so a poller is left behind to ask again (M9d).
    pub async fn request_connection(
        self: &Arc<Self>,
        peer: UserId,
        addr: SocketAddr,
    ) -> Result<RequestState> {
        let request = p2pchat_core::wire::PublicRequest::Connection(ConnectionRequest {
            version: PROTOCOL_VERSION,
            from_user_id: self.me,
            from_identity_pk: self.identity.identity_pk(),
            display_name: self.display_name.clone(),
            created_at: now_s(),
        });

        // Recorded *before* the ask, because this row is what the screen
        // reads as "connecting" (M9e) and an attempt in flight is an attempt.
        // Taken back below if the ask never lands; otherwise `settle` owns it.
        self.store.add_outbound_request(peer, addr, now_s()).await?;

        let (state, private) = match self.ask(addr, &request).await {
            Ok(answer) => answer,
            Err(error) => {
                let _ = self.store.remove_outbound_request(peer).await;
                // M12: silence from the owner's public node is the CGNAT case,
                // and a bare "timed out" reads like a typo in the address.
                if matches!(error.downcast_ref(), Some(NetError::RequestTimeout)) {
                    return Err(anyhow!(no_answer(addr, Limits::default().request_timeout)));
                }
                return Err(error);
            }
        };
        tracing::info!(%peer, %addr, ?state, "connection request sent");

        self.store.resolve_request(peer, true).await?;
        if !self.settle(peer, state, private).await {
            self.poll(peer, addr, POLL_MIN);
        }

        Ok(state)
    }

    /// The user's accept or reject — F-06, and §10's acceptance with it.
    ///
    /// Accepting needs somewhere to send the requester, and there is exactly
    /// one thing to say when there is nowhere: the same line `invite` gives.
    /// Refused before the decision is recorded, so the user can pass `--addr`
    /// and accept again rather than find a request accepted and unreachable.
    pub async fn decide(&self, peer: UserId, accepted: bool) -> Result<bool> {
        if accepted && self.private_advertise.is_none() {
            return Err(anyhow!(invite::NO_ADDR));
        }
        Ok(self.store.resolve_request(peer, accepted).await?)
    }

    /// One `CONNECTION_STATUS` question, or the answer to the request itself.
    async fn ask(
        &self,
        addr: SocketAddr,
        request: &p2pchat_core::wire::PublicRequest,
    ) -> Result<(RequestState, Option<SocketAddr>)> {
        match public::request(
            &self.asker,
            addr,
            request,
            Limits::default().request_timeout,
        )
        .await?
        {
            p2pchat_core::wire::PublicResponse::State(state, private) => Ok((state, private)),
            p2pchat_core::wire::PublicResponse::Profile(_) => {
                Err(anyhow!("the node answered a different question"))
            }
        }
    }

    /// Acts on one answer: dial on `Accepted`, forget on `Rejected`, keep
    /// polling on anything else. `true` once the request is answered and the
    /// poller has nothing left to do.
    async fn settle(
        self: &Arc<Self>,
        peer: UserId,
        state: RequestState,
        private: Option<SocketAddr>,
    ) -> bool {
        match (state, private) {
            (RequestState::Accepted, Some(private)) => {
                // A session from somewhere else — a manual dial, a reconnect —
                // already answers the request.
                if self.registry.lock().await.get(&peer).is_some() {
                    let _ = self.store.remove_outbound_request(peer).await;
                    return true;
                }

                // Dialled with the request row still in place, so the screen
                // keeps saying `connecting` for the whole attempt — the dial is
                // the slowest part of it, and a QUIC dial to an address nothing
                // answers on takes the dial deadline to give up.
                tracing::info!(%peer, addr = %private, "accepted; dialling the peer privately");
                let dialled = self.dial(private, Some(peer)).await;

                // M12c: the row goes only once a session exists, or once §6
                // has refused the peer. A dial that merely went unanswered keeps
                // it, and the poller asks and dials again, as often as it takes
                // and across restarts. Without that, a first dial lost to a
                // blip strands the peer: accepted, but with no address on
                // record, because only an address §6 has proved is stored.
                // Cleared before the event, so a screen that re-reads on the
                // hint sees the attempt already over.
                let settled = match &dialled {
                    Ok(_) => true,
                    Err(error) => fatal(error),
                };
                if settled {
                    let _ = self.store.remove_outbound_request(peer).await;
                }
                if let Err(error) = dialled {
                    // `?error` and not `%error`: the cause chain is the whole
                    // value of this line when it is all somebody has.
                    tracing::warn!(
                        ?error,
                        %peer,
                        addr = %private,
                        retrying = !settled,
                        "dialling an accepting peer failed",
                    );
                    let _ = self.events.try_send(Event::DialFailed {
                        peer,
                        reason: format!("{error:#}"),
                    });
                }
                settled
            }
            (RequestState::Rejected, _) => {
                // Taking back the acceptance `request_connection` recorded: we
                // asked, they said no, and §10 should not leave us dialling.
                let _ = self.store.resolve_request(peer, false).await;
                let _ = self.store.remove_outbound_request(peer).await;
                tracing::info!(%peer, "our connection request was rejected");
                let _ = self.events.try_send(Event::DialFailed {
                    peer,
                    reason: "they rejected the connection request".to_owned(),
                });
                true
            }
            // `Accepted` with no address is a node that answered wrongly, and
            // `Unknown` is one that has forgotten us. Neither is worth a dial;
            // both are worth asking again, because the next answer may differ.
            _ => {
                tracing::debug!(%peer, ?state, "no answer to act on yet; keeping the poller");
                false
            }
        }
    }

    /// Starts the status poller for `peer`, unless one is already running.
    fn poll(self: &Arc<Self>, peer: UserId, addr: SocketAddr, first: Duration) {
        let node = Arc::clone(self);
        // One span per attempt. Two nodes' logs are read side by side when a
        // connection stalls, and the peer on every line is what joins them.
        let span = tracing::info_span!("polling", %peer);
        tokio::spawn(
            async move {
                if !node.pollers.lock().await.insert(peer) {
                    tracing::debug!("a poller is already running for this peer");
                    return;
                }
                tracing::debug!(%addr, ?first, "polling started");
                poll_status(&node, peer, addr, first).await;
                tracing::debug!("polling stopped");
                node.pollers.lock().await.remove(&peer);
            }
            .instrument(span),
        );
    }

    /// Everything a freshly handshaked connection needs before it is a
    /// session: §10's access check, a peer row, a conversation, a cipher, two
    /// tasks, and §10's verdict on whether it is the session that survives.
    async fn establish(
        self: &Arc<Self>,
        connection: Connection,
        established: Established,
        initiator: UserId,
    ) -> Result<UserId> {
        let Established {
            session,
            send,
            recv,
        } = established;
        let peer = session.peer_user_id();

        // §10, and the first thing after the handshake: `peer` is the ID §6
        // authenticated, which is the only one worth checking — see §10 for why
        // this is not done earlier, on the ID `HELLO_INIT` merely claimed. The
        // close is the handshake's own code and reason, so an unaccepted peer
        // and a failed handshake are the same event from the outside.
        if !self.store.is_accepted(peer).await? {
            tracing::info!(%peer, "closing a session with a peer that is not accepted");
            connection.close(
                VarInt::from_u32(handshake::HANDSHAKE_ERROR_CODE),
                handshake::HANDSHAKE_ERROR_REASON,
            );
            return Err(NotAccepted.into());
        }

        let now = now_s();

        self.store
            .upsert_peer(Peer {
                user_id: peer,
                identity_pk: session.peer_identity_pk(),
                // Whatever the peer calls itself arrived over the public node,
                // unauthenticated. §6 proves the key, not the name.
                display_name: None,
                first_seen: now,
                last_seen: Some(now),
                verified: false,
                // Ignored by `upsert_peer`, which leaves both decisions where
                // the user made them. We are only here because it is true.
                accepted: true,
            })
            .await?;

        let conversation_id = derive_conversation_id(&self.me, &peer);
        self.store
            .open_conversation(conversation_id, peer, now)
            .await?;

        let cipher = SessionCipher::derive(session)?;
        let session_id = cipher.session_id();

        let conversation = Arc::new(Conversation {
            me: self.me,
            peer,
            conversation_id,
            store: Arc::clone(&self.store),
            events: self.events.clone(),
            cipher: Arc::new(Mutex::new(cipher)),
            connection: connection.clone(),
            written_from: std::sync::atomic::AtomicU64::new(u64::MAX),
            pause: self.pause,
        });
        let outgoing = session::spawn(conversation, send, recv);

        let (admit, displaced) = self.registry.lock().await.insert(
            peer,
            Handle {
                initiator,
                session_id,
                outgoing: outgoing.clone(),
            },
        );

        match admit {
            // §10: this one lost. Closing it is the whole resolution — the
            // peer is applying the same rule to the same two IDs and closing
            // the same session.
            Admit::Rejected => {
                tracing::info!(%peer, "closing the duplicate session with the higher initiator");
                let _ = outgoing.send(Outgoing::Close).await;
                return Ok(peer);
            }
            Admit::Replaced => {
                if let Some(old) = displaced {
                    tracing::info!(%peer, "replacing the session with the higher initiator");
                    let _ = old.outgoing.send(Outgoing::Close).await;
                }
            }
            Admit::Only => {}
        }

        // Cleanup, once. `remove` checks that the registered session is still
        // this one, so a loser closing later cannot take the winner with it.
        let node = Arc::clone(self);
        tokio::spawn(async move {
            connection.closed().await;
            node.registry.lock().await.remove(&peer, &session_id);
            // §10: the peer that dialled is the peer that redials, and the
            // acceptor waits to be dialled. A loser of the simultaneous-dial
            // tiebreak never reaches here, so closing it starts nothing.
            if initiator == node.me {
                node.reconnect(peer);
            }
        });

        tracing::info!(%peer, %initiator, "session established");
        // Never awaited — see `session::emit`. §2: the core does not block on
        // the UI. A dropped one costs a late redraw and nothing else: what the
        // screen reads is `Node::sessions`, not this.
        let _ = self.events.try_send(Event::Connected { peer, initiator });
        Ok(peer)
    }
}

/// §8 keeps `peers` and `pending_requests` in seconds and `messages` in
/// milliseconds. One conversion, here, rather than a second clock.
fn now_s() -> u64 {
    session::now_ms() / 1000
}

/// Asks about one request until it is answered — M9d, §10.
///
/// The interval doubles from [`POLL_MIN`] to [`POLL_MAX`]: a decision usually
/// comes in the first minute or not for hours, and a node that kept asking
/// every two seconds all day would be its own denial of service.
async fn poll_status(node: &Arc<Node>, peer: UserId, addr: SocketAddr, first: Duration) {
    let status = p2pchat_core::wire::PublicRequest::Status(p2pchat_core::wire::ConnectionStatus {
        version: PROTOCOL_VERSION,
        from_user_id: node.me,
    });

    let mut delay = first;
    loop {
        tokio::time::sleep(delay).await;
        delay = (delay * 2).clamp(POLL_MIN, POLL_MAX);
        // Every pass, at debug: "the requester never polled" and "the requester
        // polled and was told nothing" are different bugs, and the log has to
        // be able to tell them apart — M9e.
        tracing::debug!(%peer, %addr, "asking what became of our request");

        match node.ask(addr, &status).await {
            // An unreachable node is the ordinary case — it is somebody's
            // laptop — so a failed poll is the same as a `Pending` answer.
            Err(error) => tracing::debug!(%error, %peer, "polling a request failed"),
            Ok((state, private)) => {
                if node.settle(peer, state, private).await {
                    return;
                }
            }
        }
    }
}

/// §10's backoff loop: dial, wait longer, dial again, give up at the budget.
///
/// Every attempt re-reads the address and re-checks the registry, because ten
/// minutes is long enough for both to change — the peer may dial *us* while we
/// are waiting, and then there is nothing left to do.
async fn reconnect_loop(node: &Arc<Node>, peer: UserId) {
    let started = Instant::now();

    for attempt in 0.. {
        let Some(delay) = schedule(attempt, started.elapsed()) else {
            tracing::warn!(
                ?attempt,
                "giving up: the peer did not answer inside the budget"
            );
            let _ = node.events.try_send(Event::DialFailed {
                peer,
                reason: "gave up reconnecting: the peer did not answer inside the reconnect budget"
                    .to_owned(),
            });
            return;
        };
        tokio::time::sleep(delay).await;

        if node.registry.lock().await.get(&peer).is_some() {
            tracing::info!("there is a session again; nothing to reconnect");
            return;
        }

        let Some(addr) = last_addr(node, peer).await else {
            // Accepted and never dialled from here, or the row is gone. §10:
            // only the requester dials, and it has no address to dial.
            tracing::info!("no address on record for this peer; not reconnecting");
            return;
        };

        match node.dial(addr, Some(peer)).await {
            Ok(_) => return,
            Err(error) if fatal(&error) => {
                tracing::warn!(?error, %addr, "the peer did not authenticate; not retrying");
                let _ = node.events.try_send(Event::DialFailed {
                    peer,
                    reason: format!(
                        "the peer did not authenticate, so this is not retried: {error:#}"
                    ),
                });
                return;
            }
            Err(error) => tracing::debug!(?error, attempt, %addr, ?delay, "reconnect failed"),
        }
    }
}

/// Where §6 last completed a handshake with `peer`.
///
/// ponytail: reads the whole accepted list to find one row. The list is every
/// peer the user ever accepted, and a scan of it costs less than a second
/// query that returns the same thing.
async fn last_addr(node: &Node, peer: UserId) -> Option<SocketAddr> {
    node.store
        .reconnectable()
        .await
        .ok()?
        .into_iter()
        .find(|(user_id, _)| *user_id == peer)
        .map(|(_, addr)| addr)
}

/// Dials the peers that had a session before the last shutdown — §10, M10.
///
/// M9d resumes the requests still waiting for an answer; this is the other
/// half, and the two do not overlap: a peer with a request still in flight is
/// one `settle` will dial as soon as it is accepted, and dialling it here as
/// well would be two dials for one decision.
async fn reconnect_accepted(node: Arc<Node>) {
    let peers = match node.store.reconnectable().await {
        Ok(peers) => peers,
        Err(error) => {
            tracing::warn!(%error, "reading the accepted peers failed");
            return;
        }
    };

    let waiting = node.connecting().await;
    for (peer, addr) in peers {
        if waiting.contains(&peer) {
            tracing::debug!(%peer, "a request to this peer is still unanswered; not dialling");
            continue;
        }
        tracing::info!(%peer, %addr, "dialling an accepted peer at startup");
        node.reconnect(peer);
    }
}

/// Picks up the requests that were still unanswered when we last stopped.
async fn resume_polling(node: Arc<Node>) {
    let pending = match node.store.outbound_requests().await {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(%error, "reading the outbound requests failed");
            return;
        }
    };

    for (peer, addr) in pending {
        node.poll(peer, addr, Duration::ZERO);
    }
}

/// Answers the private endpoint until it stops accepting.
///
/// One task per connection: a peer that opens a connection and then stalls
/// holds up its own handshake deadline and nobody else's.
async fn accept(node: Arc<Node>, endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        let node = Arc::clone(&node);
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "inbound connection failed");
                    return;
                }
            };

            match handshake::respond(&connection, &node.identity).await {
                // They dialled, so they are the tiebreak candidate.
                Ok(established) => {
                    let initiator = established.session.peer_user_id();
                    if let Err(error) = node.establish(connection, established, initiator).await {
                        tracing::warn!(%error, "establishing the inbound session failed");
                    }
                }
                // `respond` has already closed the connection with the generic
                // code. Which check failed stays here.
                Err(error) => tracing::warn!(%error, "inbound handshake failed"),
            }
        });
    }
}

/// The public node's queue is the store's — §2 keeps the two crates apart, and
/// this is the join.
async fn answer_requests(node: Arc<Node>, mut queue: mpsc::Receiver<Incoming>) {
    while let Some(Incoming { ask, reply }) = queue.recv().await {
        let state = match ask {
            Ask::Connect(request) => {
                let from = request.from_user_id;
                let display_name = request.display_name.clone();
                let state = enqueue(&node, request).await;

                let _ = node.events.try_send(Event::Requested {
                    from,
                    display_name,
                    state,
                });
                state
            }
            Ask::Status(from) => node
                .store
                .request_state(from)
                .await
                .unwrap_or(RequestState::Unknown),
        };

        // A dropped `reply` tells the caller nothing and closes the
        // connection, which is also what a store failure should do. The
        // address goes with every answer and `public::ask` strips it from all
        // but `Accepted`, so the rule lives in one place — §3, M9d.
        let _ = reply.send((state, node.private_advertise));
    }
}

async fn enqueue(node: &Node, request: ConnectionRequest) -> RequestState {
    let pending = PendingRequest {
        from_user_id: request.from_user_id,
        from_identity_pk: request.from_identity_pk,
        display_name: request.display_name,
        created_at: request.created_at,
        received_at: invite::now(),
        state: RequestState::Pending,
    };

    match node.store.enqueue_request(pending, MAX_PENDING).await {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(%error, "queueing a connection request failed");
            // The caller is not told the difference between a full queue, a
            // refusal and a broken database.
            RequestState::Rejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §10's schedule, entry by entry.
    #[test]
    fn the_backoff_follows_the_documented_schedule() {
        for (attempt, secs) in [1u64, 2, 4, 8, 16, 30].into_iter().enumerate() {
            assert_eq!(
                schedule(attempt, Duration::ZERO),
                Some(Duration::from_secs(secs)),
                "attempt {attempt}",
            );
        }
    }

    /// Past the end of it the interval stops growing and starts scattering.
    #[test]
    fn the_backoff_settles_at_thirty_seconds_with_jitter() {
        let mut seen = HashSet::new();
        for attempt in 6..40 {
            let delay = schedule(attempt, Duration::ZERO).expect("inside the budget");
            assert!(
                (Duration::from_secs(24)..=Duration::from_secs(36)).contains(&delay),
                "attempt {attempt} waited {delay:?}, which is not 30s +/- 20%",
            );
            seen.insert(delay);
        }
        assert!(seen.len() > 1, "the jitter produced one value: {seen:?}");
    }

    /// The whole loop is bounded: §10's ten minutes, not an attempt count.
    #[test]
    fn the_backoff_gives_up_after_ten_minutes() {
        assert_eq!(
            schedule(0, Duration::from_secs(10 * 60)),
            None,
            "still retrying at the budget",
        );

        // And the schedule reaches it: summing the delays has to cross ten
        // minutes in a finite number of attempts, or nothing ever gives up.
        let mut elapsed = Duration::ZERO;
        let mut attempts = 0;
        while let Some(delay) = schedule(attempts, elapsed) {
            elapsed += delay;
            attempts += 1;
            assert!(attempts < 100, "the budget was never reached");
        }
        assert!(elapsed >= Duration::from_secs(10 * 60), "{elapsed:?}");
    }

    /// M12b: a silent address has to hit the dial deadline, which says what to
    /// check, before quinn's idle limit, which only says "timed out".
    #[test]
    fn the_dial_deadline_fires_before_the_connection_goes_idle() {
        assert!(Duration::from_millis(DIAL_TIMEOUT_MS) < p2pchat_net::CONNECT_IDLE);
    }

    /// M12c: a dial is a connect then §6, under one deadline. Raise the
    /// handshake timeout without the dial deadline and a slow connect eats
    /// the handshake's time, so the handshake timeout never fires.
    #[test]
    fn the_handshake_and_a_slow_connect_fit_inside_the_dial_deadline() {
        assert!(
            handshake::HANDSHAKE_TIMEOUT + USUAL_CONNECT_BUDGET
                <= Duration::from_millis(DIAL_TIMEOUT_MS),
            "{:?} + {USUAL_CONNECT_BUDGET:?} > {DIAL_TIMEOUT_MS} ms",
            handshake::HANDSHAKE_TIMEOUT,
        );
    }

    /// M12c: a request and a dial give up after the same time.
    #[test]
    fn a_request_and_a_dial_give_up_together() {
        assert_eq!(
            Limits::default().request_timeout,
            Duration::from_millis(DIAL_TIMEOUT_MS)
        );
    }

    /// Gate 5's classifier. A peer that is down is retried; a peer that fails
    /// §6 is not.
    #[test]
    fn only_authentication_failures_are_fatal() {
        // The shape `handshake::initiate` really produces.
        assert!(fatal(
            &anyhow::Error::new(NetError::Crypto(CryptoError::Handshake)).context("handshake")
        ));
        assert!(fatal(&anyhow::Error::new(CryptoError::Handshake)));
        assert!(fatal(&NotAccepted.into()));
        assert!(!fatal(&anyhow!("dialling 127.0.0.1:1 timed out")));
        assert!(!fatal(&anyhow::Error::new(CryptoError::Decrypt)));
    }
}
