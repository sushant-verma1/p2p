//! M9d's gates — `architecture.md` §3 and §10: the requester dials.
//!
//! The bug behind this milestone was a `CONNECTION_REQUEST` advertising the
//! requester's *bind* address, which since M9c is `0.0.0.0`. The fix is not a
//! better address: it is that nobody needs one. A request carries no address at
//! all, the acceptor answers an accepted status with its own private address,
//! and the requester dials that. Only the invite's owner has to be reachable —
//! a requester behind NAT or CGNAT can still connect.
//!
//! **M9's manual checklist item 12 is resolved here.** That item was the one
//! left open: a node behind NAT cannot be connected to. It is now half design
//! and half test. The *invite owner* must still be reachable, which is what
//! project.md §7 now says and what no code can change; a requester need not be,
//! which is [`a_requester_that_accepts_no_inbound_connections_gets_a_session`].
//!
//! What these gates cannot show is stated where it applies: both nodes are on
//! loopback, where every endpoint is reachable, so gate 1 asserts the property
//! that survives that — which side dialled — rather than staging a NAT.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pchat::{Config, Event, Node};
use p2pchat_core::wire::{ConnectionStatus, PublicRequest, PublicResponse, RequestState};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, Identity};
use p2pchat_net::public::{self, Ask, Incoming, Limits, PublicNode};
use p2pchat_net::{client_endpoint, server_endpoint, NodeKind};
use p2pchat_store::{db_path, Store};
use tokio::sync::mpsc::{self, Receiver};

/// Long enough for a loopback exchange and one poll interval on a loaded
/// machine, short enough that a stuck test fails rather than hangs.
const PATIENCE: Duration = Duration::from_secs(20);

/// Long enough to be sure nothing is merely late. Above the 2s first poll, so
/// "polling stopped" is a claim about a poll that would have happened.
const QUIET: Duration = Duration::from_secs(4);

/// What these tests pass to `--addr`. Loopback, because both nodes are on this
/// machine; the port is the public one by convention only, since the private
/// advertised address takes this host and the *bound* private port.
const ADDR: &str = "127.0.0.1:47100";

// ---------------------------------------------------------------------------
// A node in a temporary directory
// ---------------------------------------------------------------------------

struct TestNode {
    node: Arc<Node>,
    events: Receiver<Event>,
    /// Deleted when the test ends, so it has to outlive the node.
    _dir: tempfile::TempDir,
}

/// A node with a public endpoint, which is what a request is sent to.
async fn acceptor() -> TestNode {
    node(true).await
}

/// A node with no public endpoint at all: it can ask, and nobody can ask it.
async fn requester() -> TestNode {
    node(false).await
}

async fn node(public: bool) -> TestNode {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (node, events) = start(dir.path(), public).await;
    TestNode {
        node,
        events,
        _dir: dir,
    }
}

/// The node itself, over directories the caller owns — gate 7 restarts one.
async fn start(dir: &Path, public: bool) -> (Arc<Node>, Receiver<Event>) {
    Node::start(Config {
        config_dir: dir.join("config"),
        data_dir: dir.join("data"),
        private_bind: "127.0.0.1:0".parse().expect("a literal address"),
        public_bind: public.then(|| "127.0.0.1:0".parse().expect("a literal address")),
        advertise: vec![ADDR.parse().expect("a literal address")],
        private_advertise: None,
        display_name: "test".to_owned(),
    })
    .await
    .expect("the node starts")
}

impl TestNode {
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
            "the node reported an event it must not have"
        );
    }

    fn public(&self) -> SocketAddr {
        self.node.public_addr().expect("a public endpoint")
    }
}

// ---------------------------------------------------------------------------
// A public node that answers whatever the test tells it to
// ---------------------------------------------------------------------------

/// A public endpoint with no store and no policy behind it: it answers what the
/// test set, and records what it was asked.
///
/// Gates 6, 7 and 8 need either an answer a real node would never give or a
/// count of the questions rather than the answers. A real `Node` gives neither.
struct Liar {
    addr: SocketAddr,
    owner: UserId,
    /// Every question it was asked, in order.
    seen: Arc<Mutex<Vec<Ask>>>,
}

fn liar(answer: (RequestState, Option<SocketAddr>)) -> Liar {
    let identity = Identity::generate();
    let endpoint = server_endpoint(
        "127.0.0.1:0".parse().expect("a literal address"),
        NodeKind::Public,
    )
    .expect("a public endpoint");
    let addr = endpoint.local_addr().expect("a bound address");
    let invite = invite::create(
        &identity,
        "liar",
        vec![ADDR.parse().expect("a literal address")],
        invite::now(),
    )
    .expect("an invite");

    let (requests, mut queue) = mpsc::channel::<Incoming>(8);
    tokio::spawn(public::serve(
        endpoint,
        PublicNode {
            invite,
            limits: Limits::default(),
            requests,
        },
    ));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(Incoming { ask, reply }) = queue.recv().await {
            recorder.lock().expect("the lock").push(ask);
            let _ = reply.send(answer);
        }
    });

    Liar {
        addr,
        owner: identity.user_id(),
        seen,
    }
}

impl Liar {
    /// How many times somebody asked what became of their request.
    fn statuses(&self) -> usize {
        self.seen
            .lock()
            .expect("the lock")
            .iter()
            .filter(|ask| matches!(ask, Ask::Status(_)))
            .count()
    }
}

/// One `CONNECTION_STATUS` question, asked the way a requester asks it — used
/// where the gate is about the *answer* rather than what a node does with it.
async fn status(addr: SocketAddr, from: UserId) -> PublicResponse {
    let endpoint = client_endpoint(NodeKind::Public).expect("a client endpoint");
    public::request(
        &endpoint,
        addr,
        &PublicRequest::Status(ConnectionStatus {
            version: p2pchat_core::wire::PROTOCOL_VERSION,
            from_user_id: from,
        }),
        PATIENCE,
    )
    .await
    .expect("the node answers")
}

// ---------------------------------------------------------------------------
// Gate 1
// ---------------------------------------------------------------------------

/// Gate 1. A requester with no public endpoint, which told nobody where it
/// listens, ends up in a session — and it is the side that dialled.
///
/// The initiator is the assertion because it is the one this machine can make
/// honestly: both nodes are on loopback, so "unreachable" cannot be staged. It
/// is not a weak assertion — the acceptor dialling back is exactly what this
/// milestone removes, and it would show up here as the other user ID.
///
/// The rest is structural rather than tested: `ConnectionRequest` has no
/// address field, so there is nothing for an acceptor to dial back *to*, and no
/// test can be written that watches it try.
#[tokio::test(flavor = "multi_thread")]
async fn a_requester_that_accepts_no_inbound_connections_gets_a_session() {
    let mut host = acceptor().await;
    let mut caller = requester().await;

    let state = caller
        .node
        .request_connection(host.node.me, host.public())
        .await
        .expect("the request is sent");
    assert_eq!(state, RequestState::Pending);

    // The host sees a request from someone it knows nothing about but a key.
    let Event::Requested { from, .. } = host.event().await else {
        panic!("expected a request");
    };
    assert_eq!(from, caller.node.me);

    // The user says yes. The requester's poller does the rest.
    assert!(host.node.decide(from, true).await.expect("the decision"));

    let Event::Connected { peer, initiator } = caller.event().await else {
        panic!("expected a session");
    };
    assert_eq!(peer, host.node.me);
    assert_eq!(
        initiator, caller.node.me,
        "the acceptor dialled the requester; M9d says the requester dials"
    );

    let Event::Connected { initiator, .. } = host.event().await else {
        panic!("expected a session");
    };
    assert_eq!(
        initiator, caller.node.me,
        "the host dialled; only the requester dials"
    );
}

/// M12, project.md §7: an owner nobody can reach — CGNAT, a closed UDP port, a
/// wrong address — is a silence, and a silence ends in a message that says
/// what to check, not a hang. A bound socket that never answers is exactly
/// what the requester sees in all three cases.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_owner_is_reported_with_what_to_check() {
    let caller = requester().await;
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
    let addr = silent.local_addr().expect("its address");

    let error = tokio::time::timeout(
        Duration::from_secs(30),
        caller
            .node
            .request_connection(Identity::generate().user_id(), addr),
    )
    .await
    .expect("a silence ends in an error, not a hang")
    .expect_err("nobody answered");

    let text = format!("{error:#}");
    for needle in [
        addr.to_string().as_str(),
        "p2pchat check",
        "UDP port",
        "a TCP rule does nothing",
        "carrier-grade NAT",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in: {text}");
    }
}

/// M12b: the dial to a silent address gets the same guidance. Its deadline
/// and quinn's idle limit were both 20 seconds and the bare "timed out" won
/// most races; now the deadline fires first. Runs at the real 20 seconds.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_address_is_dialled_into_what_to_check() {
    let caller = requester().await;
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
    let addr = silent.local_addr().expect("its address");

    let error = tokio::time::timeout(Duration::from_secs(40), caller.node.dial(addr, None))
        .await
        .expect("a silence ends in an error, not a hang")
        .expect_err("nobody answered");

    let text = format!("{error:#}");
    for needle in ["no answer from", "UDP port", "carrier-grade NAT"] {
        assert!(text.contains(needle), "missing {needle:?} in: {text}");
    }
}

// ---------------------------------------------------------------------------
// Gate 2
// ---------------------------------------------------------------------------

/// Gate 2. The private address rides with `Accepted` and with nothing else —
/// §3. The status query is unauthenticated, so this is the whole of what an
/// unaccepted stranger can learn about where this node listens.
#[tokio::test(flavor = "multi_thread")]
async fn a_status_carries_an_address_only_when_it_is_accepted() {
    let mut host = acceptor().await;
    let caller = requester().await;
    let advertised = host
        .node
        .private_advertise()
        .expect("the host advertises a private address");

    // Nobody has asked yet: unknown, and no address.
    assert_eq!(
        status(host.public(), caller.node.me).await,
        PublicResponse::State(RequestState::Unknown, None)
    );

    caller
        .node
        .request_connection(host.node.me, host.public())
        .await
        .expect("the request is sent");
    host.event().await;

    assert_eq!(
        status(host.public(), caller.node.me).await,
        PublicResponse::State(RequestState::Pending, None),
        "a pending caller was told where the private node listens"
    );

    host.node
        .decide(caller.node.me, true)
        .await
        .expect("the decision");
    assert_eq!(
        status(host.public(), caller.node.me).await,
        PublicResponse::State(RequestState::Accepted, Some(advertised)),
        "an accepted caller was not told where to dial"
    );

    // And a rejection carries none either.
    let other = requester().await;
    other
        .node
        .request_connection(host.node.me, host.public())
        .await
        .expect("the request is sent");
    host.event().await;
    host.node
        .decide(other.node.me, false)
        .await
        .expect("the decision");
    assert_eq!(
        status(host.public(), other.node.me).await,
        PublicResponse::State(RequestState::Rejected, None),
        "a rejected caller was told where the private node listens"
    );
}

// ---------------------------------------------------------------------------
// Gates 3, 4 and 5: the addresses
// ---------------------------------------------------------------------------

/// Runs `p2pchat node` to its `ready` line and returns the line's fields, or
/// the process's stderr if it never printed one.
///
/// Driven through the binary because that is where flag, environment variable
/// and `config.toml` meet: a test that built a `Config` here would prove
/// nothing about which of the three wins. No public endpoint is asked for, so
/// nothing but the private port is bound.
fn ready_line(
    args: &[&str],
    env: &[(&str, &str)],
    config_toml: Option<&str>,
) -> Result<Vec<String>, String> {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let config = dir.path().join("config");
    std::fs::create_dir_all(&config).expect("the config directory");
    if let Some(text) = config_toml {
        std::fs::write(config.join("config.toml"), text).expect("the config file");
    }

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_p2pchat"));
    command
        .arg("node")
        .arg("--bind")
        .arg("127.0.0.1")
        .args(args)
        .env("P2PCHAT_CONFIG_DIR", &config)
        .env("P2PCHAT_DATA_DIR", dir.path().join("data"))
        // Whatever is set in the shell running `cargo test` would quietly make
        // these pass or fail for the wrong reason.
        .env_remove("P2PCHAT_ADDR")
        .env_remove("P2PCHAT_PRIVATE_ADDR")
        .stdin(std::process::Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }

    // `output` closes stdin, and the node stops when stdin ends: no kill, no
    // orphan, no waiting.
    let out = command.output().expect("the binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let Some(ready) = stdout.lines().next() else {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    };
    Ok(ready.split('\t').map(str::to_owned).collect())
}

/// The fourth field of `ready`: what an accepted requester is told to dial.
fn advertised(fields: &[String]) -> SocketAddr {
    fields[4].parse().expect("an advertised private address")
}

/// Gate 3. The private advertised address is `--addr`'s host with the private
/// port; `--private-addr` beats that; the environment beats the flag, F-27.
///
/// Every address here is in `127.0.0.0/8`, which is loopback end to end, so the
/// gate names hosts without listening anywhere a packet could arrive from.
#[test]
fn the_private_address_is_derived_from_addr_and_can_be_overridden() {
    // Derived. The port is one that was asked for, so the derivation is
    // visible rather than whatever the OS handed out.
    let derived = ready_line(
        &["--private-port", "47131", "--addr", "127.0.0.2:47100"],
        &[],
        None,
    )
    .expect("the node starts");
    assert_eq!(
        advertised(&derived),
        "127.0.0.2:47131".parse().unwrap(),
        "the private address is not --addr's host with the private port"
    );

    // Overridden by the flag.
    let by_flag = ready_line(
        &[
            "--private-port",
            "47132",
            "--addr",
            "127.0.0.2:47100",
            "--private-addr",
            "127.0.0.3:9",
        ],
        &[],
        None,
    )
    .expect("the node starts");
    assert_eq!(
        advertised(&by_flag),
        "127.0.0.3:9".parse().unwrap(),
        "--private-addr was ignored"
    );

    // And overridden again by the environment, which wins over both.
    let by_env = ready_line(
        &[
            "--private-port",
            "47133",
            "--addr",
            "127.0.0.2:47100",
            "--private-addr",
            "127.0.0.3:9",
        ],
        &[("P2PCHAT_PRIVATE_ADDR", "127.0.0.4:10")],
        None,
    )
    .expect("the node starts");
    assert_eq!(
        advertised(&by_env),
        "127.0.0.4:10".parse().unwrap(),
        "the flag beat the environment; F-27 says the override wins"
    );

    // `--addr` comes from the same three places — M9d item 7, so that the one
    // value this host cannot derive need not be retyped at every launch.
    let from_file = ready_line(
        &["--private-port", "47134"],
        &[],
        Some("addr = [\"127.0.0.5:47100\"]\n"),
    )
    .expect("the node starts");
    assert_eq!(
        advertised(&from_file),
        "127.0.0.5:47134".parse().unwrap(),
        "config.toml's addr was ignored"
    );

    let file_and_env = ready_line(
        &["--private-port", "47135"],
        &[("P2PCHAT_ADDR", "127.0.0.6:47100")],
        Some("addr = [\"127.0.0.5:47100\"]\n"),
    )
    .expect("the node starts");
    assert_eq!(
        advertised(&file_and_env),
        "127.0.0.6:47135".parse().unwrap(),
        "P2PCHAT_ADDR did not beat config.toml"
    );
}

/// Gate 4. `0.0.0.0` is where a node listens, not somewhere a peer can dial —
/// and that is as true of the address handed to an accepted requester as of the
/// one in an invite. The node refuses to start rather than hand one out.
#[test]
fn an_unspecified_private_address_is_refused() {
    for addr in ["0.0.0.0:47101", "[::]:47101"] {
        let error = ready_line(&["--addr", ADDR, "--private-addr", addr], &[], None)
            .expect_err("the node started with an unspecified private address");
        assert!(
            error.contains("--addr"),
            "the refusal for {addr} does not say what to pass: {error}"
        );
    }
}

/// Gate 5, the accept half. A node with nothing to advertise cannot accept a
/// request, because there would be nowhere to send the requester — and the
/// refusal is the same line `invite` gives, one constant, so the two cannot
/// drift apart.
///
/// The invite half is `bind.rs::an_invite_with_no_address_is_refused`.
#[tokio::test(flavor = "multi_thread")]
async fn accepting_without_an_address_is_refused_in_the_same_words() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (node, _events) = Node::start(Config {
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

    let peer = UserId::from_bytes([7; 32]);
    let error = node
        .decide(peer, true)
        .await
        .expect_err("the acceptance was allowed with nowhere to dial");
    assert_eq!(error.to_string(), invite::NO_ADDR);
    assert!(error.to_string().contains("--addr"), "{error}");

    // Rejecting needs no address: there is nothing to tell the requester.
    node.decide(peer, false)
        .await
        .expect("a rejection needs no address");
}

// ---------------------------------------------------------------------------
// Gate 6
// ---------------------------------------------------------------------------

/// Gate 6. A forged `Accepted` pointing at somebody else's node makes the
/// requester dial it — and §6 check 3 refuses the peer that answers, so the lie
/// costs one failed connection and nothing else.
///
/// This is the whole of §3's argument for the private address not being a
/// secret: a false address in a status answer can never produce a session with
/// the wrong peer, only a session with nobody.
#[tokio::test(flavor = "multi_thread")]
async fn a_forged_accepted_status_pointing_elsewhere_makes_no_session() {
    let mut bystander = acceptor().await;
    let mut caller = requester().await;

    // The liar answers for its own user ID and hands out the bystander's
    // private endpoint: a node that is running, answering §6, and not the one
    // the requester asked for.
    let elsewhere = bystander
        .node
        .private_advertise()
        .expect("the bystander advertises a private address");
    let liar = liar((RequestState::Accepted, Some(elsewhere)));

    // The two of them have accepted each other already, which is the case the
    // lie is aimed at: §10's access check would refuse a stranger whatever the
    // handshake said, so a gate that left them strangers would pass with §6
    // check 3 deleted. Accepted, the only thing between the requester and a
    // session it believes is with the liar is check 3.
    caller
        .node
        .store
        .resolve_request(bystander.node.me, true)
        .await
        .expect("the store answers");
    bystander
        .node
        .store
        .resolve_request(caller.node.me, true)
        .await
        .expect("the store answers");

    let state = caller
        .node
        .request_connection(liar.owner, liar.addr)
        .await
        .expect("the request is sent");
    assert_eq!(state, RequestState::Accepted);

    // The dial happened and failed. The requester is told so — M9e: a dial
    // that goes nowhere has to reach the screen, or it sits on `connecting`
    // for ever — and what it is told is a failure and never a session.
    let Event::DialFailed { peer, .. } = caller.event().await else {
        panic!("expected the dial to be reported as failed");
    };
    assert_eq!(peer, liar.owner);
    caller.stays_quiet().await;
    bystander.stays_quiet().await;
    assert_eq!(
        caller.node.session_count().await,
        0,
        "the requester holds a session it asked the liar for and got from          somebody else"
    );
    assert_eq!(bystander.node.session_count().await, 0);
    assert_eq!(
        caller.node.session_initiator(&liar.owner).await,
        None,
        "a session with the peer the liar claimed to be"
    );
}

// ---------------------------------------------------------------------------
// Gates 7 and 8
// ---------------------------------------------------------------------------

/// Gate 7. A request still pending when the process stopped is asked about
/// again when it starts.
///
/// Three runtimes, because a restart has to be one: the acceptor's outlives
/// both nodes so the address it answers on does not move, the first node's is
/// shut down — which is what ends its pollers, and a "restart" whose pollers
/// never stopped would prove nothing — and the second node starts on the same
/// directories.
#[test]
fn an_outbound_request_resumes_polling_after_a_restart() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let node_dir = dir.path().join("node");

    let acceptor = runtime();
    // Pending forever: the acceptor's user never decides, which is the state a
    // request is in when a requester is shut down under it.
    let liar = acceptor.block_on(async { liar((RequestState::Pending, None)) });

    let first = runtime();
    first.block_on(async {
        let (node, _events) = start(&node_dir, false).await;
        node.request_connection(liar.owner, liar.addr)
            .await
            .expect("the request is sent");
    });
    // Ends the first node: its endpoints, its store actor and its pollers.
    first.shutdown_timeout(Duration::from_secs(5));

    let asked_before = liar.statuses();

    runtime().block_on(async {
        // The row is on disk, written by the node that has now stopped.
        let store = Store::open(db_path(&node_dir.join("data")))
            .await
            .expect("the store opens");
        assert_eq!(
            store.outbound_requests().await.expect("the store answers"),
            vec![(liar.owner, liar.addr)],
            "the request was not persisted, so there is nothing to resume from"
        );
        store.close().await.expect("the store closes");

        let (_node, _events) = start(&node_dir, false).await;
        tokio::time::timeout(PATIENCE, async {
            while liar.statuses() == asked_before {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the restarted node never asked about its pending request");
    });
}

/// Gate 8. A `Rejected` answer stops the polling and takes back the acceptance
/// that sending the request recorded — §10: we no longer dial them.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejection_stops_the_polling_and_clears_the_acceptance() {
    let caller = requester().await;
    let liar = liar((RequestState::Rejected, None));

    let state = caller
        .node
        .request_connection(liar.owner, liar.addr)
        .await
        .expect("the request is sent");
    assert_eq!(state, RequestState::Rejected);

    assert!(
        !caller
            .node
            .store
            .is_accepted(liar.owner)
            .await
            .expect("the store answers"),
        "a rejected peer is still accepted, so this node would dial it"
    );
    assert!(
        caller
            .node
            .store
            .outbound_requests()
            .await
            .expect("the store answers")
            .is_empty(),
        "the answered request is still queued for polling"
    );

    // Long enough for the first poll, and the second.
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        liar.statuses(),
        0,
        "the requester kept polling a request that was answered"
    );
}

// ---------------------------------------------------------------------------
// M12c: a first dial nobody answers
// ---------------------------------------------------------------------------

/// A host on directories the caller owns, bound and advertising where it is
/// told — the stranding gate restarts one on the same store and port.
async fn host_at(
    dir: &Path,
    public_bind: SocketAddr,
    private_advertise: Option<SocketAddr>,
) -> (Arc<Node>, Receiver<Event>) {
    Node::start(Config {
        config_dir: dir.join("config"),
        data_dir: dir.join("data"),
        private_bind: "127.0.0.1:0".parse().expect("a literal address"),
        public_bind: Some(public_bind),
        advertise: vec![ADDR.parse().expect("a literal address")],
        private_advertise,
        display_name: "test".to_owned(),
    })
    .await
    .expect("the node starts")
}

/// M12c. The first dial after acceptance goes unanswered — here a silent
/// advertised address, on a real link a blip — and the peer is not stranded:
/// the request stays on file, the poller asks and dials again, and when the
/// host comes back on the same store with its real address there is a
/// session. The silent address is never recorded; only one §6 proved is.
///
/// Runs the real 20-second dial deadline once.
#[test]
fn an_unanswered_first_dial_is_retried_until_there_is_a_session() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let host_dir = dir.path().join("host");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
    let silent_addr = silent.local_addr().expect("its address");
    let wait = Duration::from_secs(90);

    let caller_runtime = runtime();
    let mut caller = caller_runtime.block_on(requester());

    let first = runtime();
    let (host, host_events) = first.block_on(host_at(
        &host_dir,
        "127.0.0.1:0".parse().expect("a literal address"),
        Some(silent_addr),
    ));
    let (host_me, public) = (host.me, host.public_addr().expect("a public endpoint"));

    caller_runtime.block_on(async {
        caller
            .node
            .request_connection(host_me, public)
            .await
            .expect("the request is sent");
    });
    first
        .block_on(host.decide(caller.node.me, true))
        .expect("the decision");

    caller_runtime.block_on(async {
        let event = tokio::time::timeout(wait, caller.session_event())
            .await
            .expect("the dial to the silent address ends");
        assert!(
            matches!(event, Some(Event::DialFailed { peer, .. }) if peer == host_me),
            "expected the first dial to fail, got {event:?}"
        );
        assert_eq!(
            caller
                .node
                .store
                .outbound_requests()
                .await
                .expect("the store answers"),
            vec![(host_me, public)],
            "an unanswered dial dropped the request, so nothing will ask again"
        );
        assert!(
            caller
                .node
                .store
                .reconnectable()
                .await
                .expect("the store answers")
                .is_empty(),
            "an address nobody answered on was recorded"
        );
    });

    // The host restarts on the same store and public port, now advertising
    // where it really listens.
    drop((host, host_events));
    first.shutdown_timeout(Duration::from_secs(5));
    let second = runtime();
    let (host, _host_events) = second.block_on(host_at(&host_dir, public, None));
    let real = host.private_advertise().expect("a private address");

    caller_runtime.block_on(async {
        let event = tokio::time::timeout(wait, caller.session_event())
            .await
            .expect("the poller dials again");
        assert!(
            matches!(event, Some(Event::Connected { peer, .. }) if peer == host_me),
            "expected a session, got {event:?}"
        );
        // `Connected` is sent from inside the dial; the address is recorded
        // after it and the row removed after that.
        tokio::time::timeout(PATIENCE, async {
            while !caller
                .node
                .store
                .outbound_requests()
                .await
                .expect("the store answers")
                .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the request outlived its session");
        assert_eq!(
            caller
                .node
                .store
                .reconnectable()
                .await
                .expect("the store answers"),
            vec![(host_me, real)],
            "the address on record is not the one §6 proved"
        );
    });
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}
