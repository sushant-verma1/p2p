//! M14 and M14b's gates: the reachability self-test, end to end over loopback.
//! And M16a's: the member rate allowance follows a passed dial-back.
//!
//! Members sit on distinct loopback IPs — 127.0.0.2 is the asked member A,
//! 127.0.0.3 the second member B — because M14b is about which *IP* a
//! dial-back comes from, and on one IP there is nothing to tell apart.
//!
//! A NAT is needed to have anything to test, and loopback has none, so [`Nat`]
//! is one: a relay in front of the node with three filtering modes. Open is a
//! full cone. IP-only admits anything from an IP the node has sent to, on any
//! port (address-restricted cone). Closed admits only replies from the exact
//! address the node sent to (endpoint-dependent, what carrier NAT does to an
//! unsolicited dial). Each remote reaches the node through an inside socket on
//! an IP of its own, so the node sees distinct remotes as distinct IPs, as it
//! would through a real NAT. The NAT counts what it drops, so a test can see
//! that a dial-back was sent and blocked rather than never sent.
//!
//! Limit: a real NAT delivers an inbound datagram with the remote's own source
//! address, and this relay cannot, so behind it the node sees each remote as
//! a relay IP. The node's own check — a dial-back from an IP it contacted is
//! not evidence — therefore cannot recognise a member through this NAT, and
//! the NAT's filtering is what these gates measure. That check is exercised
//! without a NAT, by M14 gate 4's lying member and by `reach`'s unit test.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use p2pchat::{Config, Node, Role};
use p2pchat_core::wire::{
    DhtQuery, DhtRequest, DialBackRequest, ForwardDialBack, Member, PublicRequest, PublicResponse,
    PROTOCOL_VERSION,
};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, Identity};
use p2pchat_net::dht::{Dht, Params};
use p2pchat_net::public::{self, Limits, PublicNode};
use p2pchat_net::{connect_as, node_endpoint, recv_frame, send_frame, NodeKind, DIAL_BACK_ALPN};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const PATIENCE: Duration = Duration::from_secs(20);

/// The second member's dial-back limit here: short, so a blocked one is quick.
const DIAL_BACK: Duration = Duration::from_secs(1);

/// How often the node looks for a network change in these tests.
const POLL: Duration = Duration::from_millis(100);

/// Periodic re-testing, set far out of reach so that anything that happens in
/// a test happened because of a network change.
const RETEST: Duration = Duration::from_secs(3600);

/// M14 gate 3's bound: one poll, one forwarded test whose dial-back gives up
/// after [`DIAL_BACK`], and slack for a loaded machine.
const BOUND: Duration = Duration::from_secs(5);

const A: [u8; 4] = [127, 0, 0, 2];
const B: [u8; 4] = [127, 0, 0, 3];

fn on(ip: [u8; 4]) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::from(ip), 0))
}

fn test_limits() -> Limits {
    Limits {
        dial_back_timeout: DIAL_BACK,
        forward_timeout: DIAL_BACK * 3,
        // Every NAT here has its outside on 127.0.0.1, so each test in a
        // test is aimed at the same target IP. Gate 5 sets its own.
        forward_per_target: 100,
        ..Limits::default()
    }
}

// ---------------------------------------------------------------------------
// The pieces
// ---------------------------------------------------------------------------

/// Public nodes on `ips`, each knowing all of them plus `extra` as members.
/// Returns their addresses in the same order.
fn members_with(ips: &[[u8; 4]], extra: &[SocketAddr], limits: Limits) -> Vec<SocketAddr> {
    let endpoints: Vec<_> = ips
        .iter()
        .map(|&ip| node_endpoint(on(ip), NodeKind::Public).unwrap().0)
        .collect();
    let addrs: Vec<SocketAddr> = endpoints.iter().map(|e| e.local_addr().unwrap()).collect();
    let known: Vec<SocketAddr> = addrs.iter().chain(extra).copied().collect();
    for endpoint in endpoints {
        let identity = Identity::generate();
        let own = endpoint.local_addr().unwrap();
        let invite = invite::create(&identity, "", vec![own], invite::now()).unwrap();
        let (requests, _) = mpsc::channel(1);
        tokio::spawn(public::serve(
            endpoint,
            PublicNode {
                invite,
                limits,
                requests,
                members: known.clone(),
                dht: None,
            },
        ));
    }
    addrs
}

/// A and B, knowing each other: A, the one to ask, and B.
fn pair() -> (SocketAddr, SocketAddr) {
    let both = members_with(&[A, B], &[], test_limits());
    (both[0], both[1])
}

/// A member that breaks the rules: it answers "forwarded, reached" whatever
/// happened, and dials back itself from the socket it was asked on, or not at
/// all.
fn lying_member(dials_itself: bool) -> SocketAddr {
    let (endpoint, _stun) = node_endpoint(on([127, 0, 0, 9]), NodeKind::Public).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                continue;
            };
            let Ok(PublicRequest::DialBack(request)) = recv_frame(&mut recv).await else {
                continue;
            };
            let from = connection.remote_address();
            if dials_itself {
                let until = tokio::time::Instant::now() + DIAL_BACK;
                public::dial_back(&endpoint, from, request.nonce, until).await;
            }
            let answer = PublicResponse::DialBack {
                observed: from,
                forwarded: true,
                reached: true,
            };
            let _ = send_frame(&mut send, &answer).await;
            let _ = send.finish();
            let _ = send.stopped().await;
        }
    });
    addr
}

const OPEN: u8 = 0;
const IP_ONLY: u8 = 1;
const CLOSED: u8 = 2;

/// A NAT in front of one node. The node reaches `member` by sending to
/// [`Nat::inside`]; everyone else sees the node at `outside`.
struct Nat {
    inside: SocketAddr,
    outside: SocketAddr,
    mode: Arc<AtomicU8>,
    dropped: Arc<AtomicUsize>,
}

type Contacted = Arc<Mutex<HashSet<SocketAddr>>>;

/// Inside sockets get IPs of their own, from 127.0.1.1 up.
static NEXT_INSIDE: AtomicU8 = AtomicU8::new(1);

async fn nat(node: SocketAddr, member: SocketAddr, mode: u8) -> Nat {
    let outside = Arc::new(UdpSocket::bind(on([127, 0, 0, 1])).await.unwrap());
    let mode = Arc::new(AtomicU8::new(mode));
    let dropped = Arc::new(AtomicUsize::new(0));
    let contacted: Contacted = Arc::default();
    let to_member = relay(Arc::clone(&outside), node, member, Arc::clone(&contacted)).await;
    let inside = to_member.local_addr().unwrap();

    let (outer, gate, count) = (
        Arc::clone(&outside),
        Arc::clone(&mode),
        Arc::clone(&dropped),
    );
    tokio::spawn(async move {
        let mut inside_for = HashMap::from([(member, to_member)]);
        let mut buf = vec![0u8; 65536];
        while let Ok((len, from)) = outer.recv_from(&mut buf).await {
            let admitted = {
                let sent_to = contacted.lock().unwrap();
                match gate.load(Ordering::SeqCst) {
                    OPEN => true,
                    IP_ONLY => sent_to.iter().any(|to| to.ip() == from.ip()),
                    _ => sent_to.contains(&from),
                }
            };
            if !admitted {
                count.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let socket = match inside_for.get(&from) {
                Some(socket) => Arc::clone(socket),
                None => {
                    let socket =
                        relay(Arc::clone(&outer), node, from, Arc::clone(&contacted)).await;
                    inside_for.insert(from, Arc::clone(&socket));
                    socket
                }
            };
            let _ = socket.send_to(&buf[..len], node).await;
        }
    });

    Nat {
        inside,
        outside: outside.local_addr().unwrap(),
        mode,
        dropped,
    }
}

/// An inside socket standing for `remote`: what the node sends to it leaves
/// the NAT's outside socket for `remote`, and marks `remote` contacted.
async fn relay(
    outside: Arc<UdpSocket>,
    node: SocketAddr,
    remote: SocketAddr,
    contacted: Contacted,
) -> Arc<UdpSocket> {
    let ip = [127, 0, 1, NEXT_INSIDE.fetch_add(1, Ordering::SeqCst)];
    let inside = Arc::new(UdpSocket::bind(on(ip)).await.unwrap());
    let socket = Arc::clone(&inside);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            if from == node {
                contacted.lock().unwrap().insert(remote);
                let _ = outside.send_to(&buf[..len], remote).await;
            }
        }
    });
    inside
}

async fn start(dir: &Path, private_advertise: Option<SocketAddr>) -> Arc<Node> {
    let (node, _events) = Node::start(Config {
        config_dir: dir.join("config"),
        data_dir: dir.join("data"),
        private_bind: on([127, 0, 0, 1]),
        public_bind: None,
        advertise: Vec::new(),
        private_advertise,
        display_name: "test".to_owned(),
        // Started by hand below, with a network the test can change.
        bootstrap: Vec::new(),
    })
    .await
    .unwrap();
    node
}

/// A network the test changes by bumping the counter.
fn network(on: &Arc<AtomicU8>) -> impl Fn() -> Option<IpAddr> + Send + 'static {
    let on = Arc::clone(on);
    move || Some(IpAddr::from([10, 0, 0, on.load(Ordering::SeqCst)]))
}

/// The line the node saved after its last test.
fn saved(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("data").join("reachability")).unwrap_or_default()
}

/// Waits for `done`, returning how long it took.
async fn until(what: &str, mut done: impl FnMut() -> bool) -> Duration {
    let started = Instant::now();
    while !done() {
        assert!(started.elapsed() < PATIENCE, "never happened: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    started.elapsed()
}

/// Runs one watched test and returns the role it settled on.
async fn classify(node: &Arc<Node>, dir: &Path, member: SocketAddr) -> Role {
    let on = Arc::new(AtomicU8::new(1));
    node.watch_reachability(vec![member], network(&on), POLL, RETEST);
    until("the first test", || !saved(dir).is_empty()).await;
    node.role()
}

/// A socket standing for a third party. Anything sent to it is queued.
async fn victim() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind(on([127, 0, 0, 7])).await.unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

/// Whether anything reached the victim within twice a dial-back's time.
async fn heard(victim: &UdpSocket) -> Option<SocketAddr> {
    let mut buf = [0u8; 2048];
    tokio::time::timeout(DIAL_BACK * 2, victim.recv_from(&mut buf))
        .await
        .ok()
        .map(|received| received.unwrap().1)
}

/// Sends `frame` as a public request from `from` to `to`; the answer, if any.
async fn raw_ask(from: &quinn::Endpoint, to: SocketAddr, frame: &[u8]) -> Option<PublicResponse> {
    tokio::time::timeout(PATIENCE, async {
        let connection = connect_as(from, NodeKind::Public, to).await.ok()?;
        let (mut send, mut recv) = connection.open_bi().await.ok()?;
        send.write_all(frame).await.ok()?;
        let _ = send.finish();
        recv_frame::<PublicResponse>(&mut recv).await.ok()
    })
    .await
    .ok()
    .flatten()
}

fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend(body);
    frame
}

fn forward_to(target: SocketAddr) -> Vec<u8> {
    framed(
        postcard::to_stdvec(&PublicRequest::ForwardDialBack(ForwardDialBack {
            version: PROTOCOL_VERSION,
            nonce: public::dial_back_nonce(),
            target,
        }))
        .unwrap(),
    )
}

/// Accepts dial-backs and takes them all, counting how many arrived.
fn counting_target(ip: [u8; 4]) -> (SocketAddr, Arc<AtomicUsize>) {
    let (endpoint, _stun) = node_endpoint(on(ip), NodeKind::Private).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        let _stun = _stun;
        while let Some(incoming) = endpoint.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    let _ = public::read_dial_back(&connection, PATIENCE).await;
                    connection.close(0u32.into(), b"");
                }
            });
        }
    });
    (addr, count)
}

// ---------------------------------------------------------------------------
// M14b gates
// ---------------------------------------------------------------------------

/// M14b gate 1: behind a NAT that filters on IP alone, B's dial-back is
/// dropped — the node never sent to B's IP — and the node is a client. Had A
/// dialled back itself, the NAT would have admitted it: the node sent to A.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_1_a_node_behind_an_ip_only_nat_is_a_client() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), None).await;
    let nat = nat(node.private_addr().unwrap(), pair().0, IP_ONLY).await;

    let role = classify(&node, dir.path(), nat.inside).await;
    let dropped = nat.dropped.load(Ordering::SeqCst);
    eprintln!("m14b gate 1: role {role:?}, {dropped} datagrams from B dropped at the IP-only NAT");
    assert_eq!(role, Role::Client);
    assert!(
        dropped > 0,
        "nothing was dropped: either nothing dialled back, or it came from an IP the node \
         had sent to"
    );
}

/// M14b gate 2: a reachable node is a member, and the dial-back that made it
/// one came from B's IP, not from A's.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_2_a_reachable_node_is_a_member_via_the_forwarded_dial_back() {
    let asked = pair().0;

    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), None).await;
    let answer = node.dial_back_once(asked).await.expect("A answered");
    eprintln!("m14b gate 2: {answer:?}");
    assert!(answer.forwarded, "A found no second member");
    let from = answer.arrived.expect("the dial-back arrived");
    assert_eq!(
        from.ip(),
        IpAddr::from(B),
        "the dial-back came from {from}, not B"
    );

    let role = classify(&node, dir.path(), asked).await;
    assert_eq!(role, Role::Member(node.private_addr().unwrap()));

    // And through a full-cone NAT, at the NAT's outside address.
    let dir = tempfile::tempdir().unwrap();
    let coned = start(dir.path(), None).await;
    let nat = nat(coned.private_addr().unwrap(), pair().0, OPEN).await;
    let role = classify(&coned, dir.path(), nat.inside).await;
    eprintln!(
        "m14b gate 2: direct {:?}, behind a full cone {role:?}",
        node.role()
    );
    assert_eq!(role, Role::Member(nat.outside));
}

/// M14b gate 3: fewer than two members reachable means client, and nothing
/// is dialled at all — A alone, and A whose only other member is down. The
/// node itself is reachable, so a single-member dial-back would arrive.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_3_fewer_than_two_members_reachable_is_a_client() {
    let alone = members_with(&[A], &[], test_limits())[0];
    let dead: SocketAddr = "127.0.0.3:9".parse().unwrap();
    let orphaned = members_with(&[[127, 0, 0, 4]], &[dead], test_limits())[0];

    for (what, asked) in [("alone", alone), ("other member down", orphaned)] {
        let dir = tempfile::tempdir().unwrap();
        let node = start(dir.path(), None).await;
        let answer = node.dial_back_once(asked).await.expect("A answered");
        eprintln!("m14b gate 3, {what}: {answer:?}");
        assert!(!answer.forwarded, "{what}: A claims a second member");
        assert_eq!(answer.arrived, None, "{what}: a dial-back arrived anyway");
        assert_eq!(
            classify(&node, dir.path(), asked).await,
            Role::Client,
            "{what}"
        );
    }
}

/// M14b gate 4: B's target comes from A's view of the connection, never from
/// the requester, and B takes a target from nobody but a member.
///
/// A requester writes a victim's address after its request, in postcard's
/// own encoding — what a request naming a target would carry. B dials the
/// requester where A saw it, and the victim hears nothing. A stranger sending
/// B a forward naming the victim gets silence, and so does the victim.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_4_b_dials_only_what_a_observed() {
    let (asked, b) = pair();
    let (victim, victim_addr) = victim().await;
    let (requester, _stun) = node_endpoint(on([127, 0, 0, 1]), NodeKind::Private).unwrap();

    // Decoded rather than written as a literal, so the same bytes serve a
    // `DialBackRequest` that grew a target field — the mutation this gate
    // exists to catch — and hand it the victim's address.
    let nonce = public::dial_back_nonce();
    let request: DialBackRequest = postcard::from_bytes(
        &postcard::to_stdvec(&(PROTOCOL_VERSION, nonce, victim_addr)).unwrap(),
    )
    .unwrap();
    let mut body = postcard::to_stdvec(&PublicRequest::DialBack(request)).unwrap();
    body.extend(postcard::to_stdvec(&victim_addr).unwrap());

    let accepting = requester.clone();
    let dialled_back = tokio::spawn(async move {
        let connection = accepting.accept().await.unwrap().await.unwrap();
        assert_eq!(
            p2pchat_net::alpn(&connection).as_deref(),
            Some(DIAL_BACK_ALPN)
        );
        assert_eq!(
            public::read_dial_back(&connection, PATIENCE).await.unwrap(),
            nonce
        );
        connection.close(0u32.into(), b"");
        connection.remote_address()
    });
    let answer = raw_ask(&requester, asked, &framed(body)).await;

    let reached_victim = heard(&victim).await;
    assert_eq!(
        reached_victim, None,
        "the requester aimed B at {victim_addr}"
    );

    let own = requester.local_addr().unwrap();
    assert_eq!(
        answer,
        Some(PublicResponse::DialBack {
            observed: own,
            forwarded: true,
            reached: true
        })
    );
    let from = tokio::time::timeout(PATIENCE, dialled_back)
        .await
        .expect("the requester was dialled back")
        .unwrap();
    assert_eq!(from.ip(), b.ip(), "dialled back from {from}, not B");

    // A stranger's forward, straight to B.
    let (stranger, _stun) = node_endpoint(on([127, 0, 0, 5]), NodeKind::Private).unwrap();
    let refused = raw_ask(&stranger, b, &forward_to(victim_addr)).await;
    assert_eq!(refused, None, "B answered a stranger's forward");
    assert_eq!(
        heard(&victim).await,
        None,
        "a stranger aimed B at {victim_addr}"
    );
    eprintln!(
        "m14b gate 4: B dialled the requester {own} from {from}; the named {victim_addr} heard \
         nothing, and B ignored a stranger's forward"
    );
}

/// M14b gate 5: forwarded dial-backs are rate-limited per target, whoever
/// forwards them, and per forwarding member, whatever the targets. Limits
/// here: two per target, three per member, a minute each.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_5_rate_limits_hold() {
    let limits = Limits {
        forward_per_target: 2,
        forward_per_member: 3,
        ..test_limits()
    };
    // Two forwarders B knows as members, without public nodes of their own.
    let (one, _s1) = node_endpoint(on([127, 0, 0, 20]), NodeKind::Private).unwrap();
    let (two, _s2) = node_endpoint(on([127, 0, 0, 21]), NodeKind::Private).unwrap();
    let b = members_with(
        &[B],
        &[one.local_addr().unwrap(), two.local_addr().unwrap()],
        limits,
    )[0];

    // A flood at one target, from both forwarders.
    let (target, dialled) = counting_target([127, 0, 0, 30]);
    let mut answered = 0;
    for forwarder in [&one, &two, &one, &two, &one, &two] {
        if raw_ask(forwarder, b, &forward_to(target)).await.is_some() {
            answered += 1;
        }
    }
    let per_target = dialled.load(Ordering::SeqCst);
    eprintln!("m14b gate 5: 6 forwards at one target from two members: {answered} answered, {per_target} dialled");
    assert_eq!(per_target, 2, "the target was dialled {per_target} times");

    // One member, fresh targets: its allowance is three a minute, and it
    // spent up to three above.
    let (fresh, _s4) = node_endpoint(on([127, 0, 0, 22]), NodeKind::Private).unwrap();
    let b2 = members_with(&[[127, 0, 0, 23]], &[fresh.local_addr().unwrap()], limits)[0];
    let mut per_member = 0;
    for n in 0..6u8 {
        let (target, _) = counting_target([127, 0, 2, n + 1]);
        if raw_ask(&fresh, b2, &forward_to(target)).await.is_some() {
            per_member += 1;
        }
    }
    eprintln!("m14b gate 5: 6 forwards at 6 targets from one member: {per_member} answered");
    assert_eq!(
        per_member, 3,
        "one member got {per_member} forwards through"
    );
}

/// M14b gate 6, the security gate: a forwarding member cannot be used to aim
/// B at a third party. Every route through A that a requester controls:
/// naming a target in its dial-back request, and handing A a forward of its
/// own naming one. Neither reaches the victim.
#[tokio::test(flavor = "multi_thread")]
async fn m14b_gate_6_a_forwarding_member_cannot_be_aimed_at_a_third_party() {
    let asked = pair().0;
    let (victim, victim_addr) = victim().await;
    let (attacker, _stun) = node_endpoint(on([127, 0, 0, 8]), NodeKind::Private).unwrap();

    // Route 1: a dial-back request naming the victim.
    let request: DialBackRequest = postcard::from_bytes(
        &postcard::to_stdvec(&(PROTOCOL_VERSION, public::dial_back_nonce(), victim_addr)).unwrap(),
    )
    .unwrap();
    let mut body = postcard::to_stdvec(&PublicRequest::DialBack(request)).unwrap();
    body.extend(postcard::to_stdvec(&victim_addr).unwrap());
    let accepting = attacker.clone();
    tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            if let Ok(connection) = incoming.await {
                connection.close(1u32.into(), b"");
            }
        }
    });
    let _ = raw_ask(&attacker, asked, &framed(body)).await;
    let route_1 = heard(&victim).await;

    // Route 2: a forward, handed to A as though the attacker were a member.
    let answered = raw_ask(&attacker, asked, &forward_to(victim_addr)).await;
    let route_2 = heard(&victim).await;

    eprintln!(
        "m14b gate 6: victim {victim_addr} heard from route 1: {route_1:?}, route 2: \
         {route_2:?} (A answered route 2: {})",
        answered.is_some()
    );
    assert_eq!(
        route_1, None,
        "a requester aimed the dial-back at {victim_addr}"
    );
    assert_eq!(
        route_2, None,
        "a stranger's forward through A reached {victim_addr}"
    );
    assert_eq!(answered, None, "A answered a stranger's forward");
}

// ---------------------------------------------------------------------------
// M14's gates, on the forwarded path
// ---------------------------------------------------------------------------

/// M14 gate 1: behind CGNAT the dial-back is dropped, and the node is a
/// client. The drop count shows it was really sent.
#[tokio::test(flavor = "multi_thread")]
async fn m14_gate_1_a_node_behind_cgnat_is_a_client() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), None).await;
    let nat = nat(node.private_addr().unwrap(), pair().0, CLOSED).await;
    let role = classify(&node, dir.path(), nat.inside).await;
    let dropped = nat.dropped.load(Ordering::SeqCst);
    eprintln!("m14 gate 1: role {role:?}, {dropped} datagrams dropped at the NAT");
    assert_eq!(role, Role::Client);
    assert!(dropped > 0, "nothing was dropped, so this proved nothing");
}

/// M14 gate 3: broadband to tether and back. Periodic re-testing is an hour
/// away, so each change is noticed by the watcher or not at all, within
/// [`BOUND`].
#[tokio::test(flavor = "multi_thread")]
async fn m14_gate_3_the_role_follows_a_network_change_within_a_bound() {
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), None).await;
    let nat = nat(node.private_addr().unwrap(), pair().0, OPEN).await;
    let on = Arc::new(AtomicU8::new(1));
    node.watch_reachability(vec![nat.inside], network(&on), POLL, RETEST);
    until("the first test", || node.role() != Role::Client).await;

    // Onto the tether: CGNAT, a new local address.
    nat.mode.store(CLOSED, Ordering::SeqCst);
    on.store(2, Ordering::SeqCst);
    let to_client = until("a re-test on the tether", || {
        node.role() == Role::Client && saved(dir.path()).starts_with("client - 10.0.0.2 ")
    })
    .await;

    // And back.
    nat.mode.store(OPEN, Ordering::SeqCst);
    on.store(3, Ordering::SeqCst);
    let to_member = until("a re-test back on broadband", || {
        node.role() == Role::Member(nat.outside)
    })
    .await;

    eprintln!("m14 gate 3: member -> client re-tested in {to_client:?}, client -> member in {to_member:?}, bound {BOUND:?}");
    assert!(to_client < BOUND, "{to_client:?}");
    assert!(to_member < BOUND, "{to_member:?}");
}

/// M14 gate 4: claims are not evidence. A node that advertises an address and
/// kept a `member` result from this network is tested again, and behind CGNAT
/// becomes a client. A member claiming "forwarded, reached" with nothing
/// arriving, or dialling back itself from the IP the node asked, does not make
/// a node a member — even one that, on loopback, really is reachable.
#[tokio::test(flavor = "multi_thread")]
async fn m14_gate_4_a_false_claim_of_reachability_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let claimed: SocketAddr = "203.0.113.9:47101".parse().unwrap();
    let node = start(dir.path(), Some(claimed)).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        dir.path().join("data").join("reachability"),
        format!("member {claimed} 10.0.0.1 {now}\n"),
    )
    .unwrap();
    let nat = nat(node.private_addr().unwrap(), pair().0, CLOSED).await;
    let on = Arc::new(AtomicU8::new(1));
    node.watch_reachability(vec![nat.inside], network(&on), POLL, RETEST);
    until("the claim to be tested", || {
        saved(dir.path()).starts_with("client")
    })
    .await;
    assert_eq!(node.role(), Role::Client, "a claimed and remembered member");

    for dials_itself in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let node = start(dir.path(), None).await;
        let role = classify(&node, dir.path(), lying_member(dials_itself)).await;
        assert_eq!(
            role,
            Role::Client,
            "a lying member that dials itself: {dials_itself}"
        );
    }
    eprintln!("m14 gate 4: claimed-and-remembered member behind CGNAT, and both lying members: all Client");
}

// ---------------------------------------------------------------------------
// M16a: the member allowance follows a passed dial-back
// ---------------------------------------------------------------------------

/// A DHT ping, from `ip`, naming the sender a member when `claim` is set.
/// `true` if it was answered.
async fn ping_from(from: &quinn::Endpoint, to: SocketAddr, claim: Option<UserId>) -> bool {
    let request = PublicRequest::Dht(DhtRequest {
        version: PROTOCOL_VERSION,
        from: claim.map(|id| Member { id, port: 47100 }),
        query: DhtQuery::Ping,
    });
    public::request(from, to, &request, Duration::from_secs(2))
        .await
        .is_ok()
}

async fn pings_answered(from: &quinn::Endpoint, to: SocketAddr, claim: Option<UserId>) -> u32 {
    let mut answered = 0;
    for _ in 0..12 {
        answered += u32::from(ping_from(from, to, claim).await);
    }
    answered
}

/// M16a gate: a node that names itself a member, and is held in the routing
/// table for it, gets the stranger allowance. A node that passed a forwarded
/// dial-back through this member gets the member allowance, without claiming
/// anything. Allowances here: three a minute for a stranger, eight for a
/// member, so the two cannot be mistaken for each other.
#[tokio::test(flavor = "multi_thread")]
async fn m16a_the_member_allowance_follows_a_passed_dial_back_not_a_claim() {
    const STRANGER: u32 = 3;
    const MEMBER: u32 = 8;
    let limits = Limits {
        per_source: STRANGER,
        forward_per_member: MEMBER,
        ..test_limits()
    };
    // B takes forwards from A's IP. A is a DHT member, so a claim can put a
    // sender in its routing table.
    let b = members_with(&[B], &[SocketAddr::from((Ipv4Addr::from(A), 1))], limits)[0];
    let (public_a, _s) = node_endpoint(on(A), NodeKind::Public).unwrap();
    let a = public_a.local_addr().unwrap();
    let (private_a, _s2) = node_endpoint(on(A), NodeKind::Private).unwrap();
    let identity = Identity::generate();
    let dht = Dht::new(
        identity.user_id(),
        Some(a.port()),
        private_a,
        Vec::new(),
        Params::default(),
    );
    let (requests, _) = mpsc::channel(1);
    tokio::spawn(public::serve(
        public_a,
        PublicNode {
            invite: invite::create(&identity, "", vec![a], invite::now()).unwrap(),
            limits,
            requests,
            members: vec![b],
            dht: Some(Arc::clone(&dht)),
        },
    ));

    // The claimant: names itself a member on every request, and is held.
    let claimant = Identity::generate().user_id();
    let (from_claimant, _s3) = node_endpoint(on([127, 0, 0, 40]), NodeKind::Private).unwrap();
    let claimed = pings_answered(&from_claimant, a, Some(claimant)).await;
    let held = dht.contacts().iter().any(|c| c.id == claimant);

    // The proven node: a real node, reachable, tested through A. Its pings
    // then claim nothing.
    let dir = tempfile::tempdir().unwrap();
    let node = start(dir.path(), None).await;
    let answer = node.dial_back_once(a).await.expect("A answered");
    let (from_proven, _s4) = node_endpoint(on([127, 0, 0, 1]), NodeKind::Private).unwrap();
    let proven = pings_answered(&from_proven, a, None).await;

    eprintln!(
        "m16a gate: claimant held in the table: {held}, answered {claimed} of 12; \
         proven ({answer:?}) answered {proven} of 12"
    );
    assert!(held, "the claimant never got a routing-table slot");
    assert_eq!(claimed, STRANGER, "the claim raised the allowance");
    assert!(
        answer.forwarded && answer.arrived.is_some(),
        "the dial-back did not pass"
    );
    assert_eq!(
        proven, MEMBER,
        "a passed dial-back did not raise the allowance"
    );
}

/// M17 found it: a member on a wildcard bind that lists itself as a member
/// forwarded to itself, since `0.0.0.0` matched none of its entries, and so
/// every requester that asked it was dialled back from an IP it had sent to.
/// The dial-back has to come from B.
///
/// Built as a single-IP member is on a real host: A listens on the wildcard,
/// lists itself at 127.0.0.1, is asked there, and its forwards leave from
/// there too. The requester sits on an IP of its own, so no skip rule about
/// the requester's IP can hide the self-forward.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_on_a_wildcard_bind_does_not_forward_to_itself() {
    let (wild, _s) = node_endpoint(on([0, 0, 0, 0]), NodeKind::Public).unwrap();
    let a = SocketAddr::from((Ipv4Addr::LOCALHOST, wild.local_addr().unwrap().port()));
    let b = members_with(&[B], &[a], test_limits())[0];
    let identity = Identity::generate();
    let (requests, _) = mpsc::channel(1);
    tokio::spawn(public::serve(
        wild,
        PublicNode {
            invite: invite::create(&identity, "", vec![a], invite::now()).unwrap(),
            limits: test_limits(),
            requests,
            // Itself first, as a bootstrap list shared by every member is.
            members: vec![a, b],
            dht: None,
        },
    ));

    let dir = tempfile::tempdir().unwrap();
    let (node, _events) = Node::start(Config {
        config_dir: dir.path().join("config"),
        data_dir: dir.path().join("data"),
        private_bind: on([127, 0, 0, 50]),
        public_bind: None,
        advertise: Vec::new(),
        private_advertise: None,
        display_name: "test".to_owned(),
        bootstrap: Vec::new(),
    })
    .await
    .unwrap();
    let answer = node.dial_back_once(a).await.expect("A answered");
    eprintln!("wildcard member: {answer:?}");
    let from = answer.arrived.expect("the dial-back arrived");
    assert_eq!(
        from.ip(),
        IpAddr::from(B),
        "dialled back from {from}, not B"
    );
}
