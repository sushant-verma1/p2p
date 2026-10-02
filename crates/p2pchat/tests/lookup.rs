//! M17's gates over loopback: real nodes that publish into a small DHT and are
//! dialled out of it.
//!
//! The timings that set OD-6 come from `netem/dht.py publish`, over 50
//! members and netem profiles. This is the part that runs in CI: the same
//! code, eight members, clocks scaled down, and every gate that does not
//! need a record to live out its lifetime. Gate 3's bound is a record's
//! lifetime plus the clock skew allowed, ten minutes, so here it is the
//! "not found" answer and not the time it takes; the harness measures that.
//!
//! As in `reconnect.rs`, a node is stopped by dropping its runtime, so every
//! node, and the DHT, gets one of its own and these are plain `#[test]`s.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pchat::node::NotFound;
use p2pchat::{Config, Event, Node};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, Identity};
use p2pchat_net::dht::{Dht, Params};
use p2pchat_net::public::{self, Limits, PublicNode};
use p2pchat_net::{node_endpoint, server_endpoint, NodeKind};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{self, Receiver};

const MEMBERS: usize = 8;

/// How long anything here may take before the test calls it stuck.
const PATIENCE: Duration = Duration::from_secs(30);

/// Gate 1's bound over loopback: a startup publish is a lookup and four
/// stores, tens of milliseconds, behind a reachability test that finishes
/// in about as long. Generous for a loaded CI machine.
const FINDABLE: Duration = Duration::from_secs(10);

/// A node's public port, when it has a public node.
const PUBLIC_PORT: u16 = 47100;

/// A silent dial gives up after this, so gate 4's stale dial is quick.
const DIAL_TIMEOUT_MS: &str = "2000";

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 2, last))
}

/// The DHT's parameters, for the members here and, through the environment,
/// for the nodes. Process-wide, which is why there is one test in this file.
fn params() -> Params {
    std::env::set_var("P2PCHAT_DHT_K", "8");
    std::env::set_var("P2PCHAT_DHT_ALPHA", "3");
    std::env::set_var("P2PCHAT_DHT_REPLICATION", "4");
    std::env::set_var("P2PCHAT_DHT_REFRESH_MS", "3000");
    std::env::set_var("P2PCHAT_DHT_RPC_TIMEOUT_MS", "2000");
    std::env::set_var("P2PCHAT_DIAL_TIMEOUT_MS", DIAL_TIMEOUT_MS);
    Params::from_env()
}

struct Net {
    runtime: Runtime,
    dhts: Vec<Arc<Dht>>,
    seeds: Vec<SocketAddr>,
}

/// Eight members on 127.0.1.x, each knowing the others as members so that a
/// node's dial-back can be forwarded (M14b). Joined and maintaining.
fn network() -> Net {
    let params = params();
    let runtime = runtime();
    let (dhts, addrs) = runtime.block_on(async {
        let publics: Vec<_> = (0..MEMBERS)
            .map(|n| {
                let at = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 1, n as u8 + 1)), 0);
                server_endpoint(at, NodeKind::Public).unwrap()
            })
            .collect();
        let addrs: Vec<SocketAddr> = publics.iter().map(|e| e.local_addr().unwrap()).collect();
        let mut dhts = Vec::new();
        for (n, public) in publics.into_iter().enumerate() {
            let identity = Identity::generate();
            let (private, _stun) =
                node_endpoint(SocketAddr::new(addrs[n].ip(), 0), NodeKind::Private).unwrap();
            let seed = if n == 0 { Vec::new() } else { vec![addrs[0]] };
            let dht = Dht::new(
                identity.user_id(),
                Some(addrs[n].port()),
                private,
                seed,
                params,
            );
            let (requests, _) = mpsc::channel(1);
            tokio::spawn(public::serve(
                public,
                PublicNode {
                    invite: invite::create(&identity, "", vec![addrs[n]], invite::now()).unwrap(),
                    // Every node here is a handful of IPs asking often.
                    limits: Limits {
                        per_source: 100_000,
                        forward_per_member: 100_000,
                        forward_per_target: 100,
                        ..Limits::default()
                    },
                    requests,
                    members: addrs.clone(),
                    dht: Some(Arc::clone(&dht)),
                },
            ));
            dhts.push(dht);
        }
        for dht in &dhts[1..] {
            dht.join().await;
        }
        for dht in &dhts {
            tokio::spawn(Arc::clone(dht).maintain());
        }
        (dhts, addrs)
    });
    Net {
        runtime,
        dhts,
        seeds: vec![addrs[0]],
    }
}

struct Peer {
    node: Arc<Node>,
    events: Receiver<Event>,
    seen: Vec<Event>,
    runtime: Option<Runtime>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// A node on `ip`, a new private port each start — so a restart is an
/// address change — with a public node if `public`.
fn start(dir: &Path, at: IpAddr, public: bool, seeds: &[SocketAddr]) -> Peer {
    let runtime = runtime();
    let (node, events) = runtime
        .block_on(Node::start(Config {
            config_dir: dir.join("config"),
            data_dir: dir.join("data"),
            private_bind: SocketAddr::new(at, 0),
            public_bind: public.then(|| SocketAddr::new(at, PUBLIC_PORT)),
            // The host a private address is derived from; its port is the
            // bound one (`derive_private_advertise`). The port here is the
            // public node's, which is where a member is told to serve the
            // DHT: advertise a wrong one and every table holds a dead
            // contact, whose timeouts slow every lookup that meets it.
            advertise: vec![SocketAddr::new(at, PUBLIC_PORT)],
            private_advertise: None,
            display_name: "test".to_owned(),
            bootstrap: seeds.to_vec(),
        }))
        .expect("the node starts");
    Peer {
        node,
        events,
        seen: Vec::new(),
        runtime: Some(runtime),
    }
}

fn stop(mut peer: Peer) {
    let runtime = peer.runtime.take().expect("running");
    drop(peer);
    runtime.shutdown_timeout(Duration::from_secs(5));
}

impl Peer {
    fn rt(&self) -> &Runtime {
        self.runtime.as_ref().expect("running")
    }

    fn accept(&self, who: UserId) {
        self.rt()
            .block_on(self.node.store.resolve_request(who, true))
            .expect("the store answers");
    }

    fn drain(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            self.seen.push(event);
        }
    }

    fn wait(&mut self, what: &str, mut done: impl FnMut(&Event) -> bool) {
        let started = Instant::now();
        loop {
            self.drain();
            if self.seen.iter().any(&mut done) {
                return;
            }
            assert!(started.elapsed() < PATIENCE, "never happened: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Polls `dht` for `key`'s record until one carries `addr`. How long it took.
fn findable(net: &Net, dht: &Arc<Dht>, key: UserId, addr: SocketAddr) -> Duration {
    let started = Instant::now();
    loop {
        let found = net.runtime.block_on(dht.lookup(key, true)).value;
        if found.is_some_and(|r| r.body.addrs.contains(&addr)) {
            return started.elapsed();
        }
        assert!(started.elapsed() < PATIENCE, "never findable at {addr}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn m17_gates_on_loopback() {
    let net = network();
    let unrelated = Arc::clone(&net.dhts[5]);

    // Gate 1: a node's record is findable from an unrelated member within a
    // bound of its start, at the address it will be dialled on.
    let dir_b = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let b = start(dir_b.path(), ip(2), false, &net.seeds);
    let first = b.node.private_advertise().unwrap();
    findable(&net, &unrelated, b.node.me, first);
    let took = started.elapsed();
    eprintln!("m17 gate 1: findable from an unrelated member {took:?} after start, at {first}");
    assert!(took < FINDABLE, "{took:?}");

    // Gate 5: an invite still works with the DHT running on both sides:
    // request to the owner's public node, accept, session.
    let dir_p = tempfile::tempdir().unwrap();
    let dir_q = tempfile::tempdir().unwrap();
    let mut p = start(dir_p.path(), ip(3), true, &net.seeds);
    let mut q = start(dir_q.path(), ip(4), false, &net.seeds);
    let (owner, public_addr) = (p.node.me, p.node.public_addr().unwrap());
    let requester = q.node.me;
    let state = {
        let node = Arc::clone(&q.node);
        q.rt()
            .block_on(node.request_connection(owner, public_addr))
            .unwrap()
    };
    p.wait(
        "the request",
        |e| matches!(e, Event::Requested { from, .. } if *from == requester),
    );
    p.rt()
        .block_on(p.node.decide(requester, true))
        .expect("accepted");
    q.wait(
        "the invite's session",
        |e| matches!(e, Event::Connected { peer, .. } if *peer == owner),
    );
    eprintln!("m17 gate 5: invite request answered {state:?}, accepted, session up");

    // Gate 3: a peer with no record is reported not found, not dialled.
    let dir_a = tempfile::tempdir().unwrap();
    let mut a = start(dir_a.path(), ip(1), false, &net.seeds);
    let ghost = Identity::generate().user_id();
    a.accept(ghost);
    let answer = {
        let node = Arc::clone(&a.node);
        a.rt().block_on(node.connect(ghost))
    };
    let error = answer.expect_err("a peer with no record connected");
    eprintln!("m17 gate 3: {error:#}");
    assert!(
        error.is::<NotFound>(),
        "not reported as not found: {error:#}"
    );
    assert!(
        a.rt().block_on(a.node.sessions()).is_empty(),
        "something was dialled"
    );

    // A and B accept each other; B reaches A by user ID alone. B dials, so
    // when B goes, A runs no reconnect loop of its own (§10).
    let (a_id, b_id) = (a.node.me, b.node.me);
    a.accept(b_id);
    b.accept(a_id);
    let reached = {
        let node = Arc::clone(&b.node);
        b.rt().block_on(node.connect(a_id))
    };
    assert_eq!(reached.unwrap(), a_id);
    a.wait(
        "the looked-up session",
        |e| matches!(e, Event::Connected { peer, .. } if *peer == b_id),
    );

    // Gates 2 and 4. B stops. A connects again: it finds B's record at
    // the old address and dials it. While that dial is in flight, B comes
    // back at a new port and publishes. A's dial goes unanswered, and the
    // failure has to be read as a stale record — a newer one exists — not as
    // an unreachable peer, and A has to reach B at the new address.
    stop(b);
    a.drain();
    a.seen.clear();
    let connecting = {
        let node = Arc::clone(&a.node);
        a.rt().spawn(async move { node.connect(b_id).await })
    };
    let started = Instant::now();
    while a.node.phases().get(&b_id) != Some(&p2pchat::node::Phase::Connecting) {
        assert!(
            started.elapsed() < PATIENCE,
            "A never dialled the old record"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let moved_at = Instant::now();
    let b = start(dir_b.path(), ip(2), false, &net.seeds);
    let second = b.node.private_advertise().unwrap();
    assert_ne!(first, second, "the restart kept its port");
    let propagated = findable(&net, &unrelated, b_id, second);
    eprintln!(
        "m17 gate 2: {first} -> {second}, findable from an unrelated member {:?} after the move",
        moved_at.elapsed()
    );
    assert!(propagated < FINDABLE, "{propagated:?}");

    let result = a.rt().block_on(connecting).expect("the task ran");
    a.drain();
    let reasons: Vec<&str> = a
        .seen
        .iter()
        .filter_map(|e| match e {
            Event::DialFailed { peer, reason } if *peer == b_id => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    eprintln!("m17 gate 4: {reasons:?}, then {result:?}");
    assert_eq!(
        reasons.len(),
        1,
        "one failed dial, reported once: {reasons:?}"
    );
    assert!(
        reasons[0].contains("is stale") && reasons[0].contains(&first.to_string()),
        "the stale dial was not diagnosed as stale: {}",
        reasons[0]
    );
    assert!(
        !reasons[0].contains("look the same from here"),
        "diagnosed as M12's unreachable owner: {}",
        reasons[0]
    );
    assert_eq!(
        result.unwrap(),
        b_id,
        "A did not reach B at its new address"
    );

    drop(b);
    drop((p, q, a));
}
