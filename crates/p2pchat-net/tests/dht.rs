//! M16 over real QUIC on loopback: a small network in one process.
//!
//! The gates are measured at 50 nodes by `netem/dht.py`, which is where the
//! numbers come from. This is the part that runs in CI: the same code paths,
//! sixteen members, timeouts scaled down, and every gate that does not need
//! a log or a netem profile to observe.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pchat_core::wire::{AddressRecord, DhtAnswer, DhtQuery};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, record, Identity};
use p2pchat_net::dht::{Dht, Params, Stop};
use p2pchat_net::public::{self, Limits, PublicNode};
use p2pchat_net::{node_endpoint, server_endpoint, NodeKind};
use tokio::sync::mpsc;

const MEMBERS: usize = 16;

fn params() -> Params {
    Params {
        k: 8,
        alpha: 3,
        replication: 4,
        // Short enough to observe, long enough that sixteen debug builds
        // pinging one another every round do not time each other out on a
        // loaded machine: at one second they did, and evicted live members.
        refresh: Duration::from_secs(3),
        rpc_timeout: Duration::from_secs(2),
    }
}

fn loopback() -> SocketAddr {
    (std::net::Ipv4Addr::LOCALHOST, 0).into()
}

struct Member {
    identity: Identity,
    dht: Arc<Dht>,
    public: quinn::Endpoint,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Member {
    /// Stops answering, as a killed process would.
    fn kill(&self) {
        self.public.close(0u32.into(), b"");
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn member(bootstrap: Vec<SocketAddr>) -> Member {
    let identity = Identity::generate();
    let (private, _stun) = node_endpoint(loopback(), NodeKind::Private).unwrap();
    let public = server_endpoint(loopback(), NodeKind::Public).unwrap();
    let addr = public.local_addr().unwrap();
    let dht = Dht::new(
        identity.user_id(),
        Some(addr.port()),
        private,
        bootstrap,
        params(),
    );
    let (requests, _) = mpsc::channel(1);
    let node = PublicNode {
        invite: invite::create(&identity, "", vec![addr], invite::now()).unwrap(),
        // Every node here shares 127.0.0.1, so the per-IP limits would be
        // shared too.
        limits: Limits {
            per_source: 100_000,
            forward_per_member: 100_000,
            ..Limits::default()
        },
        requests,
        members: Vec::new(),
        dht: Some(Arc::clone(&dht)),
    };
    let serve = tokio::spawn(public::serve(public.clone(), node));
    Member {
        identity,
        dht,
        public,
        tasks: vec![serve],
    }
}

fn client(bootstrap: Vec<SocketAddr>) -> (UserId, Arc<Dht>) {
    let id = Identity::generate().user_id();
    let (private, _stun) = node_endpoint(loopback(), NodeKind::Private).unwrap();
    (id, Dht::new(id, None, private, bootstrap, params()))
}

async fn network() -> Vec<Member> {
    let mut members = vec![member(Vec::new()).await];
    let seed = members[0].public.local_addr().unwrap();
    for _ in 1..MEMBERS {
        members.push(member(vec![seed]).await);
    }
    // The seed has nobody to ask; it learns the others as they join.
    for m in &members[1..] {
        m.dht.join().await;
    }
    for m in &mut members {
        let dht = Arc::clone(&m.dht);
        m.tasks.push(tokio::spawn(dht.maintain()));
    }
    members
}

/// XOR distance and bucket index, written again here rather than imported:
/// a truth computed with the code under test agrees with that code whatever
/// it does. With `dht::distance` imported, the `numeric` mutant passed.
fn xor(a: &UserId, b: &UserId) -> [u8; 32] {
    std::array::from_fn(|i| a.as_bytes()[i] ^ b.as_bytes()[i])
}

fn shared_bits(a: &UserId, b: &UserId) -> Option<usize> {
    let d = xor(a, b);
    let first = d.iter().position(|&x| x != 0)?;
    Some(first * 8 + d[first].leading_zeros() as usize)
}

fn truth(target: &UserId, ids: impl Iterator<Item = UserId>, k: usize) -> Vec<UserId> {
    let mut ids: Vec<_> = ids.filter(|id| id != target).collect();
    ids.sort_by_key(|id| xor(target, id));
    ids.truncate(k);
    ids
}

fn record_for(m: &Member, seq: u64) -> AddressRecord {
    let addr = m.public.local_addr().unwrap();
    record::create(&m.identity, vec![addr], seq, invite::now()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m16_gates_on_loopback() {
    let members = network().await;
    let ids: Vec<UserId> = members.iter().map(|m| m.identity.user_id()).collect();
    let k = params().k;

    // Gate 2, the invariant it measures: every bucket holds min(k, live
    // members that belong in it). One pass of refresh is allowed for.
    tokio::time::sleep(params().refresh * 2).await;
    for m in &members {
        let me = m.identity.user_id();
        let table = m.dht.contacts();
        for b in 0..256 {
            let want = ids
                .iter()
                .filter(|id| shared_bits(&me, id) == Some(b))
                .count();
            let have = table
                .iter()
                .filter(|c| shared_bits(&me, &c.id) == Some(b))
                .count();
            assert_eq!(have, want.min(k), "{me}: bucket {b}");
        }
    }

    // Gate 1: every member's record, found from every other member, and
    // FIND_NODE exact against the truth computed here.
    for m in &members {
        assert!(!m.dht.publish(record_for(m, 1)).await.is_empty());
    }
    for (n, m) in members.iter().enumerate() {
        let other = &members[(n + 5) % MEMBERS];
        let got = m.dht.lookup(other.identity.user_id(), true).await.value;
        let got = got.unwrap_or_else(|| panic!("no value for {n}"));
        assert_eq!(
            (got.body.user_id, got.body.seq),
            (other.identity.user_id(), 1)
        );
        let target = Identity::generate().user_id();
        let found = m.dht.lookup(target, false).await;
        let got: Vec<UserId> = found.closest.iter().map(|c| c.id).collect();
        let me = m.identity.user_id();
        assert_eq!(
            got,
            truth(&target, ids.iter().copied().filter(|id| *id != me), k)
        );
    }

    // Gate 3: an absent key ends because nothing closer is left to ask.
    let found = members[3]
        .dht
        .lookup(Identity::generate().user_id(), true)
        .await;
    assert!(found.value.is_none());
    assert_eq!(found.stop, Stop::Exhausted);

    // Gate 6: a client finds records and is held by nobody.
    let (client_id, client) = client(vec![members[0].public.local_addr().unwrap()]);
    let found = client.lookup(members[9].identity.user_id(), true).await;
    assert_eq!(found.value.map(|r| r.body.user_id), Some(ids[9]));
    assert!(client.contacts().is_empty());
    for (n, m) in members.iter().enumerate() {
        let held: Vec<_> = m
            .dht
            .contacts()
            .into_iter()
            .filter(|c| c.id == client_id)
            .collect();
        assert!(held.is_empty(), "member {n} holds the client: {held:?}");
    }

    // Gate 7: a tampered record sent straight to the closest members is
    // held by none of them, and none serves it.
    let mut tampered = record_for(&members[2], 9);
    tampered.body.addrs[0] = "198.51.100.66:47101".parse().unwrap();
    let key = tampered.body.user_id;
    let to = members[4].dht.lookup(key, false).await.closest;
    assert!(members[4].dht.store_at(&tampered, &to).await.is_empty());
    for m in &members {
        assert!(m.dht.held().iter().all(|(k, seq)| *k != key || *seq != 9));
        let asked = members[4]
            .dht
            .ask(m.public.local_addr().unwrap(), DhtQuery::FindValue(key))
            .await
            .unwrap();
        if let DhtAnswer::Value(r) = asked.answer {
            assert_eq!(r.body.seq, 1);
        }
    }

    // Gate 5: a killed member is gone from every table within one refresh,
    // a round, and one RPC timeout, plus slack.
    let dead = &members[11];
    dead.kill();
    let limit = params().refresh + params().refresh / 4 + params().rpc_timeout * 2;
    tokio::time::sleep(limit).await;
    for m in members.iter().filter(|m| !std::ptr::eq(*m, dead)) {
        assert!(
            m.dht.contacts().iter().all(|c| c.id != ids[11]),
            "a dead member is still held after {limit:?}"
        );
    }
}
