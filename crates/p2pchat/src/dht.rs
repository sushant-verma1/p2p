//! `p2pchat dht` — the M16 simulation's driver.
//!
//! A DHT node and nothing else: the identity, a private endpoint that RPCs
//! leave from (M13a), and for a member a public node whose only real business
//! is DHT queries. Driven one line at a time over stdin, answering one line
//! each on stdout, in the protocol `netem/dht.py`'s `Node` documents. Like the
//! debug node, stdout carries full IDs, because nothing but the harness reads
//! it; the log carries fingerprints.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use p2pchat_core::wire::{AddressRecord, DhtAnswer, DhtQuery};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, keystore, record, Identity};
use p2pchat_net::dht::{Dht, Params, Stop};
use p2pchat_net::public::{self, Limits, PublicNode};
use p2pchat_net::{node_endpoint, server_endpoint, NodeKind};
use tokio::sync::mpsc;

use crate::{paths, user_id};

pub async fn run(
    bind: IpAddr,
    private_port: u16,
    public_port: Option<u16>,
    client: bool,
    advertise: Vec<SocketAddr>,
    bootstrap: Vec<SocketAddr>,
) -> Result<()> {
    let identity = keystore::load_or_create(&keystore::key_path(&paths::config_dir()?))?;
    let (private, _stun) = node_endpoint(SocketAddr::new(bind, private_port), NodeKind::Private)
        .context("bind the private endpoint")?;
    let params = Params::from_env();

    let public = match (client, public_port) {
        (true, _) => None,
        (false, Some(port)) => Some(
            server_endpoint(SocketAddr::new(bind, port), NodeKind::Public)
                .context("bind the public endpoint")?,
        ),
        (false, None) => bail!("a member needs --public-port"),
    };
    // The port others are told to use: the advertised one if there is one,
    // since a forwarded port need not be the bound one.
    let member = match &public {
        Some(endpoint) => Some(
            advertise
                .first()
                .map_or(endpoint.local_addr()?.port(), SocketAddr::port),
        ),
        None => None,
    };
    let dht = Dht::new(
        identity.user_id(),
        member,
        private,
        bootstrap.clone(),
        params,
    );

    if let Some(endpoint) = public {
        // Nothing reads connection requests here: the channel's receiver is
        // dropped, so they get silence.
        let (requests, _) = mpsc::channel(1);
        let node = PublicNode {
            invite: invite::create(&identity, "", advertise.clone(), invite::now())
                .context("a member needs --addr")?,
            limits: harness_limits(),
            requests,
            members: bootstrap,
            dht: Some(Arc::clone(&dht)),
        };
        let addr = endpoint.local_addr()?;
        tokio::spawn(public::serve_with_proven(endpoint, node, harness_proven()));
        println!(
            "ready\t{}\t{addr}\tk={}\talpha={}\treplication={}",
            identity.user_id().to_hex(),
            params.k,
            params.alpha,
            params.replication
        );
        let joining = Arc::clone(&dht);
        tokio::spawn(async move {
            let size = joining.join().await;
            println!("event\tjoined\t{size}");
            joining.maintain().await;
        });
    } else {
        println!(
            "ready\t{}\t-\tk={}\talpha={}\treplication={}",
            identity.user_id().to_hex(),
            params.k,
            params.alpha,
            params.replication
        );
    }

    let (lines, mut commands) = mpsc::channel::<String>(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if lines.blocking_send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = commands.recv().await {
        let line = line.trim();
        let verb = line.split_whitespace().next().unwrap_or("");
        if verb.is_empty() {
            continue;
        }
        if verb == "quit" {
            break;
        }
        match command(&dht, &identity, line).await {
            Ok(answer) => println!("ok\t{verb}\t{answer}"),
            Err(error) => println!("err\t{verb}\t{error}"),
        }
    }
    Ok(())
}

/// Limits used only by the stdin-driven DHT harness. The chat node always
/// uses [`Limits::default`]. A compressed refresh clock needs a matching
/// harness allowance; accepting an environment override in this driver keeps
/// that distortion out of product defaults.
fn harness_limits() -> Limits {
    let mut limits = Limits::default();
    for (name, slot) in [
        ("P2PCHAT_HARNESS_PER_SOURCE", &mut limits.per_source),
        (
            "P2PCHAT_HARNESS_FORWARD_PER_MEMBER",
            &mut limits.forward_per_member,
        ),
    ] {
        if let Some(value) = std::env::var(name)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            .filter(|value| *value > 0)
        {
            *slot = value;
        }
    }
    limits
}

/// The harness starts a controlled population after M14's loopback suite has
/// separately proved the actual dial-back path. These are fixtures for that
/// already-proven state, not member claims accepted from the wire.
fn harness_proven() -> Vec<IpAddr> {
    std::env::var("P2PCHAT_HARNESS_PROVEN_IPS")
        .ok()
        .map(|text| text.split(',').filter_map(|ip| ip.parse().ok()).collect())
        .unwrap_or_default()
}

fn stop(stop: Stop) -> &'static str {
    match stop {
        Stop::Exhausted => "exhausted",
        Stop::Value => "value",
        Stop::Budget => "budget",
    }
}

fn join<T: ToString>(items: impl IntoIterator<Item = T>, sep: &str) -> String {
    items
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

async fn command(dht: &Arc<Dht>, identity: &Identity, line: &str) -> Result<String> {
    let mut words = line.split_whitespace();
    let verb = words.next().unwrap_or("");
    let mut next = |what: &str| {
        words
            .next()
            .with_context(|| format!("{verb}: missing {what}"))
    };
    Ok(match verb {
        "table" => {
            let contacts = dht.contacts();
            format!(
                "{}\t{}",
                contacts.len(),
                join(
                    contacts
                        .iter()
                        .map(|c| format!("{}@{}", c.id.to_hex(), c.addr)),
                    " "
                )
            )
        }
        "records" => {
            let held = dht.held();
            format!(
                "{}\t{}",
                held.len(),
                join(held.iter().map(|(k, s)| format!("{}:{s}", k.to_hex())), " ")
            )
        }
        "find" => {
            let target = user_id(next("id")?)?;
            let started = Instant::now();
            let found = dht.lookup(target, false).await;
            format!(
                "{}\t{}\t{}\t{}",
                started.elapsed().as_millis(),
                found.rpcs,
                stop(found.stop),
                join(found.closest.iter().map(|c| c.id.to_hex()), " ")
            )
        }
        "get" => {
            let key = user_id(next("key")?)?;
            let started = Instant::now();
            let found = dht.lookup(key, true).await;
            let (seq, addrs) = match &found.value {
                Some(r) => (r.body.seq.to_string(), join(&r.body.addrs, ",")),
                None => ("-".to_owned(), "-".to_owned()),
            };
            format!(
                "{}\t{}\t{}\t{seq}\t{addrs}",
                started.elapsed().as_millis(),
                found.rpcs,
                stop(found.stop)
            )
        }
        // `publish <seq> <addr,addr>`: this node's record, stored on the
        // `replication` closest members.
        "publish" => {
            let seq: u64 = next("seq")?.parse().context("seq")?;
            let addrs = next("addrs")?
                .split(',')
                .map(str::parse)
                .collect::<Result<Vec<SocketAddr>, _>>()
                .context("addrs")?;
            let record = record::create(identity, addrs, seq, invite::now())?;
            let took = dht.publish(record).await;
            format!(
                "{}\t{}",
                took.len(),
                join(took.iter().map(|c| c.id.to_hex()), " ")
            )
        }
        // `forge <kind> <seq>`: a record that fails M15, sent as it is to the
        // closest members to its key. For gate 7 — what a storage node is
        // given and must not keep.
        "forge" => {
            let kind = next("kind")?.to_owned();
            let seq: u64 = next("seq")?.parse().context("seq")?;
            let record = forge(identity, &kind, seq)?;
            let key = record.body.user_id;
            let found = dht.lookup(key, false).await;
            let to = &found.closest[..found.closest.len().min(dht.params().replication)];
            let took = dht.store_at(&record, to).await;
            format!("{}\t{}", key.to_hex(), took.len())
        }
        // `ask <addr> <key>`: one FIND_VALUE, and what came back as it came.
        "ask" => {
            let addr: SocketAddr = next("addr")?.parse().context("addr")?;
            let key = user_id(next("key")?)?;
            match dht.ask(addr, DhtQuery::FindValue(key)).await?.answer {
                DhtAnswer::Value(r) => format!("value\t{}", r.body.seq),
                DhtAnswer::Nodes(contacts) => format!(
                    "nodes\t{}\t{}",
                    contacts.len(),
                    join(contacts.iter().map(|c| c.id.to_hex()), " ")
                ),
                other => bail!("unexpected answer {other:?}"),
            }
        }
        other => bail!("unknown command {other}"),
    })
}

/// The ways a record fails M15, each signed by this node's own key.
fn forge(identity: &Identity, kind: &str, seq: u64) -> Result<AddressRecord> {
    let addr: SocketAddr = "192.0.2.1:47101".parse()?;
    let now = invite::now();
    Ok(match kind {
        // Signed, then an address changed: the signature no longer covers it.
        "tampered" => {
            let mut r = record::create(identity, vec![addr], seq, now)?;
            r.body.addrs[0] = "198.51.100.66:47101".parse()?;
            r
        }
        // A user ID this key does not hash to.
        "unbound" => {
            let mut r = record::create(identity, vec![addr], seq, now)?;
            r.body.user_id = UserId::from_bytes(identity.user_id().as_bytes().map(|b| !b));
            r
        }
        // Properly signed, and past its lifetime and the skew allowance.
        "expired" => record::create(
            identity,
            vec![addr],
            seq,
            now - record::LIFETIME - invite::SKEW - 60,
        )?,
        // Properly signed and current, with a seq below one already stored.
        "rollback" => record::create(identity, vec![addr], seq, now)?,
        other => bail!("no forgery called {other}"),
    })
}
