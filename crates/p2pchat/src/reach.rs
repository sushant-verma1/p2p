//! Reachability self-test — M14, M14b, `plan-v0.2.md`.
//!
//! A node is a DHT member only if a stranger can reach it, and it finds out by
//! asking a bootstrap member to have it dialled back. The asked member hands
//! the dial-back to a second member, which this node never contacted. What
//! counts as the answer is that dial-back arriving here, carrying this test's
//! nonce, from an **IP** this node never sent to. Nothing else does: not the
//! members' claims, and not a dial-back from the IP of any member this node
//! asked — a NAT that filters on IP alone lets anything from that IP in, on
//! any port, because this node sent to it (M14a).
//!
//! Anything short of that is inconclusive, and inconclusive is [`Role::Client`].
//! From here, "the dial-back was blocked" and "nobody tried" look the same, and
//! the cost of guessing wrong is lopsided: a client that could have served
//! costs the network one member, while a member that cannot serve answers no
//! queries and fills routing tables with a dead end.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{Connection, VarInt};

use p2pchat_core::wire::{
    DialBackRequest, PublicRequest, PublicResponse, DIAL_BACK_NONCE_LEN, PROTOCOL_VERSION,
};
use p2pchat_net::public::{self, Limits};

use crate::node::Node;

/// How often the local route is looked at for a network change. A routing
/// table lookup, no packet sent, so it can be frequent; it also floors how
/// often a flapping interface can cause a test.
pub const NETWORK_POLL: Duration = Duration::from_secs(10);

/// How often the test runs with no change seen. Some changes are invisible
/// locally — the router's WAN address changing, a carrier moving a line into
/// CGNAT — and this is the bound on noticing those.
pub const RETEST: Duration = Duration::from_secs(30 * 60);

/// Where the last result is kept, in the data directory.
const FILE: &str = "reachability";

/// Whether this node can serve — M14.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A dial-back reached this node at the address inside, which is where
    /// the bootstrap member saw it come from.
    Member(SocketAddr),
    /// Not shown reachable. Issues lookups, publishes its own record, serves
    /// nothing.
    Client,
}

/// Dial-backs this node is waiting for: nonce to where it arrived from, once
/// it has.
pub(crate) type Pending = std::sync::Mutex<HashMap<[u8; DIAL_BACK_NONCE_LEN], Option<SocketAddr>>>;

/// Why a test came out as it did — logged with every result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// A dial-back arrived from an IP this node never sent to.
    Reached,
    /// No bootstrap member answered at all.
    NoMemberAnswered,
    /// Members answered, but none could hand the dial-back to a second
    /// member. Fewer than two members reachable: nothing can show this node
    /// reachable from an IP it has not contacted, and a dial-back from one it
    /// has contacted proves nothing. Never answered by a single-member test.
    NoSecondMember,
    /// Forwarded, and nothing arrived: something between blocked it.
    NothingArrived,
    /// Arrived, from an IP this node sent to during the test — a member
    /// dialling for itself, which proves only that replies get in.
    ArrivedFromContacted,
}

/// The whole decision. `contacted` is every IP this node sent to during the
/// test; `answer` is the last member answer, if any.
fn classify(contacted: &HashSet<IpAddr>, answer: Option<&Answer>) -> (Role, Why) {
    let Some(answer) = answer else {
        return (Role::Client, Why::NoMemberAnswered);
    };
    if !answer.forwarded {
        return (Role::Client, Why::NoSecondMember);
    }
    match answer.arrived {
        None => (Role::Client, Why::NothingArrived),
        Some(from) if contacted.contains(&from.ip()) => (Role::Client, Why::ArrivedFromContacted),
        Some(_) => (Role::Member(answer.observed), Why::Reached),
    }
}

/// One member's answer to one dial-back request.
#[derive(Clone, Copy, Debug)]
pub struct Answer {
    /// Where the member saw the request come from.
    pub observed: SocketAddr,
    /// The member's claim that it found a second member to dial.
    pub forwarded: bool,
    /// The second member's claim, passed on. Reported, never believed.
    pub reached: bool,
    /// Where a dial-back carrying this request's nonce arrived from, if one
    /// did.
    pub arrived: Option<SocketAddr>,
}

/// Asks `member` for one dial-back. `None` if it did not answer.
pub(crate) async fn ask(node: &Node, member: SocketAddr) -> Option<Answer> {
    let nonce = public::dial_back_nonce();
    pending(node).insert(nonce, None);
    let request = PublicRequest::DialBack(DialBackRequest {
        version: PROTOCOL_VERSION,
        nonce,
    });
    // From the private endpoint, like every ask — M13a. That makes the
    // address tested the one dials and peers use.
    let answer = public::request(
        &node.private,
        member,
        &request,
        Limits::default().request_timeout,
    )
    .await;
    // The second member answers only after the close that follows our
    // reading the nonce, and the asked member only after it, so whatever was
    // going to arrive has.
    let arrived = pending(node).remove(&nonce).flatten();

    match answer {
        Ok(PublicResponse::DialBack {
            observed,
            forwarded,
            reached,
        }) => {
            tracing::info!(%member, %observed, forwarded, reached, arrived = ?arrived, "dial-back test");
            Some(Answer {
                observed,
                forwarded,
                reached,
                arrived,
            })
        }
        Ok(_) => {
            tracing::debug!(%member, "the member answered a different question");
            None
        }
        Err(error) => {
            tracing::debug!(%member, %error, "the member did not answer");
            None
        }
    }
}

/// Asks each bootstrap member in turn until one forwards the dial-back, and
/// classifies on that — or, when none forwards, on the last answer.
pub(crate) async fn test(node: &Node, bootstrap: &[SocketAddr]) -> Role {
    let mut contacted = HashSet::new();
    let mut last = None;
    for &member in bootstrap {
        contacted.insert(member.ip());
        if let Some(answer) = ask(node, member).await {
            last = Some(answer);
            if answer.forwarded {
                break;
            }
        }
    }
    let (role, why) = classify(&contacted, last.as_ref());
    tracing::info!(?role, reason = ?why, members = bootstrap.len(), "reachability test");
    role
}

/// The requester's side of one dial-back, arriving on the private endpoint.
pub(crate) async fn receive(node: &Node, connection: Connection) {
    let from = connection.remote_address();
    let recognised =
        match public::read_dial_back(&connection, Limits::default().dial_back_timeout).await {
            Ok(nonce) => match pending(node).get_mut(&nonce) {
                Some(slot @ None) => {
                    *slot = Some(from);
                    true
                }
                _ => false,
            },
            Err(error) => {
                tracing::debug!(%from, %error, "a dial-back carried no nonce");
                false
            }
        };
    // 0 is "taken", and the member's `reached` rests on it.
    connection.close(VarInt::from_u32(u32::from(!recognised)), b"");
}

fn pending(
    node: &Node,
) -> std::sync::MutexGuard<'_, HashMap<[u8; DIAL_BACK_NONCE_LEN], Option<SocketAddr>>> {
    // A poisoned lock here means a panic mid-insert; the map is still a map.
    node.dial_backs
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Tests at once, then again whenever `network` changes, and every `retest`
/// regardless — M14.
///
/// `network` is whatever identifies the network this node is on; the node
/// passes the local address its route to the first bootstrap member uses,
/// which is what changes when a laptop moves from broadband to a phone's
/// tether. On a change the role drops to `Client` straight away — the old
/// answer was about another network — and the test runs again. So a change
/// is reflected within one `poll` and one test.
pub(crate) async fn watch(
    node: Arc<Node>,
    bootstrap: Vec<SocketAddr>,
    network: impl Fn() -> Option<IpAddr>,
    poll: Duration,
    retest: Duration,
) {
    let path = node.data_dir.join(FILE);

    // A result from the last run stands until this run's first test replaces
    // it, provided it was for this network and is younger than `retest`: the
    // same staleness a running node allows itself.
    let mut on = network();
    if let Some((role, network, age)) = load(&path) {
        if network == on && age < retest {
            node.set_role(role);
        }
    }

    let mut next = Instant::now();
    loop {
        if Instant::now() >= next {
            let role = test(&node, &bootstrap).await;
            node.set_observed(match role {
                Role::Member(addr) => Some(addr),
                Role::Client => None,
            });
            node.set_role(role);
            save(&path, role, on);
            next = Instant::now() + retest;
        }

        tokio::time::sleep(poll).await;

        let now_on = network();
        if now_on != on {
            tracing::info!(from = ?on, to = ?now_on, "the network changed; testing reachability again");
            node.set_role(Role::Client);
            node.set_observed(None);
            next = Instant::now();
        }
        on = now_on;
    }
}

// ---------------------------------------------------------------------------
// The last result, on disk
// ---------------------------------------------------------------------------

/// `member <addr> <network> <unix seconds>` or `client - <network> <seconds>`,
/// `-` for no network.
fn save(path: &Path, role: Role, network: Option<IpAddr>) {
    let role = match role {
        Role::Member(addr) => format!("member {addr}"),
        Role::Client => "client -".to_owned(),
    };
    let network = network.map_or_else(|| "-".to_owned(), |ip| ip.to_string());
    let line = format!("{role} {network} {}\n", crate::node::now_s());
    // Written aside and renamed, so a crash leaves the old line or the new
    // one, never half of one. A failure costs a test at the next start.
    let aside = path.with_extension("new");
    if let Err(error) = std::fs::write(&aside, line).and_then(|()| std::fs::rename(&aside, path)) {
        tracing::warn!(%error, "the reachability result was not saved");
    }
}

/// The saved role, its network, and its age. `None` for no file or one that
/// does not parse, which is the same as never having tested.
fn load(path: &Path) -> Option<(Role, Option<IpAddr>, Duration)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut fields = text.split_whitespace();
    let role = match (fields.next()?, fields.next()?) {
        ("member", addr) => Role::Member(addr.parse().ok()?),
        ("client", _) => Role::Client,
        _ => return None,
    };
    let network = match fields.next()? {
        "-" => None,
        ip => Some(ip.parse().ok()?),
    };
    let at: u64 = fields.next()?.parse().ok()?;
    let age = crate::node::now_s().saturating_sub(at);
    Some((role, network, Duration::from_secs(age)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn answer(forwarded: bool, arrived: Option<SocketAddr>) -> Answer {
        Answer {
            observed: addr("203.0.113.9:47101"),
            forwarded,
            reached: true,
            arrived,
        }
    }

    /// M14b at the decision itself: only a forwarded dial-back from an IP
    /// this node never sent to makes a member.
    #[test]
    fn only_a_forwarded_dial_back_from_an_uncontacted_ip_makes_a_member() {
        let asked = addr("198.51.100.1:47100");
        let contacted = HashSet::from([asked.ip()]);
        let second = addr("198.51.100.2:51000");

        assert_eq!(
            classify(&contacted, Some(&answer(true, Some(second)))),
            (Role::Member(addr("203.0.113.9:47101")), Why::Reached)
        );
        // The asked member's IP, on another port: an IP-only NAT's hole.
        let same_ip = addr("198.51.100.1:51000");
        assert_eq!(
            classify(&contacted, Some(&answer(true, Some(same_ip)))),
            (Role::Client, Why::ArrivedFromContacted)
        );
        assert_eq!(
            classify(&contacted, Some(&answer(true, None))),
            (Role::Client, Why::NothingArrived)
        );
        // Fewer than two members: whatever arrived, it is not evidence.
        assert_eq!(
            classify(&contacted, Some(&answer(false, Some(second)))),
            (Role::Client, Why::NoSecondMember)
        );
        assert_eq!(
            classify(&contacted, None),
            (Role::Client, Why::NoMemberAnswered)
        );
    }

    #[test]
    fn a_saved_result_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        let network = Some("10.0.0.2".parse().unwrap());

        save(&path, Role::Member(addr("203.0.113.9:47101")), network);
        let (role, saved_on, age) = load(&path).unwrap();
        assert_eq!(role, Role::Member(addr("203.0.113.9:47101")));
        assert_eq!(saved_on, network);
        assert!(age < Duration::from_secs(5));

        save(&path, Role::Client, None);
        assert_eq!(
            load(&path).map(|(role, on, _)| (role, on)),
            Some((Role::Client, None))
        );

        std::fs::write(&path, "member not-an-address - 1\n").unwrap();
        assert!(load(&path).is_none());
    }
}
