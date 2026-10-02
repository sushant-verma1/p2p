//! Kademlia — `plan-v0.2.md` M16, `architecture.md` §3.
//!
//! **Members only.** A node that M14 found reachable holds a routing table,
//! stores records and answers queries. A client issues lookups from the
//! bootstrap list each time and holds nothing: its requests carry no
//! [`Member`], so nobody adds it, and it serves nothing, so nobody could use
//! it if they did.
//!
//! **Nothing a storage node says is trusted, and nothing it is given is
//! trusted either.** A record is checked with `record::supersedes` before it
//! is stored, again with `record::verify` before it is served (it may have
//! expired while held), and again by the asker, which also checks that the
//! record is for the key it asked about. A valid record for somebody else is
//! still a wrong answer.
//!
//! **IDs are attacker-chosen.** A node ID is a user ID, and anyone can grind
//! keys until one lands where they like. So nothing here is keyed by a
//! `HashMap` over IDs (`techstack.md`), and every collection that grows from
//! network input has a bound: [`Table`] holds at most `k` per bucket and one
//! liveness check per bucket at a time, a lookup's shortlist and budget are
//! capped ([`SHORTLIST`], [`MAX_LOOKUP_RPCS`]), at most [`MAX_LOOKUPS`] run at
//! once, and [`MAX_RECORDS`] are held, one per key. What an attacker who
//! grinds IDs can still do — fill the buckets near a target — is the eclipse
//! attack M20 documents, not something bounds fix.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use quinn::Endpoint;
use rand::RngCore;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use p2pchat_core::wire::{
    AddressRecord, Contact, DhtAnswer, DhtQuery, DhtRequest, DhtResponse, Member, PublicRequest,
    PublicResponse, MAX_CONTACTS, PROTOCOL_VERSION,
};
use p2pchat_core::UserId;
use p2pchat_crypto::{invite, record};

use crate::{public, NetError};

/// Records held for other users. About 250 bytes each, so a megabyte.
pub const MAX_RECORDS: usize = 4096;

/// Lookups running at once. A lookup holds a shortlist and up to `alpha`
/// connections; this is what bounds how many of those exist.
pub const MAX_LOOKUPS: usize = 16;

/// RPCs one lookup may spend. With honest answers a lookup ends long before
/// this, when every one of the `k` closest it knows has answered; the budget
/// is for answers that keep naming closer contacts that do not exist.
pub const MAX_LOOKUP_RPCS: usize = 128;

/// Candidates a lookup keeps. Four answers' worth: the farthest are dropped
/// first, and they are never the ones a lookup is waiting on.
pub const SHORTLIST: usize = 4 * MAX_CONTACTS;

/// Liveness checks in flight at once from one maintenance round.
const CHECKS: usize = 32;

/// Kademlia's knobs — OD-7, chosen against `netem/dht.py trial`: 50
/// members, 30% of them killed at once, lookups from every survivor at the
/// moment of the kill. `plan-v0.2.md` M16 has the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Contacts per bucket, and how many closest contacts a lookup returns.
    /// 20. k = 4 and 8 lost records that k = 12 and 20 found, and k = 12
    /// and 20 tied on every correctness count. 20 is kept for the margin
    /// over `replication`: at the kill a lookup's answer held a median of
    /// 10.5 live contacts at k = 12 and 14 at k = 20, and a publish needs
    /// eight. Fifty nodes are close to a full mesh at either value, so the
    /// simulation cannot show what k buys a large network.
    pub k: usize,
    /// RPCs a lookup keeps in flight. 5. With dead contacts in every
    /// table, a lookup's time is 20-second RPC timeouts in series, and alpha
    /// sets how many overlap: FIND_NODE took p50 160 s at alpha = 1, 70 s at
    /// 2, 60 s at 3, 40 s at 5. Under netem `poor`, a record lookup's worst
    /// case was 247 s, 20.9 s, 2.9 s and 1.2 s. The price is 23% more RPCs
    /// than 3 (10.2 against 8.3 a lookup).
    pub alpha: usize,
    /// How many of the closest nodes a record is stored on. 8. With 30% of
    /// members killed at once, records went missing at close to 0.3^r:
    /// 36%, 16%, 2.5%, 0.7% and 0.4% of lookups for r = 1 to 5, none of 560
    /// at r = 8 (0.007% expected). Storing costs r RPCs a republish.
    pub replication: usize,
    /// A bucket nobody has looked up in for this long is refreshed, and a
    /// contact not heard from for this long is pinged. Placeholder, like
    /// `record::LIFETIME`: M19 measures it under churn.
    pub refresh: Duration,
    /// One RPC, connect to answer. `request_timeout`, so that a DHT RPC and
    /// every other public exchange give up after the same time (M12c, M14b).
    pub rpc_timeout: Duration,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            k: 20,
            alpha: 5,
            replication: 8,
            refresh: Duration::from_secs(15 * 60),
            rpc_timeout: public::Limits::default().request_timeout,
        }
    }
}

impl Params {
    /// The defaults, with `P2PCHAT_DHT_K`, `_ALPHA`, `_REPLICATION`,
    /// `_REFRESH_MS` and `_RPC_TIMEOUT_MS` applied — how the simulation
    /// sweeps them. Out-of-range values are clamped, not refused: `k` to
    /// `1..=MAX_CONTACTS`, since an answer carries at most that many.
    pub fn from_env() -> Self {
        let get = |name: &str| {
            std::env::var(format!("P2PCHAT_DHT_{name}"))
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
        };
        let d = Self::default();
        let k = get("K").map_or(d.k, |v| v as usize).clamp(1, MAX_CONTACTS);
        Self {
            k,
            alpha: get("ALPHA").map_or(d.alpha, |v| v as usize).max(1),
            replication: get("REPLICATION")
                .map_or(d.replication, |v| v as usize)
                .clamp(1, k),
            refresh: get("REFRESH_MS").map_or(d.refresh, Duration::from_millis),
            rpc_timeout: get("RPC_TIMEOUT_MS").map_or(d.rpc_timeout, Duration::from_millis),
        }
    }
}

// ---------------------------------------------------------------------------
// Distance
// ---------------------------------------------------------------------------

/// XOR distance, as a 256-bit big-endian number: comparing the arrays
/// compares the distances.
pub fn distance(a: &UserId, b: &UserId) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, (x, y)) in out.iter_mut().zip(a.as_bytes().iter().zip(b.as_bytes())) {
        *o = x ^ y;
    }
    out
}

/// The bucket `id` belongs in: how many leading bits it shares with `me`.
/// `None` for `me` itself.
pub fn bucket_of(me: &UserId, id: &UserId) -> Option<usize> {
    let d = distance(me, id);
    let mut zeros = 0;
    for byte in d {
        if byte != 0 {
            return Some(zeros + byte.leading_zeros() as usize);
        }
        zeros += 8;
    }
    None
}

/// A random ID in bucket `bucket`: `me`'s first `bucket` bits, the next one
/// flipped, the rest random — what a refresh looks up.
pub fn random_in(me: &UserId, bucket: usize) -> UserId {
    let mut out = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut out);
    let me = me.as_bytes();
    for bit in 0..=bucket.min(255) {
        let (byte, mask) = (bit / 8, 0x80u8 >> (bit % 8));
        let want = if bit < bucket { me[byte] } else { !me[byte] } & mask;
        out[byte] = (out[byte] & !mask) | want;
    }
    UserId::from_bytes(out)
}

// ---------------------------------------------------------------------------
// Routing table
// ---------------------------------------------------------------------------

struct Entry {
    contact: Contact,
    seen: Instant,
    /// An RPC to it failed. Checked at the next maintenance round.
    suspect: bool,
    /// A liveness check on it is in flight, so no round starts another.
    checking: bool,
}

struct Bucket {
    /// Least recently seen first.
    entries: Vec<Entry>,
    /// When a lookup last targeted an ID in this bucket.
    looked_up: Instant,
    /// A liveness check on the oldest entry is in flight, for a newcomer
    /// that found the bucket full. One at a time: further newcomers are
    /// dropped meanwhile, which is what bounds the checks a stream of new
    /// senders can cause.
    checking: bool,
}

/// What [`Table::seen`] did.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Known,
    Added,
    /// The bucket is full: check this, its oldest entry, and replace it with
    /// the newcomer only if it does not answer.
    Check(Contact),
    Dropped,
}

/// 256 k-buckets. A member's only routing state.
pub struct Table {
    me: UserId,
    k: usize,
    buckets: Vec<Bucket>,
}

impl Table {
    pub fn new(me: UserId, k: usize, now: Instant) -> Self {
        Self {
            me,
            k,
            buckets: (0..256)
                .map(|_| Bucket {
                    entries: Vec::new(),
                    looked_up: now,
                    checking: false,
                })
                .collect(),
        }
    }

    /// `contact` answered us, or asked us something as a member.
    ///
    /// A known ID is refreshed only at the address the table holds for it. A
    /// sender claiming that ID from elsewhere proves nothing about the entry,
    /// and taking its address would let anyone who names an ID redirect it.
    /// If the member really moved, its old entry fails its next check and is
    /// evicted, and the new address gets in then.
    fn seen(&mut self, contact: Contact, now: Instant) -> Seen {
        let Some(b) = bucket_of(&self.me, &contact.id) else {
            return Seen::Dropped;
        };
        let k = self.k;
        let bucket = &mut self.buckets[b];
        if let Some(at) = bucket
            .entries
            .iter()
            .position(|e| e.contact.id == contact.id)
        {
            if bucket.entries[at].contact.addr != contact.addr {
                return Seen::Dropped;
            }
            let mut entry = bucket.entries.remove(at);
            entry.seen = now;
            entry.suspect = false;
            entry.checking = false;
            bucket.entries.push(entry);
            return Seen::Known;
        }
        if bucket.entries.len() < k {
            bucket.entries.push(Entry {
                contact,
                seen: now,
                suspect: false,
                checking: false,
            });
            return Seen::Added;
        }
        if bucket.checking {
            return Seen::Dropped;
        }
        bucket.checking = true;
        Seen::Check(bucket.entries[0].contact)
    }

    /// The end of a check [`Table::seen`] asked for.
    fn checked(&mut self, oldest: Contact, alive: bool, newcomer: Contact, now: Instant) -> bool {
        let mut evicted = false;
        if alive {
            self.seen(oldest, now);
        } else {
            evicted = self.evict(&oldest.id);
        }
        if let Some(b) = bucket_of(&self.me, &newcomer.id) {
            self.buckets[b].checking = false;
        }
        if evicted {
            self.seen(newcomer, now);
        }
        evicted
    }

    fn failed(&mut self, id: &UserId) {
        if let Some(entry) = self.entry_mut(id) {
            entry.suspect = true;
        }
    }

    /// Removes `id`. The one place a contact leaves the table.
    fn evict(&mut self, id: &UserId) -> bool {
        let Some(b) = bucket_of(&self.me, id) else {
            return false;
        };
        let entries = &mut self.buckets[b].entries;
        let before = entries.len();
        entries.retain(|e| e.contact.id != *id);
        entries.len() < before
    }

    fn entry_mut(&mut self, id: &UserId) -> Option<&mut Entry> {
        let b = bucket_of(&self.me, id)?;
        self.buckets[b]
            .entries
            .iter_mut()
            .find(|e| e.contact.id == *id)
    }

    /// The `n` contacts closest to `target`, closest first.
    pub fn closest(&self, target: &UserId, n: usize) -> Vec<Contact> {
        let mut all = self.contacts();
        all.sort_by_key(|c| distance(target, &c.id));
        all.truncate(n);
        all
    }

    pub fn contacts(&self) -> Vec<Contact> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|e| e.contact))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn has_addr(&self, addr: SocketAddr) -> bool {
        self.buckets
            .iter()
            .any(|b| b.entries.iter().any(|e| e.contact.addr == addr))
    }

    fn looked_up(&mut self, target: &UserId, now: Instant) {
        if let Some(b) = bucket_of(&self.me, target) {
            self.buckets[b].looked_up = now;
        }
    }

    fn deepest(&self) -> Option<usize> {
        self.buckets.iter().rposition(|b| !b.entries.is_empty())
    }

    /// The buckets due a refresh, marked as looked up now, so that a refresh
    /// still in flight at the next round is not started twice.
    ///
    /// Every bucket up to one past the deepest holding anything. That one is
    /// empty, and a random ID in it is closer to us than any contact we hold,
    /// so refreshing it is a lookup of our own neighbourhood: how a member
    /// finds nodes closer than any it knows. Without it, a member whose join
    /// reached only far nodes (the 50-node self-test's isolated node, once
    /// released) never looks near itself again, and its neighbours never
    /// hear of it. An empty table refreshes bucket 0, which is how a member
    /// that has lost everyone it knew starts over.
    fn take_due_refresh(&mut self, now: Instant, every: Duration) -> Vec<usize> {
        let upto = self.deepest().map_or(0, |d| (d + 1).min(255));
        let due: Vec<usize> = (0..=upto)
            .filter(|&b| now.duration_since(self.buckets[b].looked_up) >= every)
            .collect();
        for &b in &due {
            self.buckets[b].looked_up = now;
        }
        due
    }

    /// Contacts due a liveness check, failed an RPC or unheard from for
    /// `every`, marked as being checked.
    fn take_due_checks(&mut self, now: Instant, every: Duration) -> Vec<Contact> {
        let mut due = Vec::new();
        for e in self.buckets.iter_mut().flat_map(|b| b.entries.iter_mut()) {
            if !e.checking && (e.suspect || now.duration_since(e.seen) >= every) {
                e.checking = true;
                due.push(e.contact);
            }
        }
        due
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// Records held for others: one per key, the highest `seq` that verified.
#[derive(Default)]
struct Records {
    held: BTreeMap<UserId, AddressRecord>,
}

impl Records {
    /// `true` if `record` is now held. It must pass M15 in full, against
    /// whatever is already held for its key, before anything else is looked
    /// at. When full, expired records make room; if none has, the newcomer
    /// is refused rather than something held being dropped for it.
    fn store(&mut self, record: AddressRecord, now: u64) -> bool {
        let key = record.body.user_id;
        if let Err(error) = record::supersedes(&record, self.held.get(&key), now) {
            tracing::debug!(%key, %error, "record refused");
            return false;
        }
        if !self.held.contains_key(&key) && self.held.len() >= MAX_RECORDS {
            self.held
                .retain(|_, held| record::verify(held, now).is_ok());
            if self.held.len() >= MAX_RECORDS {
                return false;
            }
        }
        self.held.insert(key, record);
        true
    }

    /// The record for `key`, verified again: it may have expired since it
    /// was stored, and then it is dropped rather than served.
    fn get(&mut self, key: &UserId, now: u64) -> Option<AddressRecord> {
        if record::verify(self.held.get(key)?, now).is_err() {
            self.held.remove(key);
            return None;
        }
        self.held.get(key).cloned()
    }
}

// ---------------------------------------------------------------------------
// The node
// ---------------------------------------------------------------------------

/// Why a lookup stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Every one of the `k` closest contacts it knows answered or failed:
    /// nothing closer is left to ask. The only way a lookup for an absent
    /// key should end.
    Exhausted,
    /// A record for the key that verified.
    Value,
    /// [`MAX_LOOKUP_RPCS`] spent with closer contacts still unasked.
    Budget,
}

/// What a lookup found.
#[derive(Debug)]
pub struct Found {
    pub value: Option<AddressRecord>,
    /// The `k` closest contacts that answered, closest first.
    pub closest: Vec<Contact>,
    pub rpcs: usize,
    pub stop: Stop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Waiting,
    Asking,
    Answered,
    Failed,
}

pub struct Dht {
    me: UserId,
    /// Our public node's port, when we are a member. `None` is a client.
    /// Changes when M14's test does — M17, [`Dht::set_member`].
    member: Mutex<Option<u16>>,
    /// Where RPCs leave from: the private endpoint, M13a.
    endpoint: Endpoint,
    params: Params,
    bootstrap: Vec<SocketAddr>,
    table: Mutex<Table>,
    records: Mutex<Records>,
    lookups: Semaphore,
}

impl Dht {
    /// `member` is our public node's port if we serve, `None` for a client.
    pub fn new(
        me: UserId,
        member: Option<u16>,
        endpoint: Endpoint,
        bootstrap: Vec<SocketAddr>,
        params: Params,
    ) -> Arc<Self> {
        Arc::new(Self {
            me,
            member: Mutex::new(member),
            endpoint,
            params,
            bootstrap,
            table: Mutex::new(Table::new(me, params.k, Instant::now())),
            records: Mutex::new(Records::default()),
            lookups: Semaphore::new(MAX_LOOKUPS),
        })
    }

    pub fn params(&self) -> Params {
        self.params
    }

    /// Our public node's port while we are a member, `None` while a client.
    pub fn member(&self) -> Option<u16> {
        *self.member.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Becomes a member serving on `port`, or a client — M17, when M14's
    /// test changes its answer. A client holds nothing, so becoming one
    /// empties the table. Becoming a member does not join: the caller runs
    /// [`Dht::join`], which is a lookup and takes as long as one.
    pub fn set_member(&self, port: Option<u16>) {
        let mut member = self.member.lock().unwrap_or_else(|p| p.into_inner());
        if port.is_none() && member.is_some() {
            *self.table() = Table::new(self.me, self.params.k, Instant::now());
        }
        *member = port;
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        // Poisoned means a panic mid-update; the buckets are still buckets.
        self.table.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn records(&self) -> MutexGuard<'_, Records> {
        self.records.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The routing table, as it stands. Empty for a client, always.
    pub fn contacts(&self) -> Vec<Contact> {
        self.table().contacts()
    }

    /// Held records, as key and `seq`.
    pub fn held(&self) -> Vec<(UserId, u64)> {
        self.records()
            .held
            .iter()
            .map(|(k, r)| (*k, r.body.seq))
            .collect()
    }

    // --- serving ------------------------------------------------------------

    /// A request, as the public node received it from `from`. `None` — which
    /// the public node turns into silence — unless we are a member.
    pub(crate) fn answer(
        self: &Arc<Self>,
        request: DhtRequest,
        from: SocketAddr,
    ) -> Option<DhtResponse> {
        self.member()?;
        if request.version != PROTOCOL_VERSION {
            return None;
        }
        if let Some(sender) = request.from {
            // The IP the connection came from, the port the sender names.
            self.saw(Contact {
                id: sender.id,
                addr: SocketAddr::new(from.ip(), sender.port),
            });
        }
        let now = invite::now();
        let kind = match &request.query {
            DhtQuery::Ping => "ping",
            DhtQuery::FindNode(_) => "find_node",
            DhtQuery::FindValue(_) => "find_value",
            DhtQuery::Store(_) => "store",
        };
        tracing::debug!(source = %from.ip(), kind, "dht request");
        let answer = match request.query {
            DhtQuery::Ping => DhtAnswer::Pong,
            DhtQuery::FindNode(target) => {
                DhtAnswer::Nodes(self.table().closest(&target, self.params.k))
            }
            DhtQuery::FindValue(key) => {
                let held = self.records().get(&key, now);
                match held {
                    Some(record) => DhtAnswer::Value(Box::new(record)),
                    None => DhtAnswer::Nodes(self.table().closest(&key, self.params.k)),
                }
            }
            DhtQuery::Store(record) => DhtAnswer::Stored(self.records().store(*record, now)),
        };
        Some(DhtResponse {
            id: self.me,
            answer,
        })
    }

    /// A member answered us or asked us something. Clients keep nothing.
    fn saw(self: &Arc<Self>, contact: Contact) {
        if self.member().is_none() || contact.id == self.me {
            return;
        }
        let seen = self.table().seen(contact, Instant::now());
        if let Seen::Check(oldest) = seen {
            let dht = Arc::clone(self);
            tokio::spawn(async move {
                let alive = dht.ping(oldest).await;
                if dht.table().checked(oldest, alive, contact, Instant::now()) {
                    tracing::info!(peer = %oldest.id, reason = "bucket full, oldest did not answer", "contact evicted");
                }
            });
        }
    }

    // --- asking -------------------------------------------------------------

    /// One RPC to `addr`. Public for the debug driver, which asks single
    /// nodes directly to see what they serve.
    pub async fn ask(&self, addr: SocketAddr, query: DhtQuery) -> Result<DhtResponse, NetError> {
        let request = PublicRequest::Dht(DhtRequest {
            version: PROTOCOL_VERSION,
            from: self.member().map(|port| Member { id: self.me, port }),
            query,
        });
        let started = Instant::now();
        let answer = public::request(&self.endpoint, addr, &request, self.params.rpc_timeout).await;
        match answer {
            Ok(PublicResponse::Dht(response)) => Ok(response),
            Ok(_) => Err(NetError::WrongAnswer),
            Err(error) => {
                tracing::debug!(%addr, %error, elapsed_ms = started.elapsed().as_millis() as u64, "rpc failed");
                Err(error)
            }
        }
    }

    /// The liveness check: a `Ping` answered by the ID we hold for it.
    async fn ping(&self, contact: Contact) -> bool {
        matches!(self.ask(contact.addr, DhtQuery::Ping).await, Ok(r) if r.id == contact.id)
    }

    /// The iterative lookup: `alpha` RPCs in flight, each answer's contacts
    /// merged into a shortlist ordered by distance to `target`, until every
    /// one of the `k` closest in it has answered or failed. With
    /// `want_value`, it stops at the first record that verifies and is for
    /// `target`.
    ///
    /// Terminates without the budget: each contact is asked at most once
    /// (`asked`), and a lookup ends when nothing among the `k` closest is
    /// left to ask. The budget is for answers that go on inventing closer
    /// contacts, and hitting it is reported as [`Stop::Budget`].
    pub async fn lookup(self: &Arc<Self>, target: UserId, want_value: bool) -> Found {
        self.lookup_seeded(target, want_value, false, None).await
    }

    /// A value lookup that takes only a record newer than `seq` — M17. A
    /// lookup stops at the first record that verifies, and a replica the
    /// owner's last publish did not reach still holds an older one, so a
    /// caller whose record went stale asks again past it.
    pub async fn lookup_newer(self: &Arc<Self>, target: UserId, seq: u64) -> Found {
        self.lookup_seeded(target, true, false, Some(seq)).await
    }

    async fn lookup_seeded(
        self: &Arc<Self>,
        target: UserId,
        want_value: bool,
        bootstrap: bool,
        newer_than: Option<u64>,
    ) -> Found {
        let _permit = self.lookups.acquire().await.ok();
        let k = self.params.k;
        let alpha = self.params.alpha.max(1);

        let mut shortlist: BTreeMap<[u8; 32], (Contact, State)> = BTreeMap::new();
        let mut unnamed: Vec<SocketAddr> = Vec::new();
        let mut asked: BTreeSet<UserId> = BTreeSet::new();
        if self.member().is_some() {
            let mut table = self.table();
            table.looked_up(&target, Instant::now());
            for c in table.closest(&target, k) {
                shortlist.insert(distance(&target, &c.id), (c, State::Waiting));
            }
        }
        // A client has nothing else. A member uses the bootstrap list when
        // its table has nothing, and when told to, which is how a member cut
        // off from everyone it knew finds its way back.
        if shortlist.is_empty() || bootstrap {
            unnamed = self.bootstrap.clone();
        }

        let query = if want_value {
            DhtQuery::FindValue(target)
        } else {
            DhtQuery::FindNode(target)
        };
        let mut asking = JoinSet::new();
        let mut rpcs = 0;
        let mut value = None;
        loop {
            while asking.len() < alpha && rpcs < MAX_LOOKUP_RPCS {
                let (who, addr) = if let Some(addr) = unnamed.pop() {
                    (None, addr)
                } else if let Some((c, s)) = shortlist
                    .values_mut()
                    .filter(|(_, s)| *s != State::Failed)
                    .take(k)
                    .find(|(_, s)| *s == State::Waiting)
                {
                    *s = State::Asking;
                    asked.insert(c.id);
                    (Some(*c), c.addr)
                } else {
                    break;
                };
                rpcs += 1;
                let dht = Arc::clone(self);
                let query = query.clone();
                asking.spawn(async move { (who, addr, dht.ask(addr, query).await) });
            }

            let Some(done) = asking.join_next().await else {
                break;
            };
            let Ok((who, addr, result)) = done else {
                continue;
            };
            let key = |id: &UserId| distance(&target, id);
            match result {
                Ok(r) if r.id != self.me && who.is_none_or(|c| c.id == r.id) => {
                    let responder = Contact { id: r.id, addr };
                    asked.insert(r.id);
                    shortlist.insert(key(&r.id), (responder, State::Answered));
                    self.saw(responder);
                    match r.answer {
                        DhtAnswer::Nodes(contacts) => {
                            for c in contacts {
                                if c.id != self.me && !asked.contains(&c.id) {
                                    shortlist.entry(key(&c.id)).or_insert((c, State::Waiting));
                                }
                            }
                            while shortlist.len() > SHORTLIST {
                                match shortlist
                                    .iter()
                                    .rev()
                                    .find(|(_, (_, s))| *s != State::Asking)
                                {
                                    Some((far, _)) => {
                                        let far = *far;
                                        shortlist.remove(&far);
                                    }
                                    None => break,
                                }
                            }
                        }
                        DhtAnswer::Value(record)
                            if want_value
                                && record.body.user_id == target
                                && newer_than.is_none_or(|seq| record.body.seq > seq)
                                && record::verify(&record, invite::now()).is_ok() =>
                        {
                            value = Some(*record);
                            break;
                        }
                        // A value for another key, or one that fails M15, or
                        // one no newer than the caller already has, or an
                        // answer to a question we did not ask: this node told
                        // us nothing we can use.
                        _ => {}
                    }
                }
                // No answer, or an answer from someone other than the contact
                // we dialled: that contact is not there.
                _ => {
                    if let Some(c) = who {
                        if let Some(entry) = shortlist.get_mut(&key(&c.id)) {
                            entry.1 = State::Failed;
                        }
                        if self.member().is_some() {
                            self.table().failed(&c.id);
                        }
                    }
                }
            }
        }
        asking.abort_all();

        let stop = if value.is_some() {
            Stop::Value
        } else if shortlist
            .values()
            .filter(|(_, s)| *s != State::Failed)
            .take(k)
            .any(|(_, s)| *s == State::Waiting)
        {
            Stop::Budget
        } else {
            Stop::Exhausted
        };
        let closest = shortlist
            .values()
            .filter(|(_, s)| *s == State::Answered)
            .take(k)
            .map(|(c, _)| *c)
            .collect();
        Found {
            value,
            closest,
            rpcs,
            stop,
        }
    }

    /// Stores `record` on the `replication` closest members to its key, and
    /// returns those that took it.
    pub async fn publish(self: &Arc<Self>, record: AddressRecord) -> Vec<Contact> {
        let found = self.lookup(record.body.user_id, false).await;
        let to = &found.closest[..found.closest.len().min(self.params.replication)];
        self.store_at(&record, to).await
    }

    /// Sends `record` to each of `to` as it is, checking nothing: the checks
    /// are the storing node's to make. Returns those that said they took it.
    pub async fn store_at(
        self: &Arc<Self>,
        record: &AddressRecord,
        to: &[Contact],
    ) -> Vec<Contact> {
        let mut sends = JoinSet::new();
        for &c in to {
            let dht = Arc::clone(self);
            let query = DhtQuery::Store(Box::new(record.clone()));
            sends.spawn(async move { (c, dht.ask(c.addr, query).await) });
        }
        let mut took = Vec::new();
        while let Some(done) = sends.join_next().await {
            if let Ok((
                c,
                Ok(DhtResponse {
                    answer: DhtAnswer::Stored(true),
                    ..
                }),
            )) = done
            {
                took.push(c);
            }
        }
        took
    }

    // --- joining and maintenance -----------------------------------------

    /// A member's first lookups: itself, through the bootstrap list, and
    /// then a refresh of every bucket up to the deepest that filled. Returns
    /// the table's size afterwards.
    pub async fn join(self: &Arc<Self>) -> usize {
        self.lookup_seeded(self.me, false, true, None).await;
        let buckets = self.table().deepest().map_or(0, |d| (d + 2).min(256));
        for refresh in self.refresh((0..buckets).collect(), false) {
            let _ = refresh.await;
        }
        self.table().len()
    }

    fn refresh(
        self: &Arc<Self>,
        buckets: Vec<usize>,
        bootstrap: bool,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        buckets
            .into_iter()
            .map(|b| {
                let dht = Arc::clone(self);
                tracing::debug!(bucket = b, "bucket refreshed");
                tokio::spawn(async move {
                    dht.lookup_seeded(random_in(&dht.me, b), false, bootstrap, None)
                        .await;
                })
            })
            .collect()
    }

    /// Runs for as long as the node does, a round every quarter of
    /// `refresh`: refreshes the buckets nobody has looked up in for
    /// `refresh`, and pings every contact that failed an RPC or has not been
    /// heard from for `refresh`, evicting those that do not answer.
    ///
    /// A round starts its work and does not wait for it. A dead contact's
    /// ping takes the whole RPC timeout, and waiting on it would push every
    /// refresh behind it back by that much. The marks `take_due_refresh` and
    /// `take_due_checks` leave are what stop a later round repeating work
    /// still in flight.
    ///
    /// A member whose table holds none of the bootstrap members seeds its
    /// refreshes from the bootstrap list too. Without that, a side of a
    /// partition that lost every contact on the other side, bootstrap
    /// members included, would never look for them again.
    ///
    /// Idle while a client: a node's role can change while it runs (M17).
    pub async fn maintain(self: Arc<Self>) {
        let every = self.params.refresh;
        let mut rounds = tokio::time::interval((every / 4).max(Duration::from_millis(250)));
        rounds.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        rounds.tick().await;
        let checks = Arc::new(Semaphore::new(CHECKS));
        loop {
            rounds.tick().await;
            if self.member().is_none() {
                continue;
            }
            let now = Instant::now();
            let (due, check, lost) = {
                let mut table = self.table();
                (
                    table.take_due_refresh(now, every),
                    table.take_due_checks(now, every),
                    !self.bootstrap.iter().any(|a| table.has_addr(*a)),
                )
            };
            for c in check {
                let (dht, checks) = (Arc::clone(&self), Arc::clone(&checks));
                tokio::spawn(async move {
                    let _permit = checks.acquire().await.ok();
                    if dht.ping(c).await {
                        dht.table().seen(c, Instant::now());
                    } else if dht.table().evict(&c.id) {
                        tracing::info!(peer = %c.id, reason = "liveness check failed", "contact evicted");
                    }
                });
            }
            self.refresh(due, lost);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pchat_crypto::Identity;

    fn id(first: u8) -> UserId {
        let mut b = [0u8; 32];
        b[0] = first;
        UserId::from_bytes(b)
    }

    fn contact(first: u8) -> Contact {
        Contact {
            id: id(first),
            addr: SocketAddr::from(([203, 0, 113, first], 47100)),
        }
    }

    #[test]
    fn distance_is_xor_and_buckets_count_shared_bits() {
        let me = id(0b1000_0000);
        assert_eq!(distance(&me, &me), [0u8; 32]);
        assert_eq!(bucket_of(&me, &me), None);
        assert_eq!(bucket_of(&me, &id(0b0000_0000)), Some(0));
        assert_eq!(bucket_of(&me, &id(0b1100_0000)), Some(1));
        assert_eq!(bucket_of(&me, &id(0b1000_0001)), Some(7));
        // XOR, not difference: 0x80 and 0x7f are 1 apart as numbers and as
        // far apart as can be as IDs.
        assert_eq!(distance(&id(0x80), &id(0x7f))[0], 0xff);
    }

    #[test]
    fn a_random_id_lands_in_the_bucket_asked_for() {
        let me = Identity::generate().user_id();
        for b in [0, 1, 7, 8, 100, 255] {
            for _ in 0..20 {
                assert_eq!(bucket_of(&me, &random_in(&me, b)), Some(b));
            }
        }
    }

    /// Gate 5 at the table: k per bucket, a full bucket asks for a check on
    /// its oldest, and only a failed check lets the newcomer in.
    #[test]
    fn a_full_bucket_checks_its_oldest_and_evicts_only_the_dead() {
        let now = Instant::now();
        let mut t = Table::new(id(0), 2, now);
        // 0x80.. all share no bits with 0x00..: bucket 0.
        assert_eq!(t.seen(contact(0x80), now), Seen::Added);
        assert_eq!(t.seen(contact(0x81), now), Seen::Added);
        assert_eq!(t.seen(contact(0x82), now), Seen::Check(contact(0x80)));
        // One check at a time per bucket: another newcomer is dropped.
        assert_eq!(t.seen(contact(0x83), now), Seen::Dropped);
        assert_eq!(t.len(), 2);

        // Alive: the newcomer stays out, and the oldest becomes the newest.
        assert!(!t.checked(contact(0x80), true, contact(0x82), now));
        assert_eq!(t.seen(contact(0x82), now), Seen::Check(contact(0x81)));
        // Dead: evicted, and the newcomer takes its place.
        assert!(t.checked(contact(0x81), false, contact(0x82), now));
        let ids: Vec<_> = t.contacts().iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![id(0x80), id(0x82)]);
    }

    #[test]
    fn a_known_id_from_another_address_is_not_taken() {
        let now = Instant::now();
        let mut t = Table::new(id(0), 4, now);
        t.seen(contact(0x80), now);
        let impostor = Contact {
            addr: SocketAddr::from(([198, 51, 100, 1], 47100)),
            ..contact(0x80)
        };
        assert_eq!(t.seen(impostor, now), Seen::Dropped);
        assert_eq!(t.contacts(), vec![contact(0x80)]);
    }

    #[test]
    fn stale_and_suspect_contacts_come_up_for_checking() {
        let now = Instant::now();
        let every = Duration::from_secs(60);
        let mut t = Table::new(id(0), 4, now);
        t.seen(contact(0x80), now);
        t.seen(contact(0x40), now);
        assert!(t.take_due_checks(now, every).is_empty());
        t.failed(&id(0x40));
        assert_eq!(t.take_due_checks(now, every), vec![contact(0x40)]);
        // In flight: not handed out again until it answers.
        assert_eq!(t.take_due_checks(now + every, every), vec![contact(0x80)]);
        t.seen(contact(0x40), now + every);
        assert_eq!(t.take_due_checks(now + every * 2, every).len(), 1);
        assert!(t.evict(&id(0x40)));
        assert!(!t.evict(&id(0x40)));
    }

    #[test]
    fn refresh_covers_every_bucket_to_one_past_the_deepest_filled() {
        let now = Instant::now();
        let every = Duration::from_secs(60);
        let mut t = Table::new(id(0), 4, now);
        // Empty: bucket 0 still, which is how a node that lost everyone
        // starts again.
        assert_eq!(t.take_due_refresh(now + every, every), vec![0]);
        t.seen(contact(0x10), now); // bucket 3
        t.looked_up(&id(0x20), now + every); // bucket 2
                                             // Down to one past the deepest filled: bucket 4, nobody there yet.
        assert_eq!(t.take_due_refresh(now + every, every), vec![1, 3, 4]);
        // Taken: not due again until another `every` has passed.
        assert!(t.take_due_refresh(now + every, every).is_empty());
        assert_eq!(
            t.take_due_refresh(now + every * 2, every),
            vec![0, 1, 2, 3, 4]
        );
    }

    /// Every collection bounded: a stream of distinct senders, all into
    /// one bucket, never grows it past k.
    #[test]
    fn the_table_is_bounded_whatever_arrives() {
        let now = Instant::now();
        let mut t = Table::new(id(0), 3, now);
        for n in 0..=255u8 {
            let _ = t.seen(contact(n | 0x80), now);
        }
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn closest_is_by_xor() {
        let now = Instant::now();
        let mut t = Table::new(id(0xff), 8, now);
        for n in [0x01, 0x70, 0x80, 0x81, 0xc0] {
            t.seen(contact(n), now);
        }
        let got: Vec<u8> = t
            .closest(&id(0x80), 3)
            .iter()
            .map(|c| c.id.as_bytes()[0])
            .collect();
        assert_eq!(got, vec![0x80, 0x81, 0xc0]);
    }

    /// Gate 7 at the store: nothing that fails M15 is held, a rollback is
    /// refused, and a record that expires while held is not served.
    #[test]
    fn records_are_verified_on_the_way_in_and_on_the_way_out() {
        let owner = Identity::generate();
        let addr = || vec![SocketAddr::from(([203, 0, 113, 7], 47101))];
        let now = 1_700_000_000;
        let mut r = Records::default();

        let good = record::create(&owner, addr(), 5, now).unwrap();
        let mut tampered = record::create(&owner, addr(), 9, now).unwrap();
        tampered.body.addrs[0] = SocketAddr::from(([198, 51, 100, 66], 47101));
        let rolled = record::create(&owner, addr(), 4, now).unwrap();

        assert!(!r.store(tampered, now));
        assert!(r.held.is_empty());
        assert!(r.store(good.clone(), now));
        assert!(!r.store(rolled, now));
        assert_eq!(r.get(&owner.user_id(), now), Some(good));

        let later = now + record::LIFETIME + invite::SKEW + 1;
        assert_eq!(r.get(&owner.user_id(), later), None);
        assert!(r.held.is_empty());
    }
}
