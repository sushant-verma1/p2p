# plan-v0.2.md — DHT discovery and NAT traversal

**Status:** Planned. Do not start until V0.1 closes with M12.

---

## 1. Goal

Two people behind carrier NAT can find each other by user ID and chat directly, with no address configuration and no server either of them runs. Discovery moves from a hand-carried invite blob to a Kademlia DHT. Connectivity moves from "the invite owner must be publicly reachable" to coordinated hole punching.

## 2. Decisions locked in

| Decision | Value |
|---|---|
| Discovery | Kademlia DHT — any reachable node can serve, routing heals under churn |
| Symmetric NAT | No relay. Fail with a clear message |
| Offline delivery | Still out of scope. Both peers must be online |
| Address records | Self-certifying, signed by the Ed25519 identity key |
| Transport, crypto, storage | Unchanged from V0.1 |

## 3. The constraints these choices impose

Recorded up front because each one shapes several milestones.

**Only reachable nodes can be DHT members.** A node behind CGNAT cannot answer inbound queries, so it cannot hold routing state or serve records. It participates as a *client* — issuing lookups, publishing its own record — while members do the serving. Every real DHT works this way; libp2p calls it client mode versus server mode. So the network heals across the reachable minority, and the size of that minority is the network's actual capacity.

**Bootstrapping does not self-heal.** Joining a DHT requires already knowing one reachable member. That list ships in config. Self-healing covers churn *after* joining, not the cold start. If every bootstrap node in the list is down, a new node cannot join at all.

**No relay means some pairs cannot connect.** Symmetric NAT assigns a different external port per destination, so the address learned from a third party is useless to a fourth. Two symmetric peers, or one symmetric and one that cannot punch, have no path. V0.2 must detect this and say so, not retry forever.

**Punch coordination needs a mutually reachable third party.** Both peers must send at nearly the same moment, so one has to be told when. That signalling goes through a reachable DHT member. It carries control messages only, never conversation.

**The DHT publishes presence.** Anyone who knows a user ID can query their current address and learn they are online. This is a deliberate regression from V0.1, where only invite holders knew.

## 4. Open decisions

- **OD-4 — Does the DHT replace invites or supplement them?** If records are looked up by user ID, an invite needs only the identity key, and it stops going stale when an address changes. But a DHT lookup is public where handing over an invite is not.
- **OD-5 — Is DHT participation opt-in?** A user on metered mobile data may not want to serve queries. Opt-in shrinks the member set; opt-out surprises people.
- **OD-6 — Record TTL and republish interval.** Short TTL tracks mobile IP changes; long TTL cuts traffic. Needs measurement, like the V0.1 timeouts.
- **OD-7 — Kademlia parameters:** bucket size *k*, replication factor, lookup parallelism α. **Resolved at M16, by measurement:** k = 20 (the default, reproduced), α = 5 (not the default 3), r = 8. The data is under M16.

---

## 5. Milestones

### M13 — STUN address discovery and NAT classification

Learn the node's own external address from public STUN servers. Classify the NAT: full cone, restricted, port-restricted, or symmetric.

No infrastructure of your own. This milestone alone tells you whether M18 can ever work on a given connection.

**Gate:** reflexive address reported correctly behind a NAT; classification agrees with an independent tool on at least three networks; a node with no NAT reports so; the classification never claims punchable when it is symmetric.

### M13a — Shared socket ownership

A NAT's mapping is per socket. STUN on a throwaway socket learns nothing about quinn's; punching needs the punch packets and the QUIC traffic after them to leave from the same socket. So the node binds its sockets and hands them to quinn, STUN runs on the same socket (demultiplexed on the magic cookie), outbound dials use it too, and `p2pchat nat` reports that socket's mapping. Recorded in `architecture.md` §3 so it is not undone.

**Gate:** a full handshake completes while STUN is in flight on the same port; a QUIC packet never reaches the STUN parser and a STUN response never reaches quinn; the reflexive port matches the QUIC socket's and is stable across queries; outbound dials originate from the owned socket; V0.1 passes unchanged. Mutations: demux to quinn only fails the second; demux to STUN only fails the first; dials from a fresh socket fail the fourth.

### M14 — Reachability self-test

A node must know whether it can serve. Ask a bootstrap member to dial back on the advertised address; if the dial arrives, the node is reachable and joins as a member, otherwise as a client.

Re-test on network change, since a laptop moving from broadband to tethering changes category.

**Gate:** a node behind CGNAT classifies itself as a client; a reachable node classifies itself as a member; classification updates within a bounded time after the network changes; a node that falsely claims reachability is detected by the dial-back failing; the dial-back cannot be pointed at a third party's address.

As built: `DIAL_BACK` is a fourth public request, and it carries a nonce and no address. The member dials the address the connection came from, from a socket of its own, so the dial-back arrives from an address the requester never sent to. Only that dial-back counts, and only if it arrives carrying the nonce. Everything else is inconclusive, and inconclusive means client. The node re-tests when the local address its route to the first member uses changes (checked every 10 s), and every 30 minutes regardless. The last result is kept in `reachability` in the data directory. It stands at startup only for the same network, and only until the first test of the run. Ceiling: the dial-back comes from the member's IP on another port, so an address-restricted NAT, which filters on IP alone, still passes. A second member dialling closes that at M16.

### M13b — Follow-ups to M13a

`p2pchat nat` names a container's NAT when it reports symmetric. It detects Docker, Podman and `container=` itself, and otherwise says that a container or VM NAT is the likely cause. The running `Node` keeps the STUN channel from `node_endpoint`, so nothing later binds a second socket to get one.

### M14a — Reachability follow-ups

**Dial-back timeout, measured** with `netem/tail.py --dialbacks`, 200 samples a profile. The member's `dial_back` was timed from its own log, with the limit raised to 60 s so the tail is not cut off. Every dial-back arrived in both runs.

| profile | round trip, loss (ping) | p50 | p90 | p99 | max | over 10 s |
|---|---|---|---|---|---|---|
| `poor` | ~300 ms, 5.85% | 0.85 s | 1.89 s | 3.11 s | 4.45 s | 0 |
| `bad` | 800 ms, 15.9% | 1.60 s | 5.61 s | 9.04 s | 13.41 s | 2 (11.55, 13.41) |

The instrument was checked against the opposite case first: with the requester dropping inbound UDP that did not come from the member's public port, both samples read `reached=false` at 10.00 s. The `bad` times cluster at loss-recovery doublings (1.60, 2.50, 4.00, 7.26 s), as M12b's requests did. So 10 s does not hold on `bad`, where it wrongly makes 1% of reachable nodes clients. The value is unchanged pending a decision.

**Two-member rule: proposed, then withdrawn.** M14a first proposed closing the same-IP gap by requiring dial-backs from two independent members. That was wrong, and the reasoning is kept here so that it is not proposed again. The node sends its request to every member it asks, so an IP-only-filtering NAT has each asked member's IP open, and each member's dial-back from another port on that IP gets in. Two asked members therefore both pass. An emulated IP-only NAT confirmed it: both dial-backs arrived and nothing was dropped, while a dial-back from an IP the node never contacted was dropped. **What matters is the source IP of the dial-back, not how many arrive.** It has to be an IP the node never sent to. M14b builds that by having the asked member forward the request.

### M14b — Forwarded dial-back

The asked member A never dials the requester. It forwards `{ nonce, target = the address A observed }` to another member, B, which the requester never contacted, and B dials from a fresh socket. With fewer than two members reachable the answer is "not forwarded", and the node is a client with the reason logged. There is no fallback to a single-member dial-back. B takes forwards only from its members, rate-limited per target IP (2 a minute) and per forwarding member (30 a minute). The reflector reasoning is in `architecture.md` §3, and the exposure is in `THREAT_MODEL.md` §12.

**Gate:** a node behind an IP-only-filtering NAT is a client; a reachable node is a member via the forwarded dial-back; with fewer than two members reachable, client; B dials only what A observed; the rate limits hold; a forwarding member cannot be aimed at a third party.

**Timeouts, measured on the forwarded path.** `netem/tail.py --dialbacks` ran with three containers (requester, A, B) and 200 samples a profile, using a binary with every limit raised. Every dial-back was forwarded and arrived, 400 of 400. Each timing is taken where it happens: B's dial from B's log, A's whole forward from A's, and the whole request at the requester. The instrument was first checked against the opposite case: with the requester dropping everything from B, both samples read `forwarded=true reached=false` at 10.0 s.

| profile | ping round trip / loss | B's dial p99 / max | A's forward p99 / max | request p99 / max |
|---|---|---|---|---|
| `poor` | ~300 ms / 6.55% | 2.47 / 3.09 s | 4.09 / 5.45 s | 5.79 / 7.13 s |
| `bad` | 800 ms / 14.65% | 10.42 / 11.54 s | 14.72 / 17.68 s | 16.85 / 22.61 s |

- **`dial_back_timeout` = 12 s.** On `bad`, none of M14b's 200 dials exceeded it. With M14a's 200 direct dials added, 1 in 400 did (13.41 s). The tail rests on very few samples: that one miss, plus M14b's four dials between 10 and 12 s. It is an estimate, not a bound.
- **`forward_timeout` = 16 s** (the dial plus 4 s to reach B and hear back). It misses 1 of 200 on `bad` (17.68 s).
- **`request_timeout` stays 20 s.** It misses 1 of 200 on `bad` (22.61 s; the next slowest was 18.72 s). Covering all 200 would take about 25 s, set at both the requester and A's per-connection deadline, with `forward_timeout` raised to about 20 s to match. **Decided (2026-09-28): 20 s stays.** The 22.61 s sample is recorded here as the known miss: one in 200 on `bad`, which 20 s does not cover. A miss is a reachable node classed as a client, the safe error, and it is re-tested at the next network change or within 30 minutes. Raising it would split M12c's single 20 s give-up into two values, and a dead bootstrap member would cost 25 s instead of 20 s before the next is tried.

### M15 — Signed address records

The value stored in the DHT:

```
AddressRecord {
    user_id, identity_pk,
    addrs: Vec<SocketAddr>,
    seq: u64,
    published_at, expires_at,
    sig,
}
```

Self-certifying: any node can verify `BLAKE3(identity_pk) == user_id` and check the signature, so storage nodes are never trusted. Same argument that already governs the public node in `architecture.md` §3.

`seq` prevents rollback — a node that has seen a higher sequence rejects a lower one, so an attacker cannot replay a stale record to redirect traffic.

**Gate:** a forged record is rejected; a record whose user ID does not bind to its key is rejected; an expired record is rejected with a distinct error; a rolled-back `seq` is rejected; a tampered address field fails the signature; expiry is checked after the signature.

As built: `p2pchat_crypto::record` — `create`, `open`, `verify`, `supersedes`; the order and the signing domain are in `architecture.md` §3. The same `seq` is accepted only as the identical record. **OD-6:** records live for 180 s and republish at 90 s. The 600 s budget is §10's chosen reconnect budget, not a measured timeout; the strict expiry plus signature/wire budgets fit within it with 344 s remaining. Clock skew applies only to a `published_at` too far in the future (300 s); expiry is strict, so it cannot extend a record's lifetime.

### M16 — Kademlia core

Routing table with k-buckets, XOR distance, `FIND_NODE`, `STORE`, `FIND_VALUE`, iterative lookup with parallelism α, bucket refresh, node eviction with liveness checks.

Members only. Clients issue lookups without holding routing state.

Build the simulation harness alongside it — this cannot be tested with two nodes. Extend the existing `netem/` harness to spawn N nodes in containers with configurable churn.

**Gate:** lookups succeed in a 50-node simulated network; the routing table converges after bootstrap; a lookup for an absent key terminates rather than looping; buckets refresh on schedule; dead nodes are evicted.

As built: `p2pchat_net::dht`, served through the public node as a sixth request type (`architecture.md` §3, "DHT"). `p2pchat dht` is the simulation's driver. The harness is `netem/dht.py`, with 50 members in network namespaces inside one privileged container, and `netem/mutants.py` builds the mutants. `crates/p2pchat-net/tests/dht.rs` runs the gates that need no log or netem profile, with 16 members on loopback, in CI. That test fails under each of the four edit mutants.

**The harness was checked before any DHT gate was run.** Its first 50-node self-test failed its own positive controls: live nodes were evicted and RPCs timed out, with the processes idle. The cause was the bridged topology overflowing the kernel's neighbour table, which is shared across namespaces (`netem/README.md`, "Why routed"). The fix was a routed star plus a full-mesh ping preflight before every run. Over the old bridge, the preflight reports 519 unreachable pairs. The second 50-node self-test caught a real DHT bug: refresh stopped at the deepest filled bucket, so a node whose join reached only far nodes never looked near itself again, and its neighbours never learned of it. Refresh now goes one bucket past the deepest filled.

**OD-7, resolved.** Measured with `dht.py trial`: 50 members, converge, publish, kill 15 at once (30%), then every survivor looks up straight away, while the dead are still in every table. The first lookup of each survivor starts at the kill. Those lookups are what configurations are compared on, because later ones run in a network the liveness checks have already cleaned. The first sweep compared α across exactly that confound. Two runs a configuration, baseline netem unless marked. "Records" counts lookups over the whole run. "Find at kill" is FIND_NODE started at the kill.

| config | table | records found | owner dead, found | find at kill p50 / max | record at kill p90 / max |
|---|---|---|---|---|---|
| k=4 α=3 r=4 | 17.7 | 545/560 | 158/162 | 20 / 60 s | 10 / 40 s |
| k=8 α=3 r=4 | 27.9 | 559/560 | 177/178 | 30 / 80 s | 0.03 / 20 s |
| k=12 α=3 r=4 | 34.9 | 560/560 | 169/169 | 50 / 80 s | 0.02 / 20 s |
| k=20 α=3 r=4 | 44.4 | 560/560 | 168/168 | 60 / 60 s | 0.01 / 20 s |
| k=20 α=1 r=4 | 44.3 | 557/560 | 151/151 | 160 / 160 s | 40 / 60 s |
| k=20 α=2 r=4 | 44.1 | 551/560 | 180/180 | 70 / 100 s | 10 / 100 s |
| k=20 α=5 r=4 | 44.1 | 560/560 | 170/170 | 40 / 60 s | 0.02 / 0.03 s |
| k=20 α=3 r=1 | 44.1 | 359/560 | 121/166 | 60 / 60 s | 50 / 60 s |
| k=20 α=3 r=2 | 44.2 | 472/560 | 141/173 | 60 / 80 s | 70 / 80 s |
| k=20 α=3 r=3 | 44.3 | 546/560 | 171/173 | 60 / 60 s | 0.01 / 60 s |
| k=20 α=3 r=5 | 44.6 | 558/560 | 184/184 | 50 / 80 s | 0.01 / 20 s |
| k=20 α=3 r=8 | 44.5 | 560/560 | 197/197 | 60 / 60 s | 0.01 / 0.02 s |
| `poor`, α=1 | 44.0 | 270/280 | 84/85 | 103 / 241 s | 22 / 248 s |
| `poor`, α=2 | 44.5 | 272/280 | 74/74 | 85 / 126 s | 3.0 / 20.9 s |
| `poor`, α=3 | 44.0 | 279/280 | 92/92 | 64 / 83 s | 2.1 / 2.9 s |
| `poor`, α=5 | 45.0 | 280/280 | 85/85 | 41 / 61 s | 1.1 / 1.2 s |

Every time is a count of 20-second RPC timeouts. A lookup waits on dead contacts, and α sets how many of those waits overlap.

- **k = 20, the default, kept.** k=4 lost 15 of 560 records and k=8 lost 1. k=12 and k=20 lost none and tied on every correctness count. 20 is kept for its margin over r: at the kill, a FIND_NODE answer held a median of 10.5 live contacts at k=12 and 14 at k=20, and a publish needs 8. Fifty nodes are close to a full mesh at either value, so this simulation cannot show what k buys a large network. That is for M19.
- **α = 5, not the default 3.** Correctness is flat from α=3 up. Time is not. The record lookup's worst case at the kill was 20 s at α=3 and 0.03 s at α=5. Under `poor` it was 2.9 s against 1.2 s, and FIND_NODE's median was 64 s against 41 s. The cost is 23% more RPCs a lookup (10.2 against 8.3).
- **r = 8.** Lookups whose record went missing with 30% killed at once: 36%, 16%, 2.5%, 0.4% and 0.4% for r = 1, 2, 3, 4 and 5, and none of 560 at r = 8. Independent failure would predict 0.3^r: 30%, 9%, 2.7%, 0.8%, 0.2% and 0.007%. The low r values run worse than that, because a lookup that misses one replica also pays its timeout. r = 8 costs 8 STOREs a republish.
- **Not measured here:** refresh (15 min shipped, 30 s in the simulation) belongs to M19's churn gates. The RPC timeout stays at `request_timeout`, 20 s.

**Mutations, 50 nodes** (run on the final defaults; the table in the milestone report has the per-gate results). `numeric` fails gates 1 and 2. `noevict` fails gate 5. `noverify` fails gate 7. `clientjoins` fails gate 6. `serial` (α=1) passes every gate and degrades: the times are in the α=1 rows above.

**Gate 3 needs a record.** An absent key's lookup ends `exhausted` because every one of the k closest has answered, not because the budget ran out. `MAX_LOOKUP_RPCS` is 128, and absent-key lookups used 20 to 23 RPCs.

### M16a — Rate limit against α, and the member allowance

**The limit bound.** M16's final gates run had 43 requests refused at α = 5. A refused RPC looks like a dead contact to the asker, which marks it suspect and evicts it if the check is refused too, and that reads as churn. So the demand was measured before anything else was changed. `netem/dht.py gates` now ends with `demand`: per (server, source IP) pair, the most requests in one limiter window, counted as the limiter counts. The source is the servers' own logs. The instrument was run three ways: the `wide` build (both allowances lifted) at the simulation's 30 s refresh, the shipped limits at the same refresh, and `wide` at the shipped 15-minute refresh.

| run | pairs | peak p50 / p90 / p99 / max | pairs over 10 / 30 | refused |
|---|---|---|---|---|
| `wide`, 30 s refresh | 2601 | 8 / 18 / 29 / 34 | 1075 / 15 | 0 |
| shipped limits, 30 s refresh | 2604 | 8 / 19 / 28 / 38 | 978 / 14 | 33 |
| `wide`, 15 min refresh | 2440 | 3 / 11 / 16 / 20 | 300 / 0 | 0 |

The limited run's refusals fall where the lifted run's demand exceeds 30, which is the check that the instrument sees what it claims to. At 30 s refresh the peaks are FIND_NODE, from maintenance running at thirty times the shipped rate. At the shipped refresh the peak is a member's first minute: join, publish, and a burst of lookups.

**Resolved without a refusal signal on the wire.** The 20/minute shipped-refresh and 34/minute compressed-refresh figures are not interchangeable: the latter comes from maintenance running thirty times too often. The simulation had not performed dial-backs, so its ordinary members were strangers at most servers; it could not choose a product stranger allowance. Product defaults remain `per_source = 10` and `forward_per_member = 30`: proof is a meaningful 3× allowance, while a stranger retains V0.1's flood bound. The `p2pchat dht` harness explicitly starts its controlled population in the post-dial-back state and applies 40/60 only when its refresh is compressed to 30 seconds. No on-wire claim, routing-table entry, or simulation shortcut changes the product limiter. A refusal signal remains unnecessary protocol complexity.

**The member allowance follows a passed dial-back.** It is no longer given to routing-table presence. A public node records an IP as proven when a forwarded dial-back it took part in reached it: as the member that forwarded (on the dialling member's word) or as the member that dialled. The record lasts `PROVEN_FOR`, one hour, twice `reach::RETEST`. Only proven and configured IPs get `forward_per_member`. The proof is local and never passed on, so it exists at the bootstrap members and the members they forward to, and elsewhere members are strangers, which is why `per_source` had to carry DHT traffic. Gate, `m16a_the_member_allowance_follows_a_passed_dial_back_not_a_claim` (stranger 3, member 8, twelve pings each): a claimant that names itself a member on every request and is held in the routing table got **3**, and a node that passed a dial-back and claims nothing got **8**. Mutations: allowance granted on routing-table presence fails it (the claimant got 9, "the claim raised the allowance"), and so does a proof that is recorded and ignored (the proven node got 2).

**agent.md §7** now names the rule M16 taught: an assertion must not derive its expected value from the code under test.

### M17 — Publish and lookup integration

Nodes publish their record on startup and republish before expiry. Connecting to a peer becomes: look up their user ID, get addresses, dial.

Resolves **OD-4** and **OD-6**.

**Gate:** a node's record is findable from an unrelated node within a bounded time of startup; an address change propagates within the republish interval; a peer that has gone offline is reported as not found rather than dialled forever.

**OD-4 resolved — supplement, not replace.** Invites remain the explicit
acceptance and identity-sharing path. The DHT is used after an accepted peer is
known, so a move can be followed without reissuing an invite; it does not grant
a session and it deliberately makes current dial addresses discoverable to a
party that already knows the user ID. After a silent DHT-sourced dial, a newer
signed record with different addresses is **stale** evidence. With no newer
record the error says that the DHT address *may be stale* before the M12
unreachable checklist; silence alone is not evidence of either condition.

**OD-6 resolved — 180 s strict lifetime, 90 s republish.** The 600 s number is
the selected §10 reconnect budget, not a measured timeout. Its accounting is
180 s record lifetime + 36 s capped backoff/jitter + 40 s for two 20 s dials,
leaving 344 s. The 300 s skew check rejects only a `published_at` in the
future; it never extends expiry. At r=8, each node sends 40 publishes/hour or
320 STORE RPCs/hour, versus the old 30-minute placeholder's 2 publishes/16
STOREs per hour (20x).

**Final M17 netem, 50 nodes, final harness.** Every profile passed all five
gates and every self-test fault. Baseline/typical/poor respectively measured
startup findability maxima of 0.55/4.81/10.72 s; a strictly newer moved record
in 0.00/0.21/0.61 s; successful redial after the move in 20.02/22.58/23.35 s;
and offline-to-not-found in 216.1/167.1/188.3 s. Publish p90 was
14/3861/8970 ms and republish-gap p90 90.0/93.6/98.5 s. Mutants fail the named
gates: DHT bypass 1, no newer republish 2, ignored expiry 3, and hard-wired
unreachable 4. JSON and logs are retained under `netem/results/`.

### M18 — Coordinated hole punching

The milestone the whole plan exists for.

Both peers learn each other's reflexive addresses, a mutually reachable member signals both to punch, and both send simultaneously so each NAT opens a return path for the other. Then the existing V0.1 handshake runs over whichever path opens.

Where punching cannot work — symmetric NAT on either side — fail with a message that names the reason, in the style of M12's unreachable-owner diagnostic.

**Gate:** two clients behind simulated port-restricted NATs establish a session with no relay; punch timing tolerates realistic jitter, tested under the netem profiles; symmetric NAT produces a clear terminal error, not a retry loop; the signalling member sees no conversation content; a failed punch falls back to a direct dial where one side is reachable.

### M19 — Churn and healing

The self-healing property, tested as a property.

Bucket refresh under churn, record republication when a storage node leaves, recovery when bootstrap nodes disappear after join.

**Gate:** with 30% of members killed, lookups still succeed; with 50% killed and replaced, the network reconverges within a bounded time; a record survives the loss of the nodes originally storing it; a node whose entire bootstrap list is dead reports that clearly rather than hanging.

### M20 — Threat model and honest documentation

Update `THREAT_MODEL.md` for what V0.2 changes:

- **Presence and address are publicly queryable** by user ID. The largest single change from V0.1.
- **Sybil and eclipse attacks.** An attacker controlling enough nodes near a target's key in XOR space can censor lookups or partition a node's view. Mitigations — disjoint lookup paths, diverse bucket population — reduce it and do not eliminate it.
- **Signalling nodes learn who is trying to reach whom**, and when. They learn no content.
- **Symmetric NAT users cannot connect**, and the software cannot fix it for them.
- **Bootstrap nodes are a centralisation point** at join time.

**Gate:** every item above is written; the README states plainly which NAT types work; no claim in either document is stronger than what a test demonstrates.

---

## 6. Risks

| Risk | Impact | Response |
|---|---|---|
| The reachable member set is tiny early on | High | Bootstrap nodes must also be members; accept that the network needs seeding |
| Punch success rate lower than expected on Indian carriers | High | M13's classification tells you before M18 is built. Measure first |
| Kademlia parameters copied rather than measured | Medium | OD-7 resolved against the simulation, as V0.1's timeouts were measured against netem |
| The simulation is wrong, so every DHT gate is vacuous | High | The harness needs the same mutation discipline as the code — see `agent.md` §7 |
| Scope drift into relays or offline delivery | Medium | Both are explicitly excluded here; revisit in V0.3 if ever |

---

## 7. What stays untouched

The V0.1 protocol core — handshake, session crypto, storage, reconnection — does not change. V0.2 changes only how a peer's address is found and how a connection is opened. If a V0.2 milestone requires editing `architecture.md` §6 or §7, stop and reconsider: that is a sign the change is larger than discovery.
