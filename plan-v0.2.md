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
- **OD-7 — Kademlia parameters:** bucket size *k*, replication factor, lookup parallelism α. Defaults exist (k=20, α=3) but should be chosen against a simulated network, not copied.

---

## 5. Milestones

### M13 — STUN address discovery and NAT classification

Learn the node's own external address from public STUN servers. Classify the NAT: full cone, restricted, port-restricted, or symmetric.

No infrastructure of your own. This milestone alone tells you whether M18 can ever work on a given connection.

**Gate:** reflexive address reported correctly behind a NAT; classification agrees with an independent tool on at least three networks; a node with no NAT reports so; the classification never claims punchable when it is symmetric.

### M14 — Reachability self-test

A node must know whether it can serve. Ask a bootstrap member to dial back on the advertised address; if the dial arrives, the node is reachable and joins as a member, otherwise as a client.

Re-test on network change, since a laptop moving from broadband to tethering changes category.

**Gate:** a node behind CGNAT classifies itself as a client; a reachable node classifies itself as a member; classification updates within a bounded time after the network changes; a node that falsely claims reachability is detected by the dial-back failing.

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

**Gate:** a forged record is rejected; a record whose user ID does not bind to its key is rejected; an expired record is rejected with a distinct error; a rolled-back `seq` is rejected; a tampered address field fails the signature.

### M16 — Kademlia core

Routing table with k-buckets, XOR distance, `FIND_NODE`, `STORE`, `FIND_VALUE`, iterative lookup with parallelism α, bucket refresh, node eviction with liveness checks.

Members only. Clients issue lookups without holding routing state.

Build the simulation harness alongside it — this cannot be tested with two nodes. Extend the existing `netem/` harness to spawn N nodes in containers with configurable churn.

**Gate:** lookups succeed in a 50-node simulated network; the routing table converges after bootstrap; a lookup for an absent key terminates rather than looping; buckets refresh on schedule; dead nodes are evicted.

### M17 — Publish and lookup integration

Nodes publish their record on startup and republish before expiry. Connecting to a peer becomes: look up their user ID, get addresses, dial.

Resolves **OD-4** and **OD-6**.

**Gate:** a node's record is findable from an unrelated node within a bounded time of startup; an address change propagates within the republish interval; a peer that has gone offline is reported as not found rather than dialled forever.

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
