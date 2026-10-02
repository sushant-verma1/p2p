# architecture.md — V0.1

Normative. If the code and this document disagree, one of them is a bug; decide which and fix it.

---

## 1. Changes from the original specification

Four structural defects in the V0.1 spec are corrected here. Anyone implementing from the old document will reintroduce them.

| # | Defect in original spec | Correction |
|---|---|---|
| 1 | Each side signed a nonce it chose itself (§8), so a recorded `HELLO` replays successfully. | Each side signs a transcript that includes the **peer's** nonce and the QUIC channel binding. |
| 2 | `SESSION_KEY` (§11) was unsigned and unbound; anyone could send one, since the recipient's public key is public. | The `SESSION_KEY` message is deleted. The key comes from an ephemeral X25519 exchange whose public values are covered by the signed transcript. |
| 3 | Random per-message nonces under a long-lived key (§15). A repeat under GCM is a total break, and the birthday bound on a 96-bit random nonce is uncomfortably close for a long session. | Nonces are **derived from the sequence number**, and each direction gets its own key via HKDF. Reuse becomes structurally impossible. |
| 4 | Wire ciphertext stored in the local database (§19), forcing every old session key to be retained forever, which defeats the key rotation in §21 and the forward secrecy added here. | Transport decryption and storage are separate layers. The database never holds wire ciphertext. |

A fifth change follows from the choice of ephemeral X25519: the "no forward secrecy" limitation the original spec acknowledged in §11 no longer applies. Compromise of an identity key allows impersonation *going forward*; it does not decrypt any recorded past session.

---

## 2. Process and module layout

One binary, one process, two QUIC endpoints on two UDP ports.

```
p2pchat (bin)
├── p2pchat-core      types, wire format, errors, IDs
├── p2pchat-crypto    identity, handshake, AEAD, KDF, keystore
├── p2pchat-net       QUIC endpoints, public node, private node, sessions
├── p2pchat-store     SQLite schema, migrations, repositories
└── p2pchat-tui       ratatui rendering and input
```

Dependency direction is strictly downward. `core` depends on nothing internal. `crypto` depends on `core`. `net` depends on `core` and `crypto`. `store` depends on `core` only. `tui` depends on `core` only and talks to everything else through channels. **No library crate depends on `tui`.** The binary is the composition root: it depends on all five, wires them together, and is the only place that may name `tui`.

This matters because it keeps the crypto and protocol layers testable without a terminal, a socket, or a database.

### Runtime shape

```
main
 ├── tokio runtime (multi-thread)
 │    ├── public endpoint task    accepts CONNECTION_REQUEST etc.
 │    ├── private endpoint task   accepts inbound sessions
 │    ├── session task × N        one per connected peer
 │    └── store actor task        owns the rusqlite Connection
 └── TUI thread (blocking)
      └── crossterm event read loop
```

The TUI runs on a dedicated OS thread — the process's main thread, with the runtime built underneath it — and never as a Tokio task, because `crossterm`'s event read is blocking and must not occupy a runtime worker. Being outside the runtime is also why it reaches the core with `blocking_send` and `oneshot::blocking_recv`: `block_on` from inside a runtime deadlocks it. The seam is a `Core` trait declared in `p2pchat-tui` and implemented in the binary, so the screen knows about channels no more than it knows about sockets. Two channels:

- `mpsc<Request>` — TUI to core ("send this message", "accept this request", "import this invite"), each with a oneshot for the answer
- `mpsc<Notice>` — core to TUI, and notifications only: "conversation X changed", "the peer list changed", "the requests changed". Never a payload. The core sends with `try_send` and never waits, so a stalled screen cannot stall a session task, and a dropped notice loses nothing: the store holds the truth and the TUI reads back the page it needs. The alternative — events carrying message bodies — makes the screen's speed the network's speed, which is the deadlock this design exists to avoid.

`rusqlite::Connection` is not `Sync` and SQLite writes serialize anyway, so a single store actor task owns the connection and receives requests over a channel with oneshot replies. No connection pool, no `Arc<Mutex<Connection>>`.

---

## 3. Public node and private node

Both are `quinn::Endpoint`s, separated by ALPN so a misdirected connection fails immediately rather than confusingly.

| | Public node | Private node |
|---|---|---|
| ALPN | `p2pchat-pub/1` | `p2pchat-priv/1` |
| Default port | 47100 | 47101 |
| Default bind address | `0.0.0.0` | `0.0.0.0` |
| Auth required | No | Yes, mutual |
| Carries | Profile, connection requests | The conversation |

**The bind address and the advertised address are different addresses, and neither is derived from the other.** The bind address says which of this host's interfaces will accept packets; it defaults to every one of them, because a node bound to `127.0.0.1` is reachable by nothing but the machine it runs on. The advertised address is what a peer elsewhere has to dial, it is carried in invites and in the answer to a status query, and this process cannot work it out — behind NAT the address a peer must use is not an address this host holds at all. So it is supplied, by `--addr`, and an invite that would advertise an unspecified address is refused rather than emitted (§9, F-04). Every integration test binds loopback explicitly, which is why binding loopback by default survived this long unnoticed.

**The private advertised address is not a secret.** A node's private endpoint is where an accepted requester dials it (§10), and that address is handed out in the answer to `CONNECTION_STATUS` — an unauthenticated query anyone can make. It is derived from `--addr`'s host with the private port, `--private-addr` overriding it, and like the invite's address it may never be unspecified: a node given nowhere to advertise refuses to start rather than hand out `0.0.0.0`.

Two things make giving it away cheap. The address is only told to a caller whose request the *user accepted*, so it is not a free read of where the node listens; and knowing it buys nothing anyway, because §10's access control, not obscurity, is what keeps an unaccepted peer out of a session — an unaccepted dialler completes §6 and is closed. The reverse lie costs no more: a public node that answers `Accepted` with somebody *else's* private address makes the requester dial that node, where §6 check 3 finds an identity that is not the one the requester asked for and aborts. A false address is worth one failed connection. It is never worth an impersonation. Since M17 the first reason no longer holds, and the second always did: a node's DHT record publishes where it can be dialled privately to anyone who knows its user ID (see "Publish and lookup" below).

The public node answers six request types and nothing else: `PROFILE_REQUEST`, `CONNECTION_REQUEST`, `CONNECTION_STATUS`, and, from V0.2, `DIAL_BACK` (M14), `FORWARD_DIAL_BACK` (M14b, member to member) and the DHT's queries (M16, answered only by a member). It is deliberately dumb and stateless apart from a pending-requests table. On the wire the five are the variants of one closed enum, `PublicRequest`, answered by a closed `PublicResponse`; "and nothing else" is then a property of the types rather than of a match arm someone remembers not to add. `CONNECTION_STATUS` is a *query* — "what became of my request?" — keyed by the caller's user ID, which is how the pending-requests table is keyed. The answer to `PROFILE_REQUEST` is the owner's signed invite (§9), not a fresh unsigned profile type: the caller verifies a signature instead of trusting the node that handed it over. **Anything it says about identity is untrusted.** The private node authenticates the peer itself and never relies on the public node's claim — this is what the original spec's §4 was pointing at, and it is load-bearing.

### The node owns its sockets

**Each endpoint's UDP socket is bound by this process and handed to quinn — `p2pchat_net::node_endpoint` — and every dial leaves from the private endpoint's socket. Do not "simplify" this back to `Endpoint::server` plus a separate `Endpoint::client`.** The reason is NAT, and it is not visible on a LAN or in any loopback test: a NAT's mapping belongs to one socket, not to the host. STUN asked from a throwaway socket learns the throwaway's mapping, which says nothing about the port quinn's packets leave from; a hole punched from any socket but quinn's opens a port nothing is listening on; a dial from an ephemeral client socket uses neither. So the socket STUN asks from, the socket punch packets leave from, and the socket QUIC dials and listens on have to be the same one (M13a).

Two consequences follow, and both are load-bearing:

- **One socket carries STUN and QUIC, split on the way in.** A datagram whose first two bits are zero and which carries STUN's magic cookie goes to STUN; everything else goes to quinn; nothing goes to both (`p2pchat_net::socket`). This is exact only because every QUIC packet sets the fixed bit, `0x40`, of its first byte — so **quinn's `grease_quic_bit` stays off**. RFC 9287 greasing lets a peer clear that bit, quinn offers it by default, and with it on a QUIC packet could be taken for STUN. Turned off, quinn also drops any packet that arrives with the bit clear.
- **The private endpoint dials, and asks public nodes, as well as listening.** A QUIC endpoint's ALPN is per connection, so an ask offers `p2pchat-pub/1` explicitly (`connect_as`) from the same socket. There is no separate dialling endpoint any more, and a new one should not be added.

The public endpoint is built the same way, over its own socket; nothing asks STUN from it yet.

### Dial-back (M14, M14b)

`DIAL_BACK` asks a public node to have the requester dialled back and to say whether that worked. A node uses the answer to decide whether it can serve as a DHT member. **The request carries no address.** The asked member, A, takes the target from `remote_address()` of the connection the request arrived on. That address is proven, because the QUIC handshake completed before the request could be read, and an off-path attacker cannot complete one from a forged source. A field naming a target would make the public node a reflector for whoever writes into it. So there is none, and adding one is a wire change that has to answer this paragraph.

**A never dials the requester itself. It forwards.** The requester has just sent packets to A's IP, so a NAT that filters on IP alone admits anything from that IP, on any port. A dial-back from A therefore passes behind such a NAT whether or not a stranger could get in. Asking two members does not help, because the requester sends to each member it asks (M14a found this). What makes an arrival mean something is its source: an IP the requester never contacted. So A sends `FORWARD_DIAL_BACK { nonce, target }` to another member, B, and B dials `target`. B dials from a socket made for that one dial-back. A socket B reused could be one the target answered on a previous test, and an endpoint-dependent NAT would still hold that mapping open.

**A skips every member at the IP the request was sent to** (`Connection::local_ip`). That is A itself, and any other member on its IP, both addresses the requester has sent to. Comparing against A's own socket address is not enough: on the default wildcard bind that address is `0.0.0.0`, which matches no member entry. Until M17 found it, a member so bound that listed itself (as a shared bootstrap list does) forwarded to itself, dialled back from the IP it was asked on, and so made every requester a client.

**Fewer than two members means client, never a single-member dial.** If A has no other member, or none answers within `forward_timeout`, A answers `{ observed, forwarded: false }` and dials nothing. The requester reads that as inconclusive and logs the reason. There is no fallback to A dialling, because that fallback is exactly the test that passes behind an IP-only NAT.

The dial-back offers its own ALPN, `p2pchat-dialback/1`, which the private endpoint also accepts, and the private endpoint routes such a connection away from §6 before the handshake starts. The connection carries the request's nonce, and the requester closes it with code 0 once it recognises the nonce. B answers A after that close, and A answers the requester after that, so the answer `{ observed, forwarded, reached }` arrives after the dial-back has landed or failed. The requester believes only what arrived. It is a member only if the answer says forwarded and a dial-back carrying its nonce reached it from an IP it did not send to during the test. That second check does not trust A. A member that dials back itself and claims to have forwarded is caught by it.

**`FORWARD_DIAL_BACK` does name an address, and that is the exposure this design accepts.** B cannot check that `target` is what A observed. So:

- B takes a forward only from an IP in its member list, and silently ignores anyone else's. A stranger cannot aim B at all, and cannot aim A either: A's own target comes from the connection, and A ignores forwards from non-members too.
- A member that lies can aim B at a third party. Each forward buys one QUIC connection attempt, and **there is no amplification**: one request in, one dial out, and the dial is a QUIC Initial, which is smaller than the forward that caused it. The target receives a single connection attempt, with ALPN `p2pchat-dialback/1`, from an address a member vouched for. It gets no payload unless it completes a QUIC handshake, which a third party that is not running this software will not do.
- B limits forwarded dial-backs **per target IP** (`forward_per_target`, default 2 a minute, whoever forwards) and **per forwarding member** (`forward_per_member`, default 30 a minute, counted before the TLS handshake in place of the stranger's 10). A lying member can therefore aim at most 30 single attempts a minute through B, and any one target receives at most 2 a minute from B however many members forward to it. A rate-limited forward is answered `reached: false` rather than with silence, so the forwarder does not misreport it as "no second member".

`THREAT_MODEL.md` §12 records this as an exposure V0.2 introduces. The limits are `public::Limits` fields, so a deployment can tighten them.

### Address records (M15)

An `AddressRecord` is `{ body: AddressRecordBody, sig }`, where the body holds `version`, `user_id`, `identity_pk`, `addrs` (at most `MAX_ADDRS`, never empty), `seq`, `published_at` and `expires_at`. The signature is Ed25519 over `b"p2pchat-v1-address-record" ‖ postcard(body)`. The prefix matters because the same identity key signs invites (unprefixed body bytes) and §6 transcripts, and none of those signatures may verify as a record. The checks run in this order: bounds, `version`, `BLAKE3(domain ‖ identity_pk) == user_id`, the signature (`verify_strict`), and then the timestamp. `seq` is compared only after all of those pass. Checking a timestamp or counter before the signature lets an attacker produce "expired" by editing a number, or outrank a real record with a forged `seq`. That is the invite rule in §9 again. A record supersedes the held one for the same user only with a higher `seq`. The same `seq` is accepted only as the identical record. `p2pchat_crypto::record` implements all of this.

### DHT (M16)

Kademlia over the public node: `PublicRequest::Dht` carries `PING`, `FIND_NODE`, `FIND_VALUE` or `STORE`, one request per connection like every other public request, and `p2pchat_net::dht` implements it. A node ID is the user ID. Distance is XOR, and a bucket is the number of leading bits two IDs share.

**Only members serve and only members are held.** A member's request names itself, as `Member { id, port }`. A client's names nobody, so no routing table ever holds a client, and a client holds no routing table either: it starts every lookup from its bootstrap list. **The contact a member is entered as is the connection's IP with the port it names.** The IP is never the sender's word, for the reason `DIAL_BACK` carries no address: otherwise anyone could put a third party's address into every routing table that hears from them. A known ID is refreshed only at the address already held for it. A request claiming that ID from elsewhere proves nothing about the entry, and taking its address would let anyone who names an ID redirect it.

**A storage node is never trusted, and never trusts what it is given.** `STORE` runs `record::supersedes` against the record already held for that key before anything is kept. `FIND_VALUE` runs `record::verify` again before serving, because a record can expire while it is held. The asker runs `record::verify` a third time, and also checks that the record's `user_id` is the key it asked for. A valid record for somebody else is still a wrong answer.

**Bounds**, since IDs are chosen by whoever generates the key. Every collection that grows from network input has one. The routing table holds `k` per bucket. A full bucket runs one liveness check on its oldest entry at a time, and a newcomer is dropped while that check runs. A lookup's shortlist holds `SHORTLIST` candidates and spends at most `MAX_LOOKUP_RPCS` RPCs, and at most `MAX_LOOKUPS` lookups run at once. At most `MAX_RECORDS` records are held, one per key. An answer carries at most `MAX_CONTACTS`, which is checked on decode. Nothing is keyed by a `HashMap` over IDs (`techstack.md`).

**Liveness.** A contact that fails an RPC, or has not been heard from for `refresh`, is pinged at the next maintenance round, and evicted if the ping goes unanswered. The ping must be answered with the ID held for that contact. A round starts its refreshes and pings and does not wait for them, so one dead contact's 20-second timeout does not delay every other refresh. A member whose table holds none of its bootstrap members also seeds its refreshes from the bootstrap list, and an empty table still refreshes bucket 0. Without those two rules, a member cut off from everyone it knew would never look for them again.

**Rate allowance (M16a).** Lookups and refreshes between members pass through the same public-node limiter as everything else, which counts per source IP before the TLS handshake and so cannot see what is asked. A source gets the member allowance (`forward_per_member`, 30 a minute) only if it is a configured member or has **passed a forwarded dial-back this node took part in**, as the member that forwarded it or the one that dialled (`public::PROVEN_FOR`, one hour, twice `reach::RETEST`). Naming itself a `Member` in a DHT request, and the routing-table slot that buys, raise nothing: both are the sender's word. The proof is local and never passed on. The 50-node simulation's 30-second refresh does not model dial-backs, so its controlled members are explicitly seeded as already proven and its harness-only allowance is 40/60; that clock runs maintenance thirty times faster than the shipped 15-minute refresh. Product defaults remain stranger 10 and proven/configured member 30, a meaningful 3× proof benefit. No simulated request changes those defaults.

### Publish and lookup (M17)

Every node with a bootstrap list runs the DHT: as a member while M14's test says it is reachable and it has a public node to serve on, as a client otherwise, switching when the test's answer changes. A member that becomes a client empties its table.

**The record.** A node publishes an `AddressRecord` whose `addrs` are, in order, the address this run's last dial-back reached (observed by a member and proved dialable by another) and the configured private address (`--private-addr`, or `--addr`'s host with the private port). The observed one comes first because it follows the node: after a network change the next test observes the new address, while the configured one says what was true when it was typed. It is this run's, never the result restored from the last run: that one is about a socket a restart may have replaced. A client with nothing configured publishes nothing; there is nowhere to say it can be dialled (M18 adds the reflexive address). `seq` is the time in milliseconds, or one more than the last, so a restarted node's first record outranks the last run's without state on disk.

**When.** At startup, again every `record::REPUBLISH` (90 s), and at once when a test finds a new address. A publish that no member took is retried after `reach::NETWORK_POLL`. Losing an address (the network changed, the retest has not answered) does not republish: until the retest says where the node is now, a new record would say nothing truer.

**Connecting** to an accepted peer is a lookup of its user ID, then a dial to each address in its record in order. The reconnect loop (§10) does the same on every attempt when the node has a DHT, so it follows a peer that moved. No record is `NotFound`, which is terminal: the peer is offline, and the loop reports it and stops rather than dialling an address nobody vouches for.

**Stale or unreachable.** A silent dial to an address from a record looks the same whether the peer has left that address or is still behind it. That is M12's difficulty, and it is not solved at the dial. What tells the cases apart is the record, which the owner signed with the time it was published. After a silent dial the node asks the DHT for a record newer than the one it dialled (`Dht::lookup_newer`, which skips replicas still holding the old one). A newer record with different addresses means the address was **stale**. The dial is reported so, and the newer addresses are dialled. A newer record with the same addresses is only a republish. With no newer record, the DHT-sourced address **may still be stale**: inside `REPUBLISH` it may be a current unreachable peer or a move not yet republished; after it, the owner missed an expected republish and may be offline or moved without knowing it. The failure message says that uncertainty before giving M12's unreachable checklist. The stale reading still needs the owner's republish to land inside the dialler's silent dial, `DIAL_TIMEOUT_MS` (20 s).

**OD-6.** `record::LIFETIME` is 180 s and `REPUBLISH` half that, 90 s. The 600 s bound comes from §10's existing, chosen reconnect budget: a peer that goes offline must become not found before that loop gives up. Expiry is strict: a record stops verifying at `LIFETIME` after its last publication. The 300 s skew allowance applies only when a signed `published_at` is in the verifier's future; it never extends expiry. An attempt waits at most the 30 s backoff cap plus 20% jitter (36 s) and then dials each address for the 20 s dial deadline, 40 s for two addresses. Thus `LIFETIME + 36 + 40 ≤ 600`; 180 leaves 344 s of budget margin. Moves are measured as the elapsed time from the change to a successful redial by the M17 netem harness, not derived from this bound.

### QUIC TLS layer

QUIC mandates TLS 1.3. This project does not use the web PKI, so:

- Each node generates a self-signed certificate at startup via `rcgen`. It is ephemeral and carries no identity meaning.
- The client uses a custom `rustls::client::danger::ServerCertVerifier` that accepts any certificate. This is correct here and only here — authentication happens in the inner handshake.
- The certificate must **not** be treated as identity. A reviewer will look for this mistake.

To stop the outer tunnel from being a relay point, extract 32 bytes of channel binding after the QUIC handshake:

```rust
let mut cb = [0u8; 32];
connection.export_keying_material(&mut cb, b"p2pchat-v1-channel-binding", &[])?;
```

Those bytes are mixed into the transcript hash. An attacker who terminates one QUIC connection and opens another to the real peer gets different channel bindings on the two sides, the signatures fail to verify, and the handshake aborts. Without this step, the inner handshake would be relayable and the TLS layer would be doing nothing for us.

---

## 4. Identity

```
Ed25519 keypair generated on first launch
        ↓
identity_pk (32 bytes)
        ↓
BLAKE3(b"p2pchat-v1-userid" || identity_pk)
        ↓
user_id (32 bytes) → 64 hex chars
```

BLAKE3 rather than SHA-256: faster, and one fewer hash family in the dependency tree since it is also used for the transcript.

Displayed to humans as a **fingerprint** — first 16 hex chars in groups of four (`a83f 1e92 7c4b 0d15`). Full ID shown on the profile screen. The fingerprint is what users compare out-of-band to detect a swapped invite; the TUI must present it prominently enough that comparing it is the obvious thing to do.

The Ed25519 key signs. It never performs key agreement. Deriving X25519 from Ed25519 is possible but mixes key usage across two algorithms, and there is no reason to do it when generating a separate ephemeral key is trivial.

**Storage:** `~/.config/p2pchat/identity.key`, mode `0600`, containing the 32-byte Ed25519 seed and nothing else. Permissions are verified on load and the application refuses to start if they are wider; on platforms with no `0600` equivalent it says so rather than skipping the check. The file is **not** encrypted — OD-2, resolved; see `project.md` §5 and §7.

---

## 5. Wire format

`postcard` over QUIC streams. Chosen over JSON and CBOR because it is deterministic — the same value always serializes to the same bytes. That property is required, not aesthetic: both sides independently hash the handshake transcript, and a serializer permitted to reorder map keys or vary integer encodings would make those hashes disagree.

Every stream carries length-delimited frames: `u32` big-endian length, then that many bytes of `postcard`. Maximum frame size 64 KiB; anything larger closes the connection with a protocol error. QUIC does not preserve message boundaries within a stream, so framing is still required.

### Signed structures

Anything signed "over all preceding fields" is a nested struct holding exactly those fields, with the signature beside it: `HelloResp { unsigned, sig_r }`, `Invite { body, sig }`. `postcard` writes a nested struct inline, so the bytes are identical to the flat layouts drawn in §6 and §9, while the signed range becomes a type instead of a comment about where to stop.

### Bounds

Every variable-length field has a declared maximum, checked on decode at the one call site that turns bytes into a wire type. A peer must not get to choose our allocation sizes.

| Field | Maximum | Why |
|---|---|---|
| frame | 64 KiB | above; checked from the length prefix, before anything is allocated |
| `ciphertext` | 4096 + 16 | F-13's 4 KiB body plus the ChaCha20-Poly1305 tag |
| `display_name` | 32 bytes | keeps an invite blob inside F-04's 300 characters |
| `addrs` | 4 | one node, a handful of public addresses. The invite's field, and since M9d the only one: a `CONNECTION_REQUEST` carries no address at all (§10) |
| `nonce_i`, `nonce_r` | 32 bytes, exactly | fixed size, so nothing to bound; the length matters because they are inside the signed transcript |

An `ACK` arriving from a peer carries only `DELIVERED` or `READ`. `PENDING`, `SENT` and `FAILED` are local states the peer cannot observe, and a frame claiming one of them is malformed, not a disagreement (§11).

### Version

`version` is **not** checked while decoding. A v2 peer sends a well-formed message that we decline — §6 check 1, at the handshake — and that is a different outcome from a corrupt one: different error, different thing to tell the user.

### Stream usage

- Handshake: one bidirectional stream, opened by the initiator.
- Messages: the same stream, which **becomes** the conversation stream once the handshake reaches Established. It is not closed and a second one is not opened. A stream opened with `open_bi()` is invisible to the peer until something is written on it, so a fresh conversation stream would leave both sides waiting for the other to speak first, and the ordering guarantee that makes this work (F-14) is per-stream: the conversation's order is the handshake stream's order.
- Control (ACKs, resync): the same conversation stream. Separate streams would reintroduce ordering problems that QUIC just solved.

---

## 6. Handshake

Three messages. Structurally this is the Noise `XX` pattern with explicit signatures instead of a static-static DH; describing it that way in the README is accurate and saves explanation.

Let **I** = initiator, **R** = responder.

```
        I                                          R
        │                                          │
        │  QUIC connection established             │
        │  both compute cb = channel binding       │
        │                                          │
        │  ── 1. HELLO_INIT ──────────────────────▶│
        │     version, user_id_i,                  │
        │     identity_pk_i, eph_pk_i, nonce_i     │
        │                                          │
        │                                          │  verify id binding
        │                                          │
        │◀─ 2. HELLO_RESP ─────────────────────────│
        │     version, user_id_r,                  │
        │     identity_pk_r, eph_pk_r, nonce_r,    │
        │     sig_r                                │
        │                                          │
   verify sig_r                                    │
        │                                          │
        │  ── 3. HELLO_CONFIRM ───────────────────▶│
        │     sig_i                                │
        │                                          │  verify sig_i
        │                                          │
        │  ◀════ session established ═══════════▶  │
```

### Transcript

Maintained by both sides as a running BLAKE3 hasher:

```
h ← BLAKE3.new()
h.update(b"p2pchat-v1-handshake")
h.update(cb)                          // 32-byte channel binding
h.update(postcard(HELLO_INIT))
h.update(postcard(HELLO_RESP_unsigned))   // all fields except sig_r
```

`nonce_i` and `nonce_r` are 32 bytes each, from `OsRng`. They exist only inside the signed transcript, which is the one place their length matters.

The two nonces are redundant with the channel binding and the ephemeral public keys, which already make every transcript unique; they are kept as defence in depth. If the channel binding is ever dropped — by a refactor, or by a transport that cannot export one — the nonces are what still stops a transcript from repeating. Do not remove them as unused.

- `sig_r = Ed25519_sign(identity_sk_r, h.finalize())` computed at that point.
- `h.update(sig_r)`, then `sig_i = Ed25519_sign(identity_sk_i, h.finalize())`.

Because the transcript covers `nonce_i`, `nonce_r`, both ephemeral public keys, and the channel binding, a signature is valid for exactly one connection between exactly these two parties. Replaying any message into a different connection fails. This is the fix for defect 1.

### Checks each side performs, in order

1. `version == 1`, else abort.
2. `BLAKE3(domain || identity_pk_peer) == user_id_peer`. Prevents claiming another identity. Abort on mismatch.
3. If the peer was expected — an outbound connection to a known user ID — `user_id_peer` equals the expected ID. Abort on mismatch. **This check is what makes the invite blob meaningful; skipping it makes authentication pointless.**
4. Signature verifies against `identity_pk_peer` over the transcript hash at the correct point.
5. `eph_pk_peer` is not the all-zero point and not a known small-order point. `x25519_dalek`'s `SharedSecret::was_contributory()` covers this — check it and abort if false.

Any failure closes the connection immediately with a generic error code. Do not report *which* check failed to the peer; it is an oracle. Log the detail locally.

### Timeout

The whole exchange must complete within **14 seconds** of the QUIC connection opening, else abort. Each individual read gets the same deadline, so a peer that sends one byte a second cannot stretch the exchange out by keeping a read alive.

A peer that connects and never finishes the handshake otherwise holds a connection, a stream and an ephemeral key pair for as long as it likes, at no cost to itself. The timeout is the only thing that bounds that.

The value is measured, not chosen (M12b, `netem/`). Over an 800 ms round trip with bursty loss — netem's Gilbert-Elliott model, set for 8% loss with a mean burst of 1.45 — 150 handshakes took p50 0.80 s, p99 8.47 s, max 13.22 s; the old 10 seconds failed one of them. The link measured 16.95% round-trip ping loss, about 8.9% a leg, which is harsher than the 8% intended, so 14 seconds is a conservative figure rather than a tight one.

It is not a loose one either. M12c came close to it twice, both over the same 800 ms round trip with 8% independent loss:
- 13.93 s, 0.07 s under the limit: M12c's sweep, 30 handshakes, 13.25% round-trip ping loss over 400 pings.
- 13.21 s, 0.79 s under it: the re-run after the harness fix, 150 handshakes, 15.75% round-trip ping loss over 2000 pings.

The margin is tight on purpose, and only on profiles harsher than real mobile networks: an 800 ms round trip losing 13–16% of pings is past what a poor cellular link does. Covering these near-misses would mean a higher limit, and every peer that connects and then stalls would hold its connection that much longer. So 14 seconds stays. A handshake timeout under real conditions, not under netem, is the signal to raise it.

The 14 seconds start when the QUIC connection opens, so they cover none of the connect. A whole dial — connect *plus* handshake — gets **20 seconds**: the 14, plus 6 for the connect. The 6 is a budget that covers almost every connect, not the slowest ever seen. Over the same 800 ms round trip, at 8% independent loss and bursty loss alike, M12b's slowest of 180 connects was 3.80 s, and every one of M12c's 486 was 3.23 s or under except one: 8.02 s, under bursty loss, followed by a 2.40 s handshake, so that dial still finished inside the 20. Raising the dial deadline to guarantee that case would make every unreachable peer wait longer to buy it. A unit test holds the handshake timeout plus the connect budget under the dial deadline, so raising one without the other fails. An unreachable peer produces a failed dial at that point rather than whatever QUIC eventually decides. `P2PCHAT_DIAL_TIMEOUT_MS` overrides it; the gates set it low so that this deadline, and not QUIC's, is what they measure. For the same reason a dialler offers a **60-second** idle limit rather than 20: until the peer answers there is no negotiation, the dialler's own limit governs, and at 20 it raced the dial deadline and usually won with a bare "timed out" (M12b). Once the peer's transport parameters arrive QUIC takes the smaller offer, so an established session still uses the 20 seconds below.

A connection request to a public node (§3) also waits **20 seconds**, so a request and a dial give up after the same time. Over an 800 ms round trip with 8% loss (16.35% round-trip ping loss), 200 requests took p50 1.61 s, p90 4.94 s, p99 16.37 s, max 25.05 s. QUIC's loss recovery doubles its timer on each consecutive loss, so the answers bunch up: about 7.3 s after three losses in a row, 14.5–17.4 s after four, about 25 s after five. The old 5 seconds failed 9.5% of them. 20 seconds fails 0.5%, the one five-loss run, which is the same rate as the 18.2 s the samples alone suggest. The public node applies the same 20 seconds to its side of the exchange. A node that gave up sooner would cut off callers on slow links who were still inside their own deadline.

### Keep-alive

An established connection carries a packet at least every **5 seconds**, and is declared lost after **20 seconds** without one.

quinn's defaults are a 30-second idle timeout and no keep-alive. A chat is silent most of the time, so those defaults close every conversation thirty seconds after the last message — the connection is gone while both screens still say connected, and the next message is written to a session that no longer exists. Both values are set on the shared transport config, so the two endpoints cannot drift apart; a keep-alive on one side only is still a session that dies.

### Key derivation

```
ss     = X25519(eph_sk_self, eph_pk_peer)      // 32 bytes
salt   = final transcript hash                  // 32 bytes
okm    = HKDF-SHA256(ikm = ss, salt = salt, info = b"p2pchat-v1-session", len = 64)

k_i2r  = okm[0..32]     // initiator → responder
k_r2i  = okm[32..64]    // responder → initiator
```

Both ephemeral secret keys are zeroized immediately after the DH. `ss` is zeroized after HKDF. The identity secret key stays in memory, wrapped in a `Zeroizing` type.

Two directional keys, not one. This is required by §7 and is the second half of the fix for defect 3.

---

## 7. Message encryption

**ChaCha20-Poly1305.** 32-byte key, 12-byte nonce, 16-byte tag.

### Nonce construction

```
nonce[0..4]  = 0x00 0x00 0x00 0x00     // reserved, must be zero
nonce[4..12] = sequence as u64 big-endian
```

Derived, never random. Each direction has its own key and its own counter starting at 0, so a `(key, nonce)` pair is used exactly once in the lifetime of the session. This is the fix for defect 3.

Sequence numbers are **per-session**, reset to 0 on every new session, and are not the same thing as the message sequence used for resync. Keeping these confused is the easiest way to reintroduce nonce reuse. The wire type names them distinctly: `frame_seq` (transport, per-session) and `msg_seq` (application, per-conversation, persistent).

**`frame_seq` is never transmitted.** It is a local counter, one per direction, advanced on every frame sent and every frame accepted. The QUIC stream delivers exactly once and in order, so the sender's counter and the receiver's counter cannot drift apart; if they somehow did, the next tag would fail. Putting it on the wire would hand an attacker a mutable nonce selector and buy nothing in return. `MessageFrame` is therefore `{ header, ciphertext }`, and `frame_seq` is absent from the AAD for the same reason it is absent from the wire.

If `frame_seq` would exceed 2^32, tear down the session and rekey. It will not happen in practice; assert it anyway.

### AAD

The full plaintext header is passed as associated data:

```
version ‖ msg_type ‖ message_id ‖ conversation_id ‖ sender_id ‖ msg_seq ‖ created_at
```

The header travels in the clear so the receiver can dedupe and order before decrypting. Because it is authenticated, an attacker cannot alter it. Note that this makes `sender_id` and timing visible on the wire — accepted, and recorded in the threat model.

### Receiver rules

Applied in this order, before anything else:

1. Take the next `frame_seq` for this direction from the local counter. There is no peer-supplied value to validate: transport replay is prevented by the QUIC stream, which delivers each frame exactly once and in order, and the counter is correct by construction. A duplicated or reordered frame is not something the stream can deliver, and a stream that fails is a closed connection rather than a scrambled one.
2. Decrypt and verify the tag. Failure → close the session. A single forgery attempt means the session is not trustworthy; do not continue.
3. `sender_id` matches the authenticated peer of this session. Guards against a peer relaying someone else's traffic.
4. `message_id` not already in the store → otherwise re-send the ACK and stop. Idempotency, at the application layer.

Transport replay is handled by rule 1 — the QUIC stream and the local counter together. Rule 4 is application-level retry handling. The original spec §17 provided only rule 4 and described it as replay protection; on its own it is not.

---

## 8. Storage

SQLite via `rusqlite` with the `bundled` feature. WAL mode, `foreign_keys = ON`, `synchronous = NORMAL`.

**The database never stores wire ciphertext.** Fix for defect 4. Ciphertext is a property of a session that will be destroyed; history outlives sessions. Storing it would force retention of every session key ever used, which is precisely what forward secrecy is meant to prevent.

```sql
CREATE TABLE peers (
    user_id       BLOB PRIMARY KEY,      -- 32 bytes
    identity_pk   BLOB NOT NULL,         -- 32 bytes
    display_name  TEXT,
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER,
    verified      INTEGER NOT NULL DEFAULT 0,  -- fingerprint confirmed out-of-band
    accepted      INTEGER NOT NULL DEFAULT 0   -- the user let this peer in (§10)
);

CREATE TABLE conversations (
    conversation_id BLOB PRIMARY KEY,
    peer_id         BLOB NOT NULL REFERENCES peers(user_id),
    created_at      INTEGER NOT NULL,
    last_msg_seq    INTEGER NOT NULL DEFAULT 0,   -- highest we have sent
    peer_acked_seq  INTEGER NOT NULL DEFAULT 0    -- highest peer confirmed
);

CREATE TABLE messages (
    message_id      BLOB PRIMARY KEY,
    conversation_id BLOB NOT NULL REFERENCES conversations(conversation_id),
    sender_id       BLOB NOT NULL,
    msg_seq         INTEGER NOT NULL,
    body            BLOB NOT NULL,        -- plaintext, OD-1
    created_at      INTEGER NOT NULL,
    received_at     INTEGER,
    status          INTEGER NOT NULL,     -- 0 pending 1 sent 2 delivered 3 read 4 failed
    UNIQUE (conversation_id, sender_id, msg_seq)
);

CREATE INDEX idx_messages_conv_seq ON messages(conversation_id, msg_seq);

CREATE TABLE pending_requests (
    from_user_id     BLOB PRIMARY KEY,      -- 32 bytes, self-declared
    from_identity_pk BLOB NOT NULL,         -- 32 bytes, self-declared
    display_name     TEXT NOT NULL,         -- advisory, attacker-controlled
    created_at       INTEGER NOT NULL,      -- the caller's clock, unverified
    received_at      INTEGER NOT NULL,      -- ours
    state            INTEGER NOT NULL       -- 0 pending 1 accepted 2 rejected
);

CREATE INDEX idx_pending_requests_state ON pending_requests(state, received_at);

CREATE TABLE outbound_requests (
    to_user_id  BLOB PRIMARY KEY,      -- 32 bytes, from the invite we are acting on
    addr        TEXT NOT NULL,         -- that invite's public node, where we ask again
    created_at  INTEGER NOT NULL       -- ours
);

CREATE TABLE schema_version (version INTEGER NOT NULL);
```

`pending_requests` is the one piece of state the public node keeps (§3), and F-07 requires it to survive restart. Every column but `received_at` and `state` is copied from a `CONNECTION_REQUEST` that nobody has authenticated — the row records *a claim that arrived*, not a peer. Nothing may be trusted out of it, and a row here is not a `peers` row: a peer is written only after the §6 handshake proves the key.

Keyed by `from_user_id`, so a caller who repeats a request finds their existing row rather than adding one. The count of rows in state 0 is capped; a request arriving at a full queue is refused rather than queued, and the refusal is the same `REJECTED` the user's own refusal produces. Rows in state 1 and 2 do not count against the cap, and accumulate only as fast as the user resolves them.

`outbound_requests` is the mirror of it: requests *we* sent and nobody has answered. A row is written when the request goes out. It is removed when the answer is `REJECTED`, or when an `ACCEPTED` answer has produced a session (§10, M12c), so the table is exactly the set of attempts not yet finished. It exists because the answer is rarely immediate and the requester is the side that must keep asking (§10) — without the row, a request pending when the process stops is one nobody ever returns to, and the user would have to send it again to find out it had been accepted an hour ago. The address is stored beside the ID because it is where the *question* goes, which is the invite's public node and not anywhere the peer has claimed to be since.

`peers.accepted` is the user's decision about a peer — §10's access rule, and the half of F-06 that outlives the queue row. It is written by an accept or a reject and by nothing else: a handshake never sets it, or a peer would grant itself access by connecting. A peer may therefore have a row here with no `identity_pk` yet, because the decision can be made before the first handshake; the column is all-zero until §6 proves a key, and an all-zero key cannot satisfy §6 check 2. The migration that adds the column defaults existing rows to 0 — those rows were written when a handshake was all it took, and none of them records a decision anyone made.

`conversation_id` is derived deterministically
 so both sides compute the same value without negotiating:
`BLAKE3(b"p2pchat-v1-conv" || min(user_id_a, user_id_b) || max(user_id_a, user_id_b))`

`message_id` is a UUIDv7 — time-ordered, so the primary key index stays dense.

The `UNIQUE (conversation_id, sender_id, msg_seq)` constraint is the real dedupe mechanism. An `INSERT OR IGNORE` that affects zero rows means "already have it", which is atomic and avoids a check-then-insert race.

It dedupes **per sender, not per conversation.** `msg_seq` is a per-conversation counter held by each peer for the messages *it* sends, so both peers number from their own counter and the column is not unique within a conversation — hence `sender_id` in the constraint, and hence the fact that a conversation normally holds two rows with `msg_seq = 1`.

Ordering is `(msg_seq DESC, message_id DESC)`, the UUIDv7 primary key breaking the tie between the two peers' Nth messages. That tie-break is **arrival-ish order** — the instant each side minted its message ID — and not a happens-before relation: nothing in V0.1 establishes one across the pair, and clocks are not synchronised. Interleaving between the two peers is therefore resolved by that approximation, which both sides compute identically from stored bytes and so agree on. Accepted for V0.1. A real causal order needs a Lamport timestamp or vector clock in `MessageHeader`, which is a wire-format change and does not belong in a point release.

**OD-1 resolved: `body` holds plaintext.** Per-row encryption under an Argon2id-derived key is meaningfully better only if the identity key sitting next to it is also protected, and OD-2 chose not to protect it. Encrypting one and not the other buys nothing and costs an unlock screen. `project.md` §7 states the consequence plainly.

Because the bodies are plaintext, **the database file is refused if it is group- or other-readable**, mirroring the key file check in §4: the file mode is the whole of the protection, not a defence in depth behind encryption. It is created `0600` at the moment it first exists rather than fixed up afterwards, since SQLite would otherwise create it at `0666` minus the umask and leave a window. On a platform with no `0600` equivalent the application says so rather than skipping the check quietly.

---

## 9. Invite blob

```
p2pchat:v1:<base64url(postcard(Invite))>
```

```rust
struct Invite {
    version: u8,
    user_id: [u8; 32],
    identity_pk: [u8; 32],
    display_name: String,     // advisory only, never trusted
    addrs: Vec<SocketAddr>,   // public node addresses
    created_at: u64,
    expires_at: Option<u64>,  // created_at + 24h, OD-3
    sig: [u8; 64],            // over all preceding fields
}
```

**Expiry (OD-3, resolved).** `expires_at` is set to `created_at + 24h`. A receiver rejects an invite whose `expires_at` is in the past, allowing 5 minutes of clock skew so that a fast clock does not reject an invite that was just generated. Expiry is checked *after* the signature verifies — an unsigned timestamp is not worth acting on — and produces its own error variant, distinct from "malformed" and from "bad signature", because the user's next move differs: ask for a new invite, rather than re-copy the one they have.

Roughly 180–220 characters. Self-signed, so tampering is detectable — but self-signed means it proves only internal consistency, not who sent it. An attacker who controls the channel carrying the invite substitutes their own wholesale. The fingerprint comparison in §4 is the only defence and it is manual. Say so in the UI, not just the docs.

---

## 10. Connection lifecycle

```
DISCONNECTED
     │ user pastes invite / peer connects
     ▼
CONNECTING ──── QUIC fails ────▶ BACKOFF ──┐
     │                                      │
     ▼                              retry ◀─┘
HANDSHAKING ─── verification fails ──▶ FAILED (terminal, needs user action)
     │
     ▼
ESTABLISHED ──── stream/connection closed ────▶ BACKOFF
     │
     ▼ user closes
DISCONNECTED
```

Backoff: 1s, 2s, 4s, 8s, 16s, 30s, then every 30s with ±20% jitter. Give up after 10 minutes and require user action.

That is the schedule the code sets, not what a user sees. Against a peer that is down, each attempt costs its backoff delay plus the whole 20-second dial deadline (§6). A node that is down, a closed UDP port and a wrong address all look like silence to QUIC. So attempts start 21, 22, 24, 28, 36 and 50 s apart, and then about every 50 s (44–56 with the jitter). The budget is checked before each attempt, so **15 attempts** start inside the 10 minutes, 14 to 16 depending on the jitter. The last one starts at about 9 min 41 s, and the loop gives up at about 10 min 31 s.

A verification failure — bad signature, ID mismatch — never retries automatically. It means either a bug or an attack, and quietly reconnecting in a loop is the wrong response to both.

### Access control

A private node holds a session **only with a peer the user has accepted** — §6 proves who the peer is, and this decides whether that peer gets in. `peers.accepted` (§8) is the record, F-06 is the decision, and it survives restart, so a peer accepted once reconnects without asking again.

Without this rule the reject in F-06 does nothing. The private address is not a secret (§3): it is handed to every accepted requester, it is derivable from the same `--addr` an invite advertises, and nothing stops a peer that once held it from dialling straight past the public node. The queue would then be a suggestion.

The rule runs in both directions. Inbound, the check is made **after the §6 handshake completes**, on the user ID the handshake *authenticated*, and it is the first thing done with a finished handshake. An unaccepted peer is closed with the same code and reason as a handshake failure (§6), so from outside the two are one event. Outbound, we dial only peers we have accepted: a dial to an unaccepted peer is refused before the connection is opened when the peer is known in advance, and the same post-handshake check catches it when it is not.

**The check is not made on the `user_id` in `HELLO_INIT`, and the connection is not closed early to save the handshake work.** `HELLO_INIT` is unauthenticated: anybody can send any user ID with its matching public key, both of which an invite hands out. Closing early for a claimed-unaccepted ID while carrying on for a claimed-accepted one makes the handshake an oracle — the difference in behaviour is a free read of the accepted list for anyone who can open a QUIC connection, with no key and no invite. Doing the full exchange and then closing is a few signatures wasted on a connection that was going to be closed anyway; that is the price, and it is worth paying. The probe that would exploit the optimisation is a gate test (`p2pchat/tests/access.rs`), and it asserts both the close code *and* how far the exchange got, because an identical close string proves nothing if one connection was cut before `HELLO_RESP` and the other was not.

Note that the claimed ID and the authenticated one are the same value once the handshake has finished — check 2 binds the ID to the key and `sig_i` binds the key to the transcript. Checking the claim at that point is therefore not wrong, it is just indistinguishable; what matters is that nothing is decided *before* it. The equivalence holds only while §6 checks 2 and 4 both hold: check 2 binds the ID to the key, check 4 binds the key to the transcript. The code checks the authenticated ID rather than leaning on the equivalence, because if check 2 is ever relaxed the two diverge, the claim becomes forgeable, and no test in the suite would catch it — the mutant that checks the claim is dead only under the checks as they stand today.

### Who dials, and the wait

**The requester dials. The acceptor never dials back.**

A `CONNECTION_REQUEST` therefore carries no address: the requester's own is of no use to anyone, and the field that used to hold it was a standing invitation to advertise a bind address by accident. The acceptor answers `CONNECTION_STATUS` with its own private advertised address, and only when the state is `ACCEPTED` — `PENDING` and `REJECTED` carry nothing, because a node that has not let someone in has nothing to tell them about where it listens. The requester dials that address with the user ID from the invite as the expected peer, so §6 check 3 decides whether the address was honest.

The reason is reachability. Only the invite's owner has to be reachable — they published an address and are waiting to be asked. The requester published nothing, and under CGNAT has nothing it *could* publish. Having the acceptor dial back would require the requester to be reachable too, which doubles the hosting requirement for no gain and rules out exactly the peer this design is for: someone on mobile data who was handed an invite. `project.md` §7 records what is left of the CGNAT problem after this change.

An answer is rarely immediate — a human has to decide — so the requester asks again: **2 seconds, doubling to a ceiling of 60**, for as long as the request is unanswered and the node is running. The interval starts short because the common case is a user watching both screens, and ends long because the uncommon case is a user who will answer tomorrow. Pending requests are stored (`outbound_requests`, §8) and polling resumes at startup, immediately rather than after the first interval: the decision may well have been made while we were gone. `REJECTED` stops the polling and takes back the acceptance that sending the request recorded, since §10 would otherwise leave us dialling a peer who said no.

`ACCEPTED` does not end the request by itself. **The request stays on file until a session exists** (M12c). If the dial it triggers goes unanswered, the poller keeps asking, gets `ACCEPTED` again and dials again, for as long as the node runs and again after a restart. There is no cap. Only a §6 refusal ends it early, because a peer that fails verification is never retried. Without this, a first dial lost to a blip would strand the peer: accepted, but with nowhere on record to dial, because only an address §6 has proved is stored (`peers.last_addr`, below). Recording the address on acceptance instead would store an address nobody has vouched for. A forged `ACCEPTED` would then be redialled on every restart.

### Simultaneous dial

Two peers who dial each other at the same moment both complete a handshake, and end up with two valid sessions to the same peer. Both are cryptographically sound; the problem is only that messages would split across them.

Rule: **keep the session whose initiator has the lower `user_id`, close the other.** Byte-wise comparison of the 32-byte IDs. Both sides run the same rule on the same two IDs and reach the same answer without exchanging anything further.

Implementing this is M8's work, when a session registry exists to notice the duplicate. Recorded here because the ambiguity is in the protocol, not in the code that will eventually resolve it.

### Reconnect and resync

Every reconnection produces a **completely new session**: new ephemeral keys, new directional keys, `frame_seq` back to 0. No session resumption in V0.1. This is what makes per-connection forward secrecy real, and it costs one extra round trip.

After the handshake, on the conversation stream:

```
I → R:  RESYNC { conversation_id, have_through: u64 }   // highest msg_seq received from R
R → I:  RESYNC { conversation_id, have_through: u64 }
```

Each side then retransmits everything it holds above the peer's `have_through`, in order, re-encrypted under the **new** session key. This is only possible because the store holds decrypted bodies rather than wire ciphertext — §8, defect 4. With ciphertext storage this step would require the old session key, which no longer exists.

Duplicates are harmless: the `UNIQUE` constraint absorbs them.

**`have_through` is also a cumulative acknowledgement.** It is the peer saying it has stored everything up to that number, which is exactly what `DELIVERED` means (§11). The per-message ACKs for those went down with the session that carried them, and the peer will never send them again — from its side they arrived — so without this every message whose ACK was in flight when the connection dropped would sit on `SENT` for the rest of the conversation's life.

**Only the peer that dialled redials.** The rule above — the requester dials, the acceptor never dials back — holds for a session that drops as much as for one that never existed, and for the same reason: the acceptor still has nowhere to dial the requester, and the requester's address is still of no use to anyone. So on a dropped session the side that opened it runs the backoff loop, and the side that answered waits to be dialled again. The address it dials is the one §6 last completed a handshake on, cached in `peers.last_addr` (§8); a node that comes back up dials every accepted peer it has an address for, which is the same path.

**The V0.1 limitation this leaves:** if the original requester is unreachable and the acceptor is not, the session stays down until the requester comes back. Nothing recovers it from the other end, because nothing at the other end knows where to dial. That is accepted rather than unnoticed — the alternative is the acceptor storing and dialling requester addresses, which is exactly the reachability requirement §10 removed, and it would rule out the peer this design is for.

---

## 11. Acknowledgements

```
SENT ──▶ DELIVERED ──▶ READ
```

`SENT` is local, set on write to the socket. `DELIVERED` on receipt of an ACK, which the receiver emits after the store commit, not on receipt — otherwise a crash between the two loses a message that was reported as delivered. `READ` when the conversation pane is focused and the message is on screen.

ACKs are ordinary encrypted frames on the conversation stream. They are not themselves acknowledged.

An ACK's own `MessageHeader` carries a fresh UUIDv7 `message_id` and `msg_seq = 0`. Neither is load-bearing: nothing acknowledges an ACK, so its ID is never referenced, and `msg_seq` numbers stored messages, which an ACK is not. The acknowledged message is named by the `Ack` body inside the frame, not by the header around it. A reader looking for meaning in those two fields will not find any.

---

## 12. Things a reviewer will look for

Collected here because each is a plausible implementation slip that silently removes a security property:

- Accepting the QUIC certificate as identity rather than only as transport.
- Forgetting the channel binding, making the inner handshake relayable.
- Signing only one's own nonce, reintroducing replay.
- A random nonce sneaking back into the AEAD path.
- A `frame_seq` that travels on the wire, where a peer gets to choose it.
- One session key used in both directions with a shared counter.
- Skipping check 3 in §6 on outbound connections, so any peer can answer.
- Reporting which handshake check failed back to the peer.
- Deciding §10 access on the `user_id` `HELLO_INIT` claims, or closing early for an unaccepted claim — either turns the handshake into an oracle for the accepted list.
- Logging key material, plaintext, or full user IDs at any level.
- Storing wire ciphertext, breaking resync after key rotation.
- `unwrap()` on network-supplied data — a remote panic is a remote denial of service.
