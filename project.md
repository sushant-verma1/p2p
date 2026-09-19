# project.md — Decentralized P2P Terminal Chat

**Version:** V0.1
**Status:** Design approved, implementation not started
**Owner:** Sushant Verma

---

## 1. What this is

A peer-to-peer terminal chat application written in Rust. Every user runs their own node. No central server stores, relays, or can read conversations. Two peers exchange an invite blob out-of-band, connect directly over QUIC, mutually authenticate with long-term identity keys, derive a forward-secret session key, and exchange authenticated encrypted messages that are stored only on the two participants' own machines.

## 2. Why it exists

Primary goal is **learning by building the internals**: cryptographic handshake design, wire protocol design, session state machines, async networking, and local durability. The value is in what is *not* delegated to a framework.

Secondary goal is a portfolio artifact that demonstrates protocol-level competence rather than CRUD competence.

This is explicitly **not** a product. It is not intended for users who need real communications security today. That is stated plainly in the README and in the threat model.

## 3. Non-goals for V0.1

Listed so they cannot silently creep back in:

- Group chat, file transfer, voice, video
- Offline delivery of any kind — both peers must be online simultaneously
- A DHT or any global discovery mechanism
- NAT traversal, hole punching, or relays
- Mobile, background delivery, or push notifications
- Deniability, metadata privacy, or protection against traffic analysis
- Multi-device support for one identity
- Key rotation, revocation, or recovery of a lost identity

## 4. Decisions locked in

These came from discovery and are settled unless deliberately revisited. Marked `[stated]` where the user chose directly, `[derived]` where it follows necessarily from a stated choice.

| Decision | Value | Source |
|---|---|---|
| Language | Rust (2021 edition) | [stated] |
| Transport | QUIC via `quinn` | [stated] |
| Signatures | Ed25519 | [stated] |
| Key agreement | X25519, **ephemeral per connection** | [stated] |
| Local storage | SQLite via `rusqlite` | [stated] |
| Discovery | Manual paste of a signed invite blob | [stated] |
| Terminal UI | Full TUI with panes and scrollback | [stated] |
| AEAD | ChaCha20-Poly1305 | [derived] — pairs with the dalek stack, no AES-NI dependency |
| Async runtime | Tokio | [derived] — `quinn` requires it |

## 5. Settled decisions

The three open decisions of the design phase are resolved. Recorded here rather than deleted, so the reasoning survives.

- **OD-1 — Message storage at rest. Resolved: plaintext in SQLite.** At-rest protection is out of scope for V0.1. Decided together with OD-2: per-row encryption is only meaningful if the identity key sitting next to it is also protected, and neither is. Consequence in §7. See `architecture.md` §8.
- **OD-2 — Identity key at rest. Resolved: unencrypted file, mode `0600`, permissions verified at startup.** No passphrase, so the TUI needs no unlock screen. Windows has no `0600`; where the equivalent cannot be verified the application says so explicitly rather than skipping the check silently. Consequence in §7.
- **OD-3 — Invite blob expiry. Resolved: invites expire 24 hours after `created_at`,** with a few minutes of skew tolerance so a fast clock does not reject a fresh invite. An expired invite produces a distinct error from a malformed or badly signed one: "ask for a new invite" is a different instruction from "your paste is corrupted". See `architecture.md` §9.

## 6. Success criteria

V0.1 is done when all of the following hold:

1. Two nodes on two different machines, on two different networks, complete a chat session with no third party involved in message delivery.
2. Killing the network mid-conversation and restoring it results in a new session key and zero lost or duplicated messages.
3. A recorded handshake replayed against a node is rejected.
4. An attacker positioned between the two nodes cannot produce a session that either side accepts.
5. `cargo audit` and `cargo clippy -- -D warnings` are both clean.
6. `THREAT_MODEL.md` exists and honestly states what this does and does not protect against.

Criteria 2–4 are covered by automated tests, not manual checks.

## 7. Known structural weaknesses

Accepted for V0.1, recorded so they are not mistaken for oversights:

- **CGNAT.** Most Indian home broadband and all mobile data put the node behind carrier-grade NAT, where inbound connections are impossible. With no hole punching in scope, real-world testing requires a VPS, a LAN, or a port-forwarded connection. This is the single largest practical limitation.
- **Trust on first use.** Nothing verifies that an invite blob came from the person who claims to have sent it. If the channel used to share the invite is compromised, the attacker is the peer. Out-of-band fingerprint comparison is the only mitigation and it is manual.
- **Metadata.** An observer on the wire sees that two IP addresses are talking, when, and roughly how much. Only content is protected.
- **No protection at rest.** The identity key is an unencrypted file and message bodies are plaintext in SQLite (OD-1, OD-2). Anyone who can read the disk — a stolen unlocked laptop, a backup, another local account with sufficient privilege — reads the entire history and can impersonate the identity from that point on. What a stolen identity key does *not* do is decrypt past traffic: session keys are ephemeral and are never written down, so recorded conversations stay unreadable. Full-disk encryption is the mitigation, and it is the operating system's job.
- **Presence.** A node is reachable only while running. There is no store-and-forward.

## 8. Glossary

| Term | Meaning |
|---|---|
| **Identity key** | Long-term Ed25519 keypair. Generated once. Answers "who are you?" |
| **User ID** | `BLAKE3(identity public key)`, 32 bytes, rendered as 64 hex chars. Permanent. |
| **Ephemeral key** | X25519 keypair generated fresh for each connection, destroyed after. Provides forward secrecy. |
| **Public node** | QUIC endpoint serving profile lookups and connection requests. Carries no conversation. |
| **Private node** | QUIC endpoint carrying the authenticated encrypted conversation. |
| **Invite blob** | Signed, base64 string containing a user's ID, identity public key, and reachable addresses. |
| **Session** | One authenticated connection. Has its own directional keys and its own sequence counters. |
| **Transcript hash** | Running hash of every handshake byte, plus the QUIC channel binding. What both parties sign. |
| **Channel binding** | 32 bytes exported from the QUIC TLS session, tying the inner handshake to the outer tunnel. |
