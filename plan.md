# plan.md — V0.1 build order

Twelve milestones. Each has a **gate**: a concrete, checkable condition. Do not start the next milestone until the current gate passes. The ordering is deliberate — it front-loads the parts that are hard to retrofit and defers the parts that are pleasant to build.

Estimates assume part-time work and are for sequencing, not for commitments.

---

## M0 — Scaffolding · ~1 day

Workspace with six crates. `thiserror` error enums per crate. `tracing` writing to a rotating file. CI running fmt, clippy with `-D warnings`, test, `cargo audit`, `cargo deny`.

**Gate:** `cargo test --all` passes on an empty workspace; a `tracing::info!` lands in the log file and nothing appears on stdout.

> Set up file logging here, not later. Once the TUI exists, a stray `println!` corrupts the display and the cause is not obvious.

---

## M1 — Identity · ~1 day

Ed25519 keygen, user ID derivation, fingerprint formatting, keystore load/save with permission checks. `whoami` subcommand.

**Resolves OD-2.** Decide now whether the identity file is passphrase-encrypted, because it determines whether the TUI needs an unlock screen in M9.

**Gate:** two runs produce an identical user ID; a key file with mode `0644` causes a refusal to start; F-01 and F-02 criteria pass.

---

## M2 — Wire format · ~1 day

All `postcard` message types in `p2pchat-core`. Length-delimited framing. Frame size limits.

**Gate:** property test round-trips every message type; serialization is byte-identical across 1000 runs of the same value (this is what the transcript hash depends on); an over-size frame is rejected rather than allocated.

---

## M3 — QUIC transport · ~2 days

`rcgen` certificate, permissive client verifier, both endpoints listening, channel binding extraction.

**Gate:** two processes on localhost open a connection, exchange framed messages, and **both independently derive the same 32-byte channel binding**. Assert equality in a test — if this is skipped, M4's relay resistance is untestable.

---

## M4 — Handshake · ~3 days, the hard one

Three-message exchange, transcript hashing, signing, all five verification checks, small-order point rejection.

**Gate:** happy path succeeds. Then all of these fail correctly, each with its own test:
- bad signature
- `BLAKE3(identity_pk) != user_id`
- unexpected peer ID on an outbound connection
- replayed `HELLO_INIT` from a captured session (F-09)
- replayed `HELLO_CONFIRM` into a different connection
- a QUIC-level proxy between the parties (F-10)
- all-zero ephemeral public key

The negative tests are the milestone. A handshake that only passes the happy path has been tested for nothing.

---

## M5 — Session crypto · ~2 days

HKDF split into directional keys, ChaCha20-Poly1305 with sequence-derived nonces, AAD binding, receiver ordering rules, zeroization.

**Gate:** encrypt/decrypt round-trips both directions; the two directional keys differ; encrypting identical input twice produces identical output (proving no RNG in the path); a replayed frame is rejected by the `frame_seq` rule; a flipped ciphertext bit fails the tag; two consecutive sessions derive different keys (F-11).

---

## M6 — Storage · ~2 days

Schema, migrations, store actor, repositories, pagination.

**Resolves OD-1.** Decide alongside the OD-2 outcome from M1 — per-row encryption only makes sense if the identity key is also protected.

**Gate:** messages survive restart; the `UNIQUE` constraint absorbs a duplicate insert without error; 10,000 messages paginate in under 50 ms per page; database file is `0600`.

---

## M7 — Public node · ~2 days

Invite encode/decode, profile requests, connection request/accept/reject, pending queue.

**Resolves OD-3** (invite expiry).

**Gate:** an invite round-trips; a tampered invite is rejected; a connection request reaches the peer and both accept and reject paths work end to end.

---

## M8 — Messaging end to end · ~2 days

Wire M4, M5, M6, M7 together. Send, receive, persist, ACK. Still headless, driven by a debug CLI.

**Gate:** two processes on localhost exchange 100 messages with correct order, no duplicates, and correct `SENT`/`DELIVERED` transitions. This is the first genuinely working chat.

---

## M8a — Private-node access control · ~0.5 day

Close the hole M8's gate exposed: `architecture.md` §6 proves who a peer is, and nothing was deciding whether that peer was allowed in. Persist the user's acceptance per peer (§8's `peers.accepted`), check it after the handshake on the authenticated ID, dial only accepted peers.

**Gate:** an unaccepted peer that completes a valid handshake is closed; an accepted peer's session succeeds; acceptance survives restart and the peer reconnects without re-requesting; a rejected peer cannot open a session; a peer claiming an accepted `user_id` without its key is rejected; and probing with a claimed-accepted ID and a claimed-unaccepted ID, neither holding the key, is indistinguishable — same close code, same point in the exchange.

---

## M9 — TUI · ~4 days

`ratatui` layout, the dedicated input thread, channel bridge to the async core, scrollback, textarea, help overlay, panic hook that restores the terminal.

**Gate:** all F-21 to F-25 criteria; usable at 80×24; resize does not corrupt; `Ctrl-C` restores the terminal; a deliberate panic also restores the terminal.

> Budget generously. Bridging a blocking input loop to an async core is where most TUI projects lose time, and the bug class — a rendering deadlock under load — is unpleasant to debug.

---

## M10 — Reconnection and resync · ~2 days

Connection state machine, backoff with jitter, `RESYNC` exchange, retransmission under the new session key.

**Gate:** F-20's test — kill the network, send 50 messages, restore, assert all 50 arrive exactly once in order. Also: an authentication failure does not enter the retry loop.

M9 left two of F-25's five states unreachable: nothing reports `handshaking`, and `reconnecting` has nothing to report yet. Both belong to the state machine built here, and the status bar already has the labels.

---

## M11 — Hardening · ~2 days

Zeroization audit, `cargo audit`, `THREAT_MODEL.md`, the log-scanning test from F-29, README with honest limitations.

**Gate:** clean audit; the log-secret test passes; the threat model names what is not protected, including metadata, TOFU, and presence.

---

## M12 — Real-network validation · ~1 day

One node on a VPS with a public IP, one on a home connection. Chat across the real Internet.

**Gate:** project success criterion 1. Document what happens when both nodes are behind CGNAT — it will fail, and the failure mode should be a clear message rather than a hang.

---

## Sequencing rationale

Crypto before storage, storage before UI, UI before polish. Three reasons:

**Security properties cannot be retrofitted.** Nonce derivation, transcript binding, and key separation change the wire format. Adding them after the TUI exists means changing every layer at once. Adding them first costs nothing.

**The TUI is the most satisfying part and the least load-bearing.** Building it early would produce a beautiful shell around an unfinished protocol, and the temptation to declare victory there is real.

**The negative tests in M4 and M5 are the actual deliverable.** Everything else is plumbing that either works or obviously does not. Authentication that is subtly broken looks exactly like authentication that works.

---

## Risk register

| Risk | Likelihood | Impact | Response |
|---|---|---|---|
| CGNAT blocks real-world testing | High | Medium | VPS for M12; documented in project.md §7 |
| Handshake takes longer than M4's estimate | Medium | Medium | Expected. Do not compress the negative tests to recover time |
| TUI/async bridge deadlocks | Medium | Medium | Channels only, never a lock held across an await |
| `rustls`/`quinn` version skew | Medium | Low | Pin both; upgrade together or not at all |
| Scope creep into group chat or file transfer | Medium | High | feature.md's out-of-scope list is the answer |
| dalek 3.0 lands mid-build with a `rand` 0.9 requirement | Low | Low | Pin and ignore until V0.2 |

---

## After V0.1

Not commitments, just the natural next steps: replace the hand-rolled handshake with Noise XX via `snow` and compare; add hole punching with a rendezvous server; double ratchet for per-message forward secrecy; multi-device; group chat via pairwise sessions.
