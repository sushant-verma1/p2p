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

The TUI runs on a dedicated OS thread, not a Tokio task, because `crossterm`'s event read is blocking and must not occupy a runtime worker. It communicates over two channels:

- `mpsc<UiCommand>` — TUI to core ("send this message", "accept this request")
- `mpsc<AppEvent>` — core to TUI ("message received", "peer disconnected")

`rusqlite::Connection` is not `Sync` and SQLite writes serialize anyway, so a single store actor task owns the connection and receives requests over a channel with oneshot replies. No connection pool, no `Arc<Mutex<Connection>>`.

---

## 3. Public node and private node

Both are `quinn::Endpoint`s, separated by ALPN so a misdirected connection fails immediately rather than confusingly.

| | Public node | Private node |
|---|---|---|
| ALPN | `p2pchat-pub/1` | `p2pchat-priv/1` |
| Default port | 47100 | 47101 |
| Auth required | No | Yes, mutual |
| Carries | Profile, connection requests | The conversation |

The public node answers three request types and nothing else: `PROFILE_REQUEST`, `CONNECTION_REQUEST`, and `CONNECTION_STATUS`. It is deliberately dumb and stateless apart from a pending-requests table. **Anything it says about identity is untrusted.** The private node authenticates the peer itself and never relies on the public node's claim — this is what the original spec's §4 was pointing at, and it is load-bearing.

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

### Stream usage

- Handshake: one bidirectional stream, opened by the initiator, closed after the handshake completes.
- Messages: one bidirectional stream per conversation, long-lived.
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

If `frame_seq` would exceed 2^32, tear down the session and rekey. It will not happen in practice; assert it anyway.

### AAD

The full plaintext header is passed as associated data:

```
version ‖ msg_type ‖ message_id ‖ conversation_id ‖ sender_id ‖ msg_seq ‖ created_at
```

The header travels in the clear so the receiver can dedupe and order before decrypting. Because it is authenticated, an attacker cannot alter it. Note that this makes `sender_id` and timing visible on the wire — accepted, and recorded in the threat model.

### Receiver rules

Applied in this order, before anything else:

1. `frame_seq > last_seen_frame_seq`, else drop silently. Replay defence, at the transport layer.
2. Decrypt and verify the tag. Failure → close the session. A single forgery attempt means the session is not trustworthy; do not continue.
3. `sender_id` matches the authenticated peer of this session. Guards against a peer relaying someone else's traffic.
4. `message_id` not already in the store → otherwise re-send the ACK and stop. Idempotency, at the application layer.

Rule 1 is cryptographic. Rule 4 is application-level retry handling. The original spec §17 provided only rule 4 and described it as replay protection; it is not.

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
    verified      INTEGER NOT NULL DEFAULT 0   -- fingerprint confirmed out-of-band
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
CREATE TABLE schema_version (version INTEGER NOT NULL);
```

`conversation_id` is derived deterministically so both sides compute the same value without negotiating:
`BLAKE3(b"p2pchat-v1-conv" || min(user_id_a, user_id_b) || max(user_id_a, user_id_b))`

`message_id` is a UUIDv7 — time-ordered, so the primary key index stays dense.

The `UNIQUE (conversation_id, sender_id, msg_seq)` constraint is the real dedupe mechanism. An `INSERT OR IGNORE` that affects zero rows means "already have it", which is atomic and avoids a check-then-insert race.

**OD-1 resolved: `body` holds plaintext.** Per-row encryption under an Argon2id-derived key is meaningfully better only if the identity key sitting next to it is also protected, and OD-2 chose not to protect it. Encrypting one and not the other buys nothing and costs an unlock screen. `project.md` §7 states the consequence plainly.

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

A verification failure — bad signature, ID mismatch — never retries automatically. It means either a bug or an attack, and quietly reconnecting in a loop is the wrong response to both.

### Reconnect and resync

Every reconnection produces a **completely new session**: new ephemeral keys, new directional keys, `frame_seq` back to 0. No session resumption in V0.1. This is what makes per-connection forward secrecy real, and it costs one extra round trip.

After the handshake, on the conversation stream:

```
I → R:  RESYNC { conversation_id, have_through: u64 }   // highest msg_seq received from R
R → I:  RESYNC { conversation_id, have_through: u64 }
```

Each side then retransmits everything it holds above the peer's `have_through`, in order, re-encrypted under the **new** session key. This is only possible because the store holds decrypted bodies rather than wire ciphertext — §8, defect 4. With ciphertext storage this step would require the old session key, which no longer exists.

Duplicates are harmless: the `UNIQUE` constraint absorbs them.

---

## 11. Acknowledgements

```
SENT ──▶ DELIVERED ──▶ READ
```

`SENT` is local, set on write to the socket. `DELIVERED` on receipt of an ACK, which the receiver emits after the store commit, not on receipt — otherwise a crash between the two loses a message that was reported as delivered. `READ` when the conversation pane is focused and the message is on screen.

ACKs are ordinary encrypted frames on the conversation stream. They are not themselves acknowledged.

---

## 12. Things a reviewer will look for

Collected here because each is a plausible implementation slip that silently removes a security property:

- Accepting the QUIC certificate as identity rather than only as transport.
- Forgetting the channel binding, making the inner handshake relayable.
- Signing only one's own nonce, reintroducing replay.
- A random nonce sneaking back into the AEAD path.
- One session key used in both directions with a shared counter.
- Skipping check 3 in §6 on outbound connections, so any peer can answer.
- Reporting which handshake check failed back to the peer.
- Logging key material, plaintext, or full user IDs at any level.
- Storing wire ciphertext, breaking resync after key rotation.
- `unwrap()` on network-supplied data — a remote panic is a remote denial of service.
