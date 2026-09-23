# feature.md — V0.1

Every feature carries acceptance criteria. A feature is not done when the code exists; it is done when the criteria pass, in a test where the criterion can be expressed as one.

Priority: **P0** ships or V0.1 does not exist. **P1** ships unless time runs out. **P2** is stretch.

---

## Identity

### F-01 — Identity generation · P0
On first launch, generate an Ed25519 keypair and derive the user ID.

- Second launch loads the same identity; user ID is byte-identical.
- Key file is mode `0600`; the app refuses to start if permissions are wider.
- Generation completes in under 100 ms.
- Secret key material is either wrapped in `Zeroizing<_>` or held in a type that implements `ZeroizeOnDrop`. `ed25519-dalek`'s `SigningKey` is the second kind: it zeroizes itself on drop and cannot be wrapped in `Zeroizing`, so it is held bare and a test asserts the bound.

### F-02 — Fingerprint display · P0
Show a short fingerprint for the local identity and every peer.

- Format `a83f 1e92 7c4b 0d15`, derived from the first 16 hex chars of the user ID.
- Local fingerprint reachable within one keystroke from the main view.
- Peer fingerprint visible in the conversation header, not buried in a submenu.
- An unverified peer is visually marked as such.

### F-03 — Fingerprint verification · P1
Let a user mark a peer as verified after comparing fingerprints out-of-band.

- Sets `peers.verified = 1`, persists across restarts.
- If a known peer presents a different identity key, the session is refused and the user is told plainly. This must not be a silent re-trust.

---

## Discovery and connection

### F-04 — Invite generation · P0
Produce a pasteable invite blob for the local identity.

- Output is a single line beginning `p2pchat:v1:`, under 300 characters.
- Contains user ID, identity public key, display name, public node addresses.
- Signed by the identity key.
- Never advertises an unspecified address (`0.0.0.0`, `[::]`). That is a bind address; it names no host, so a peer cannot dial it. Generation fails and says to pass `--addr`. Loopback is allowed: it names this host, and two nodes on one machine is how the tests run.

### F-05 — Invite import · P0
Accept a pasted invite blob.

- Rejects a malformed blob with a readable message, not a panic.
- Rejects a blob whose signature does not verify.
- Rejects a blob where `BLAKE3(identity_pk) != user_id`.
- Rejects an expired blob, once OD-3 is settled.
- On success, stores the peer and shows its fingerprint for comparison **before** connecting.

### F-06 — Connection request · P0
Ask a peer's public node for permission to open a private session.

- Request appears on the recipient's TUI within two seconds.
- Recipient can accept or reject.
- Rejection is reported to the sender and does not retry.
- A request from an unknown peer shows its fingerprint and user ID, never only a self-declared display name.
- A peer the user has not accepted cannot open a private session, even with a valid handshake: it is closed, with the same code a handshake failure closes with.

### F-07 — Pending request queue · P1
Requests arriving while the user is elsewhere in the UI are queued, not dropped.

- Visible badge count.
- Queue survives restart.

---

## Session security

### F-08 — Mutual authentication · P0
Both peers prove control of their identity keys.

- A handshake with a bad signature is rejected.
- A handshake where `BLAKE3(identity_pk) != user_id` is rejected.
- On outbound connections, a handshake from an unexpected user ID is rejected.
- Failures close the connection without revealing which check failed.
- Every one of the above has a negative test.

### F-09 — Replay resistance · P0
A recorded handshake cannot be reused.

- Test: capture all three handshake messages, replay against a fresh responder, assert rejection.
- Test: replay `HELLO_CONFIRM` into a different connection, assert rejection.

### F-10 — Relay resistance · P0
A man-in-the-middle terminating and reopening QUIC cannot produce an accepted session.

- Test: a harness that proxies at the QUIC level, so the two connections have different channel bindings. Assert both sides abort.
- This test is the one that proves the channel binding is actually wired in. Without it, the binding can be silently dropped and everything still appears to work.

### F-11 — Forward secrecy · P0
Compromise of an identity key does not decrypt recorded sessions.

- Ephemeral X25519 keys are fresh per connection.
- Ephemeral secrets are zeroized immediately after the DH.
- Test: assert two consecutive sessions between the same peers derive different session keys.

### F-12 — Directional keys and derived nonces · P0
Nonce reuse is structurally impossible.

- HKDF produces two distinct 32-byte keys; assert they differ.
- Nonce is a function of `frame_seq`; no RNG call in the encrypt path. Enforced by review and by a test that runs the encryptor twice with identical input and asserts identical output.
- Receiver rejects any frame whose `frame_seq` is not strictly greater than the last seen.

---

## Messaging

### F-13 — Send and receive · P0
Exchange authenticated encrypted text messages.

- Round trip on loopback under 50 ms at p50.
- Messages up to 4 KiB of UTF-8.
- A tag verification failure closes the session rather than dropping the frame.
- Messages are persisted before an ACK is emitted.

### F-14 — Ordering · P0
Messages display in the order sent.

- Ordered by `msg_seq` within a conversation, not by arrival or timestamp.
- Within one QUIC stream, ordering is already guaranteed; the logic exists for the cross-session case and is tested there.

### F-15 — Deduplication · P0
A resent message is stored once.

- Enforced by `UNIQUE (conversation_id, sender_id, msg_seq)` and `INSERT OR IGNORE`.
- A duplicate triggers a repeated ACK, not a second stored row or a second UI entry.

### F-16 — Delivery status · P1
Show `SENT`, `DELIVERED`, `READ`.

- `DELIVERED` is emitted after the store commit, never before.
- `READ` fires only when the conversation pane has focus.
- Status survives restart.

### F-17 — Local history · P0
Conversations persist.

- Restarting shows prior history.
- Database is at `~/.local/share/p2pchat/`, mode `0600`.
- Storage form of `body` pending **OD-1**.

---

## Resilience

### F-18 — Disconnect detection · P0
A dropped connection is noticed and shown.

- Detected within 20 seconds via QUIC keepalive and idle timeout (`architecture.md` §6). The keepalive is 5 seconds, so 20 seconds is three missed keepalives before the connection is declared lost.
- Peer shown as offline in the TUI.
- Queued outbound messages are marked pending rather than failed.

### F-19 — Reconnection · P0
Reconnect automatically with backoff.

- 1s, 2s, 4s, 8s, 16s, 30s, then 30s with ±20% jitter.
- Gives up after 10 minutes and requires user action.
- A full new handshake and new session keys each time; no resumption.
- An authentication failure does **not** trigger automatic retry.

### F-20 — Message resync · P0
Nothing is lost across a disconnect.

- Both sides exchange `have_through`, then retransmit above it.
- Test: send 50 messages while the peer is down, reconnect, assert all 50 arrive exactly once in order.
- Retransmission is encrypted under the new session key, sourced from stored bodies.

---

## Terminal UI

### F-21 — Layout · P0
Panes: conversation list on the left, message history centre, input at the bottom, status bar at the top.

- Reflows on resize without corruption.
- Usable at 80×24.
- Renders at 30 fps or on event, whichever is less work — do not redraw in a busy loop.

### F-22 — Scrollback · P0
Scroll through history.

- Page up/down, home/end.
- Loads older messages from SQLite in pages of 50 rather than reading the whole conversation.
- Auto-scrolls on a new message only when already at the bottom.

### F-23 — Input · P0
Compose and send.

- Multi-line via `tui-textarea`, Enter sends, Shift+Enter newline.
- Unsent draft preserved when switching conversations.

### F-24 — Keybindings and help · P1
Discoverable controls.

- `?` opens a help overlay listing every binding.
- `Ctrl-C` exits cleanly: terminal restored, database closed, keys zeroized.
- A panic restores the terminal before printing — otherwise the user's shell is left in raw mode.

### F-25 — Connection indicator · P1
Status bar shows connection state per conversation.

- Distinguishes connecting, handshaking, established, reconnecting, failed.
- Unverified peers marked.

### F-26 — Notification on new message · P2
Terminal bell or visual marker when a message arrives in an unfocused conversation.

---

## Operational

### F-27 — Config file · P1
TOML at `~/.config/p2pchat/config.toml`.

- Ports, display name, log level, data directory.
- Missing file uses defaults and writes one.
- Invalid file is a clear error, not a panic.
- Every config value is overridable by environment variable, and the override wins over the file. Two nodes must be runnable on one machine from M3 onward — the integration tests depend on it. The variables are listed in `techstack.md`.

### F-28 — CLI subcommands · P1
- `p2pchat` — launch TUI
- `p2pchat whoami` — print user ID, fingerprint, invite blob
- `p2pchat invite` — print invite blob only, for piping
- `p2pchat --version`

### F-29 — File logging · P0
Logs to file, never to the terminal.

- Non-blocking writer, daily rotation.
- Level via `RUST_LOG`.
- **No key material, no plaintext bodies, no full user IDs.** Log fingerprints instead. A test greps the log output of an end-to-end run for known-secret byte patterns and fails if any appear.

---

## Explicitly out of scope

Group chat · file transfer · voice or video · offline or store-and-forward delivery · DHT or global discovery · NAT traversal, hole punching, relays · mobile · multi-device identity · key rotation or revocation · identity recovery · message editing or deletion · read receipts beyond the three states above · typing indicators · themes · plugins
