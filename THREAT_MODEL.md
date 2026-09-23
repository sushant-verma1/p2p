# THREAT_MODEL.md — V0.1

What this protects against, and — at greater length, because it is the more
useful half — what it does not.

This is a learning project. The honest summary is at the bottom of `README.md`
and it is the same one: do not use this where being wrong has a cost.

---

## 1. The attacker this was built against

One attacker, with three of the usual capabilities:

- **On the wire.** Reads, drops, reorders, replays and forges every packet
  between the two nodes. Can terminate a QUIC connection and open its own.
- **Dishonest peer.** Runs the software, or something that speaks the protocol,
  and connects to you. May claim to be anybody.
- **Off-path forger.** Produces invite blobs, connection requests and status
  answers without being on the path at all.

And three it does not have:

- Code execution on either endpoint.
- Read access to either endpoint's disk. (§5 is about what happens when it
  does.)
- A way to break Ed25519, X25519, BLAKE3, SHA-256 or ChaCha20-Poly1305.

---

## 2. What is protected

| Property | Mechanism | Test |
|---|---|---|
| Confidentiality of message bodies in flight | ChaCha20-Poly1305 under a per-session, per-direction key | `p2pchat-crypto` §7 tests |
| Integrity of message bodies and headers | The header is the AEAD's associated data: edit a field, fail the tag | `session.rs` |
| Mutual authentication | Both sides sign a transcript hash with their Ed25519 identity key; `BLAKE3(identity_pk)` must equal the claimed `user_id` | F-08, `net/tests/handshake.rs` |
| Replay of a recorded handshake | The transcript covers the *peer's* nonce and this connection's QUIC channel binding | F-09 |
| Relay / MITM at the QUIC layer | The transcript covers 32 bytes exported from the QUIC TLS session; a terminator sees two different bindings and neither signature verifies | F-10 |
| Replay or reorder of a recorded frame | The nonce is the receiver's own counter, never a wire field | F-12 |
| Nonce reuse | Two directional keys from HKDF, each with its own counter; no RNG in the encrypt path | F-12 |
| Forward secrecy of recorded sessions against later identity-key theft | Ephemeral X25519 per connection, zeroized after the DH; keys never persisted | F-11 |
| An unaccepted peer opening a session | §10 access control on the *authenticated* ID, after the handshake, with the same close code a handshake failure uses | M8a, `tests/access.rs` |
| Learning which check failed | Every handshake failure is the same error and the same close; the detail goes to the local log only | F-08 |
| Learning who is on the accepted list | An unaccepted peer is closed at the same point, with the same code, as a peer whose handshake failed | M8a gate 6 |

---

## 3. Trust on first use

There is no directory, no key server, no web of trust and no certificate
authority. The first time you see a peer, you see it in an invite blob that
somebody sent you.

**A substituted invite is undetectable.** The invite is signed, but it is
signed by whoever made it. A signature proves the blob was not edited in
transit; it proves nothing about who wrote it. If the channel you used to
exchange invites — email, a chat app, a shared document — is under an
attacker's control, the attacker sends you *its* invite, and everything from
that point on works perfectly: the handshake succeeds, the fingerprint is
stable, messages flow. You are talking to the attacker, and the software has no
way to know.

The only defence is the one the software cannot do for you: **compare the
16-hex-character fingerprint out of band**, over a channel the attacker does
not also control, before you say anything you mind them reading. The TUI shows
the fingerprint in the conversation header, marks unverified peers, and shows
an invite's fingerprint *before* connecting, precisely so that comparing is the
obvious thing to do. It is still manual, and nothing forces it.

`Ctrl-T` marks a peer verified. That flag records that *you* compared
fingerprints. It is not evidence of anything else.

What TOFU does buy: once a peer is known, a *different* key claiming to be that
peer is refused (F-03), so the substitution has to happen at the first contact
or not at all.

---

## 4. Metadata: not protected, at all

An observer on the network — an ISP, a hosting provider, anyone with a tap —
learns:

- **Who talks to whom.** Both IP addresses, directly. There is no relay, no
  mixing, no cover traffic. Direct connection is the design.
- **When**, to the second: connection open, connection close, and every
  reconnection attempt in between.
- **How much**, to within a frame: QUIC packet sizes track message sizes
  closely, and there is no padding. Message counts and rough lengths are
  visible, and typing rhythm is visible in packet timing.
- **That it is this protocol.** The ALPN strings `p2pchat-pub/1` and
  `p2pchat-priv/1` are in the clear in the TLS handshake, as ALPN always is.
  The default ports 47100 and 47101 are a further hint.

`project.md` §3 lists "deniability, metadata privacy, protection against
traffic analysis" as explicit non-goals. This section is what that means in
practice.

### The header is in the clear

`architecture.md` §7 makes the `MessageHeader` the AEAD's **associated data**,
not ciphertext. Associated data is authenticated, not encrypted. So an observer
reads, for every frame:

- `sender_id` — the full 32-byte user ID of the sender
- `conversation_id`
- `message_id`, `msg_seq`, `created_at`, `msg_type`, `version`

Only `body` is encrypted. This is a deliberate trade — the header is what binds
a frame to its conversation and its sender, and having it authenticated in the
clear is what makes the receiver's checks cheap — but it means **the pseudonyms
of both participants are on the wire in every frame**, and a passive observer
can link every session either party ever opens, from any IP address, to the
same identity. Combined with §3, an attacker who has ever seen your invite can
recognise your traffic anywhere.

If that matters to you, this is the wrong tool.

---

## 5. No protection at rest

Neither the identity key nor the message history is encrypted. This was decided
deliberately and together (`project.md` §5, OD-1 and OD-2): per-row database
encryption is theatre if the key that would protect it is sitting unencrypted
in the next directory.

- `~/.config/p2pchat/identity.key` — the raw 32-byte Ed25519 seed. Created mode
  `0600`; the permissions are re-checked on every load and the application
  refuses to start if group or other has any access.
- `~/.local/share/p2pchat/` — the SQLite database, mode `0600`, with every
  message body stored as **plaintext**, and the log file beside it.

**On Windows, permissions are not verified.** There is no `0600`; the
equivalent is an ACL walk that needs a platform crate this project does not
carry. `PERMISSIONS_ENFORCED` is `false` there and the application says so out
loud at startup rather than letting you believe a check happened. Whether the
files are actually protected on a Windows machine is **unknown and untested**:
they inherit whatever the parent directory grants, which on a single-user
install is usually the user's profile, and on a shared or misconfigured machine
may be more.

Anyone who can read the disk — a stolen unlocked laptop, an unencrypted backup,
another local account with sufficient privilege, a cloud-synced home directory
— reads the entire conversation history in the clear, and takes the identity
key with it.

Full-disk encryption is the mitigation, and it is the operating system's job.

---

## 6. Forward secrecy: per session, and no finer

Each connection does a fresh ephemeral X25519 exchange. The shared secret is
zeroized as soon as HKDF has read it; the derived keys live in memory for the
life of the connection and are never written anywhere.

So: **an attacker who records traffic today and steals your identity key
tomorrow cannot decrypt the recording.** That is the property F-11 asks for and
it holds.

What it does not give you:

- **One key per session, not per message.** There is no double ratchet. If an
  attacker extracts the session keys out of a *running* process's memory, every
  message in that session — before and after the moment of compromise — is
  readable. A long-lived session is a large blast radius.
- **No post-compromise recovery within a session.** There is no rekeying. The
  only thing that rotates a key is a reconnection, which is a full new
  handshake (`architecture.md` §10).
- **Nothing protects the stored copy.** Forward secrecy is about the wire. The
  plaintext is in SQLite regardless — see §5. Against an attacker with disk
  access, forward secrecy buys nothing.

### Secrets in memory that are not zeroized

F-01 asks for every secret to be zeroized. An audit at M11 found four places
where it is not. All four are deliberate and are listed here so that nobody has
to find them again:

| Where | What stays in memory | Why it is accepted |
|---|---|---|
| `p2pchat-net` `server_endpoint`, `rcgen::generate_simple_self_signed` | The QUIC certificate's private key, in rcgen's `KeyPair` and the `serialize_der` buffer made from it, freed without being wiped | The key is generated fresh for each process and never reaches disk. It has no identity meaning (`architecture.md` §3): authentication is the inner handshake, bound to the TLS session by the channel binding. rustls keeps its own copy anyway (next row), so wiping rcgen's copy would still leave the key in memory. |
| rustls `ServerConfig` (0.23), via `with_single_cert` | The same TLS key, held for as long as the endpoint exists | rustls exposes no way to wipe a key it holds. The key only matters while the process is running, and anyone who can read the process's memory can already read the session keys (above). |
| `p2pchat-crypto` `session.rs` `expand`, `hkdf` 0.12 | HKDF's PRK, inside the `Hkdf` value, until it is dropped | `hkdf` exposes no way to wipe it. It lives for one call. The input `ss` and the output OKM are both zeroized, so the PRK is the only copy left, briefly, on the stack. |
| Message bodies (`String`s in the session, the store and the TUI) | Plaintext, for as long as anything holds it | Deliberate under OD-1: the same bodies are stored as plaintext in SQLite (§5), so wiping the copies in memory would protect nothing. |

None of the four weakens the forward secrecy claim above. That claim is about
keys that could decrypt a *recording*, and those keys (the ephemeral X25519
keys, `ss`, the session keys) are all zeroized.

---

## 7. What identity key theft does and does not allow

An attacker holding your `identity.key`:

**Can**

- Impersonate you to anyone who has your invite, from now on. They complete the
  handshake correctly; the fingerprint they present is *yours*, so out-of-band
  verification does not help.
- Sign invite blobs in your name and distribute them.
- Accept connections as you, if they can also be reached at an address your
  peers dial.
- Read anything sent to them going forward.

**Cannot**

- Decrypt recorded past sessions. The session keys came from ephemeral X25519
  keys that were destroyed, and are not recoverable from the identity key —
  §6. This is the one thing the design does buy here.
- Read your local history without also reading your disk. (Though in practice
  the attacker who got one file usually got the other — see §5.)
- Be detected and revoked. There is no revocation, no rotation and no recovery
  (`project.md` §3). The only remedy is to generate a new identity, which is a
  new user ID, and re-exchange invites with every peer out of band.

The inverse case — your peer's key is stolen — is symmetric, and F-03 does not
help: the thief has the *same* key, so nothing looks different.

---

## 8. Presence: both peers must be online

There is no store-and-forward, no queueing at a third party, no offline
delivery of any kind. A message can only be sent while both nodes are running
and connected to each other.

- A message composed while the peer is down is held **locally**, marked
  pending, and sent on reconnection (F-18, F-20). It has not left your machine.
- If the peer never comes back, it never sends.
- Closing your terminal ends your availability. There is no daemon.

The security consequence is small and the usability consequence is large; it is
listed here because "why did my message not arrive" has a security-shaped
answer often enough to be worth stating plainly.

---

## 9. Reachability and CGNAT

Direct connection means somebody has to be dialable.

Since M9d, **only the invite's owner must be reachable**. The requester dials
out, so a peer behind carrier-grade NAT — most Indian home broadband, and all
mobile data — can connect *to* an invite's owner and hold a full session.

What CGNAT still blocks is *being* the owner. A node nobody can reach cannot
hand out a usable invite: `--addr` names the address peers dial, the process
cannot work it out for itself behind NAT, and an invite advertising `0.0.0.0`
is refused rather than emitted (F-04). If **both** ends are behind CGNAT they
cannot meet at all. There is no hole punching, no rendezvous server and no
relay, and all three are explicit non-goals.

The workaround is a VPS, a LAN, or a forwarded port.

This is not a security property, but it shapes one: the party who must be
reachable is the party whose address is public, and §4's observer sees every
connection made to it.

---

## 10. Known weaknesses that are accepted rather than solved

Collected so that nothing above reads as an accident:

| Weakness | Why it is accepted |
|---|---|
| Hand-rolled handshake rather than Noise XX | The point of the project is to build one. `plan.md` "After V0.1" replaces it with `snow` and compares. |
| The private advertised address is handed out to anyone who asks `CONNECTION_STATUS` | §10's access control, not obscurity, keeps unaccepted peers out. `architecture.md` §3 argues this at length. |
| The QUIC certificate is accepted unconditionally | It is a transport artefact with no identity meaning; authentication is the inner handshake. This is only correct *because* of the channel binding. |
| No rate limiting on the public node | A denial-of-service concern, not a confidentiality one, and out of scope for V0.1. |
| No padding, no cover traffic | See §4. Explicit non-goal. |
| Display names are unauthenticated | They are advisory. The fingerprint identifies a peer; the UI never shows a name without one. |

---

## 11. Where this is enforced

The properties in §2 are load-bearing on a small number of specific lines, and
`architecture.md` §12 lists the slips that would silently remove each of them.
That list is a review checklist, not prose — if you are auditing this, start
there.
