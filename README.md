# p2pchat

A decentralized peer-to-peer terminal chat application, in Rust.

Every user runs their own node. There is no server: no account, no directory,
no relay, and nothing in the middle that stores or can read a conversation. Two
people exchange an invite blob out of band, connect directly over QUIC,
mutually authenticate their long-term identity keys, derive a forward-secret
session key, and exchange authenticated encrypted messages that are stored only
on their own two machines.

> **This is a learning project. It is not suitable for real communications
> security.** See [Honesty](#honesty) at the bottom, and `THREAT_MODEL.md` in
> full. If you need a messenger you can rely on, use Signal.

---

## What it is for

The point was to build the internals rather than call a library that has them:
a cryptographic handshake, a wire format, a session state machine, async
networking, and local durability. `project.md` §2 says it plainly — the value
is in the parts that were *not* delegated to a framework.

So: a real protocol, built carefully, with the negative tests that make
"carefully" mean something, and a threat model that says what it does not do.

---

## How it works, in one screen

```
Ed25519 identity key ──BLAKE3──▶ user_id (64 hex) ──▶ fingerprint (16 hex)
                                      │
                              signed invite blob
                                      │  out of band
                                      ▼
   public node  :47100  ── CONNECTION_REQUEST ─▶  the other user accepts
   private node :47101  ◀── QUIC + 3-message handshake ──
                                      │
                    ephemeral X25519 + transcript hash + QUIC channel binding
                                      │
                             HKDF ──▶ two directional ChaCha20-Poly1305 keys
                                      │
                              messages, ACKs, resync
                                      ▼
                             SQLite, on both machines
```

- **Identity** is an Ed25519 keypair. Your user ID is `BLAKE3(public key)`; the
  fingerprint people compare is its first 16 hex characters.
- **Two endpoints.** The *public* node answers profile lookups and connection
  requests and carries no conversation. The *private* node carries the
  conversation and authenticates both ends.
- **The handshake** is three messages. Each side signs a running transcript
  hash that covers the other side's nonce and 32 bytes exported from the QUIC
  TLS session, so a recorded handshake cannot be replayed and a man in the
  middle who terminates QUIC cannot relay one.
- **The record layer** derives two keys, one per direction, and uses the frame
  counter as the nonce. There is no RNG in the encrypt path and no
  attacker-chosen sequence number on the wire.
- **Nothing is negotiated that could be downgraded.** One version, one cipher
  suite, one hash.

`architecture.md` is the normative description. `THREAT_MODEL.md` is what it
does and does not buy you.

---

## Building

Rust 1.88 (pinned in `rust-toolchain.toml`). SQLite is compiled from source and
`ring` builds C and assembly, so a C toolchain is required — `build-essential`
on Debian/Ubuntu.

```sh
cargo build --release
cargo test --all
```

CI runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
`cargo audit` and `cargo deny check`. All five are expected to be clean;
`deny.toml`'s advisory ignore list is empty and is meant to stay that way.

---

## Running it

### 1. Find out who you are

```sh
p2pchat whoami
```

Prints your user ID and fingerprint, generating the identity on first run. The
key lands in `~/.config/p2pchat/identity.key`, mode `0600`.

### 2. Publish an invite

The node cannot work out what address a peer should dial — behind NAT, the
address a peer needs is not one this host holds at all — so you have to say:

```sh
p2pchat invite --addr 203.0.113.9:47100 --name alice
```

That prints one line beginning `p2pchat:v1:`. Send it to the other person over
any channel you like. **Then compare fingerprints with them over a different
channel** — see `THREAT_MODEL.md` §3 for why that sentence is the most
important one in this file.

### 3. Chat

```sh
p2pchat --addr 203.0.113.9:47100 --public-port 47100
```

Paste the other person's invite into the input box and press Enter: their
fingerprint is shown before anything connects. They see your connection request
under `Ctrl-R` and accept it. After that you have a conversation.

```
Tab / Shift-Tab    next / previous conversation
Enter              send      (Alt-Enter or Shift-Enter: newline)
PgUp / PgDn        scroll    (Home / End: the ends)
Ctrl-T             mark the selected peer verified
Ctrl-P             your own fingerprint and full user ID
Ctrl-R             connection requests: a accept, r reject
Ctrl-C             quit
?                  help, on an empty input. Esc closes.
```

### Other subcommands

| Command | Does |
|---|---|
| `p2pchat` | the TUI |
| `p2pchat whoami` | user ID and fingerprint |
| `p2pchat invite` | the invite blob alone, for piping |
| `p2pchat check` | binds the endpoints, prints bound and advertised addresses, flags what cannot work; takes the same flags as the chat |
| `p2pchat node` | a headless node driven line-by-line on stdin — the debug and test driver |
| `p2pchat history <user-id>` | the stored conversation, oldest first, from a node that need not be running |
| `p2pchat --version` | version |

### Where things live

| | Path (Linux) |
|---|---|
| Identity key | `~/.config/p2pchat/identity.key` (`0600`) |
| Database and log | `~/.local/share/p2pchat/` (`0600`) |

Both are overridable with `P2PCHAT_CONFIG_DIR` and `P2PCHAT_DATA_DIR`, which is
how two nodes run on one machine. `RUST_LOG` sets the log level. Logs never go
to the terminal — the TUI owns it.

## Deployment: a node on a VPS

Someone has to be reachable, and a home connection often cannot be. The usual
shape is the invite owner on a VPS and everyone else at home: the home side only
dials out, so it needs no open ports, no forwarding and no public address.

### On the VPS

```sh
p2pchat check --addr 198.51.100.7:47100 --public-port 47100 --private-port 47101
p2pchat       --addr 198.51.100.7:47100 --public-port 47100 --private-port 47101 --name alice
```

- **`--addr` is the provider's public IP** — the one shown in their console,
  or `curl -4 ifconfig.me`. Not `0.0.0.0`, which is a bind address and not
  somewhere to dial, and not the instance's own interface address: on most
  clouds (AWS, GCP, Azure) that is a `10.x`/`172.16.x` address the provider
  NATs, and a peer given it dials nowhere. Put it in
  `~/.config/p2pchat/config.toml` as `addr = ["198.51.100.7:47100"]` to stop
  retyping it.
- **`--private-port 47101`.** The default is 0, an OS-chosen port that changes
  every launch, so no firewall rule can name it. An accepted requester is told
  to dial `--addr`'s host on this port.
- **`--bind`** stays at its default, every interface. `--private-addr` is only
  for when the private endpoint is reachable somewhere other than `--addr`'s
  host on port 47101 — a router forwarding a different port, say.

### Open UDP 47100 and 47101 — UDP, not TCP

The transport is QUIC, which is UDP. **A TCP rule for these ports does nothing**,
and it is the most likely reason a correctly started node cannot be reached.
Both places need it, inbound:

```sh
# the host firewall
sudo ufw allow 47100/udp
sudo ufw allow 47101/udp
```

and the provider's firewall — the AWS security group, GCP VPC firewall rule,
Hetzner/DigitalOcean cloud firewall — with protocol set to **UDP**. 47100 is
the public endpoint (invites and connection requests); 47101 is the private one
(the session itself, and only after you accept).

### Before sharing the invite

`p2pchat check` with the chat's flags binds both endpoints the way the node
would and prints what it bound, what it advertises and which ports to open. It
exits non-zero and says why when the configuration cannot work: an advertised
address that is loopback, a private LAN address or carrier-grade NAT space, an
advertised port that is not the bound one, `--addr` without `--public-port`, or
a private port left to the OS. It cannot see whether the outside reaches this
host — nothing on the host can. That is what a peer's first connection tests.

### If it will not connect

A peer that cannot reach the owner's public endpoint waits 5 seconds (20 for
the private one, after acceptance) and gets, in the selected conversation:

```
! no answer from 198.51.100.7:47100 after 5s. An unreachable node and a wrong
  address look the same from here, so check: ...
```

From the dialling side an unreachable node and a wrong address are the same
silence, so the message lists what to check, in order:

1. **The address.** Is it what `p2pchat check` on the owner's machine prints
   as advertised? An invite made before the VPS's IP changed still carries the
   old one.
2. **UDP.** Are 47100 and 47101 open inbound as UDP in both the host firewall
   and the cloud firewall? A request that got an answer but whose session then
   timed out points at 47101 specifically.
3. **Carrier-grade NAT.** If the owner is at home: does their router's WAN
   address start with `100.64`–`100.127`, or differ from what
   `curl ifconfig.me` shows? Then their ISP shares one public address among
   many customers, no forwarding rule on their router can help, and nobody can
   reach them. Their node belongs on a VPS, a shared LAN or a connection with a
   forwarded port.

Two peers both behind CGNAT cannot connect at all. There is no hole punching,
no rendezvous server and no relay, by design (`project.md` §7).

---

## Layout

```
p2pchat (bin)        the composition root — the only crate that names all five
├── p2pchat-core     types, wire format, errors, IDs
├── p2pchat-crypto   identity, handshake, AEAD, KDF, keystore
├── p2pchat-net      QUIC endpoints, public node, private node, sessions
├── p2pchat-store    SQLite schema, migrations, repositories
└── p2pchat-tui      ratatui rendering and input
```

Dependencies run strictly downward and no library crate depends on the TUI,
which is what keeps the protocol testable without a terminal, a socket or a
database.

| Document | What it is |
|---|---|
| `project.md` | what this is, why, and what is out of scope |
| `architecture.md` | normative design. If the code disagrees, one of them is a bug |
| `feature.md` | every feature with its acceptance criteria |
| `plan.md` | the build order and each milestone's gate |
| `techstack.md` | every dependency and why it is there |
| `THREAT_MODEL.md` | what is protected and what is not |

---

## Honesty

This is a portfolio and learning project written by one person. It has not been
audited by anybody. The handshake is hand-rolled rather than a reviewed
construction like Noise — which was the point of building it, and is also
exactly why you should not trust it with anything that matters.

Concretely, and at more length in `THREAT_MODEL.md`:

- **Trust on first use.** Nothing verifies that an invite came from who it
  claims. A substituted invite is undetectable unless you compare fingerprints
  out of band, by hand.
- **No metadata protection.** An observer sees who talks to whom, when, and how
  much. The message header — including both user IDs — travels in the clear as
  the AEAD's associated data; only the body is encrypted.
- **No protection at rest.** The identity key and the whole message history are
  unencrypted on disk. On Windows the file permissions are not verified at all.
- **Forward secrecy is per session, not per message.** One key for a whole
  session; no ratchet, no rekeying.
- **Both peers must be online.** No store-and-forward, no offline delivery.
- **No key rotation, revocation or recovery.** A stolen identity key means a
  new identity and a fresh out-of-band exchange with every peer.

Use it to read, to learn from, or to argue with. Do not use it to say anything
you would mind an adversary reading.
