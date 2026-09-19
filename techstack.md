# techstack.md — V0.1

Rust 2021 edition, MSRV 1.75. Cargo workspace, six members.

Versions below are the majors to pin in `Cargo.toml`. Do not add a dependency that is not listed here without recording the reason in this file.

---

## Core

| Crate | Version | Role |
|---|---|---|
| `tokio` | 1 | Async runtime. Features: `rt-multi-thread`, `macros`, `sync`, `time`, `fs`, `signal` |
| `quinn` | 0.11 | QUIC transport |
| `rustls` | 0.23 | Required by quinn. Used with `ring` backend |
| `rcgen` | 0.13 | Self-signed certificate for the QUIC layer |

`quinn` pulls `rustls` in transitively; pin it explicitly anyway, because a version skew between them produces type errors that are hard to read.

## Cryptography

| Crate | Version | Role |
|---|---|---|
| `ed25519-dalek` | 2 | Identity signatures. Features: `rand_core`, `zeroize` |
| `x25519-dalek` | 2 | Ephemeral key agreement. Features: `reusable_secrets`, `zeroize` |
| `chacha20poly1305` | 0.10 | Message AEAD |
| `blake3` | 1 | User IDs, transcript hash, conversation IDs |
| `hkdf` | 0.12 | Session key derivation |
| `sha2` | 0.10 | HKDF's hash |
| `zeroize` | 1 | Wiping key material. Feature: `zeroize_derive` |
| `rand` | 0.8 | `OsRng` only |
| `argon2` | 0.5 | Passphrase KDF, if OD-1/OD-2 require it |
| `subtle` | 2 | Constant-time comparison of IDs and tags |

Version note: `ed25519-dalek` 2.x and `rand` 0.8 are compatible; `rand` 0.9 is not, because `RngCore` moved. Keep `rand` at 0.8 until dalek 3 ships.

## Storage

| Crate | Version | Role |
|---|---|---|
| `rusqlite` | 0.32 | SQLite. Features: `bundled`, `blob` |
| `uuid` | 1 | UUIDv7 message IDs. Features: `v7`, `serde` |

`bundled` compiles SQLite from source, so there is no system dependency and the build works identically on every machine. Costs about 30 seconds on a clean build.

## Serialization

| Crate | Version | Role |
|---|---|---|
| `serde` | 1 | Derive only. Feature: `derive` |
| `postcard` | 1 | Wire format. Feature: `use-std` |
| `base64` | 0.22 | Invite blob encoding |
| `toml` | 0.8 | Config file |

## Terminal UI

| Crate | Version | Role |
|---|---|---|
| `ratatui` | 0.29 | Widgets, layout, rendering |
| `crossterm` | 0.28 | Terminal backend, events, raw mode |
| `tui-textarea` | 0.7 | Multi-line input with editing. Saves writing a text editor |

`crossterm`'s version must match what `ratatui` expects, or two incompatible `Event` types end up in scope. Let `ratatui` choose it via its `crossterm` feature rather than pinning independently.

## Operational

| Crate | Version | Role |
|---|---|---|
| `tracing` | 0.1 | Structured logging |
| `tracing-subscriber` | 0.3 | Features: `env-filter`, `fmt` |
| `tracing-appender` | 0.2 | Non-blocking file writer |
| `thiserror` | 2 | Error types in library crates |
| `anyhow` | 1 | Error handling in the binary only |
| `clap` | 4 | CLI. Feature: `derive` |
| `directories` | 5 | Platform config and data paths |

**Logs go to a file, never to stdout or stderr.** The TUI owns the terminal; a log line written to stdout corrupts the display. Set this up in M0, before the TUI exists, or the first hour of M9 is spent debugging a scrambled screen. Default path `~/.local/share/p2pchat/p2pchat.log`, daily rotation.

## Dev and CI

| Crate | Role |
|---|---|
| `criterion` | Benchmarks for handshake and AEAD throughput |
| `proptest` | Property tests for wire round-trips and sequence handling |
| `tempfile` | Throwaway databases in tests |
| `tokio-test` | Async test helpers |

Required in CI: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo audit`, `cargo deny check`.

---

## Rejected alternatives

Recorded so these are not relitigated at 2am.

**RSA (`rsa` crate).** The original spec's choice. Rejected because the crate carries RUSTSEC-2023-0071, an unfixed timing side-channel in decryption, which would sit permanently in `cargo audit` output on a project whose entire point is security. Also: multi-second keygen, 512-byte signatures, and 550-byte public keys that would push the invite blob past comfortable paste length. Ed25519 signatures are 64 bytes and keys are 32.

**AES-256-GCM.** Fine primitive. ChaCha20-Poly1305 chosen instead because it is constant-time in software without AES-NI, keeps the whole crypto stack in pure-Rust audited crates, and has a more forgiving nonce story. No practical downside here.

**`snow` (Noise framework).** Would implement the handshake correctly and in about twenty lines. Rejected because implementing the handshake is the main thing being learned. Worth reading its source as a reference; worth revisiting for V0.2 if the hand-rolled version proves fragile.

**`libp2p`.** Implements roughly 70% of this specification, including peer IDs as public key hashes, Noise sessions, and NAT traversal. Same objection as `snow`, larger. Genuinely the right answer for a product; wrong for this project.

**Raw TCP.** Would mean writing the reliability layer by hand. QUIC was chosen instead, which means TLS 1.3 sits underneath the custom handshake. This is redundancy, and it is a fair criticism of the stack — the channel binding in `architecture.md` §3 turns the redundancy into an asset by using the outer session to prevent relay attacks on the inner one, but it remains true that a TCP build would have taught more about reliability and less about nothing.

**`sled`.** Pure Rust, no C compilation. Rejected because the query patterns are relational (ordering by sequence within a conversation, uniqueness constraints) and SQLite does that natively. `sled` is also still pre-1.0.

**JSON or CBOR on the wire.** Rejected because the transcript hash requires byte-deterministic serialization. `serde_json` does not guarantee key ordering across versions, and CBOR has multiple valid encodings for the same integer. `postcard` has exactly one encoding per value.

**`std::collections::HashMap` keyed by user ID in hot paths.** Use `BTreeMap` or a `HashMap` with a fixed-seed hasher. IDs are attacker-influenced (anyone can generate a key until their ID collides in a bucket), which is a HashDoS vector. Minor, but free to avoid.
