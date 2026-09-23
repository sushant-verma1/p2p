# techstack.md — V0.1

Rust 2021 edition, MSRV 1.88, pinned in `rust-toolchain.toml`. Cargo workspace, six members.

The MSRV was 1.75 during design. It moved because the patched `time` (≥ 0.3.47, which clears RUSTSEC-2026-0009) declares `rust-version = 1.88`, and `tracing-appender` depends on `time` unconditionally. A clean `cargo audit` is `project.md` §6 criterion 5; nothing here is consumed as a library, so the MSRV was the cheaper of the two to move. No advisory is ignored.

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

Both are taken with `default-features = false`. `rustls` 0.23 defaults to `aws-lc-rs`, which wants `cmake` and `nasm`; `ring` is the choice here and `p2pchat-net::crypto_provider` is where it is named, so no dependency's feature flags can quietly change it. Dropping `quinn`'s `platform-verifier` drops a web-PKI trust store this project has no use for — `architecture.md` §3 explains why there is no PKI here at all.

`tokio`'s `io-util` and `process` features are enabled only in `p2pchat-net`'s dev-dependencies, for the two-process transport test. The library itself needs neither.

**A C compiler is required from M3 on.** `ring` builds C and assembly. Linux and macOS have one; on Windows the `x86_64-pc-windows-gnu` toolchain does not ship `gcc`, and the workspace does not build there without one. Building in a `rust` container is the practical route on such a machine; CI runs on Linux regardless.

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
| `ratatui` | 0.30 | Widgets, layout, rendering |
| `crossterm` | 0.29 | Terminal backend, events, raw mode |
| `ratatui-textarea` | 0.9 | Multi-line input with editing. Saves writing a text editor |
| `unicode-width` | 0.2 | Display width of a char, for wrapping and truncation |

`unicode-width` is already in the tree under `ratatui`, which is why the version tracks `ratatui`'s rather than being picked freshly — two copies of it would disagree about how wide an emoji is, and the wrapping would not match the renderer. A column is not a char: an emoji is two and a combining mark is none, and counting chars wraps a message over the pane border.

`crossterm`'s version must match what `ratatui` expects, or two incompatible `Event` types end up in scope. Let `ratatui` choose it via its `crossterm` feature rather than pinning independently. `cargo tree -d` is the check: one `ratatui`, one `crossterm`.

`ratatui-textarea` is the ratatui project's fork of `tui-textarea`, taken in M9b because the original pins `ratatui` 0.29 and would have held the whole tree there. The API is the same bar the crate name in the import. Beware: an unrelated abandoned crate squats the same name at 0.4.x — the one meant here has `repository = "https://github.com/ratatui/ratatui-textarea"`.

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

### Environment overrides

Every path and port has an environment override. This is not a convenience: from M3 onward the integration tests run two nodes on one machine, which is impossible if the config paths and ports are fixed. `directories` resolves platform paths that no environment variable reaches, so the override has to be ours.

| Variable | Overrides | Default |
|---|---|---|
| `P2PCHAT_CONFIG_DIR` | Config directory, holding `identity.key` | `~/.config/p2pchat` |
| `P2PCHAT_DATA_DIR` | Data directory, holding the log and the database | `~/.local/share/p2pchat` |
| `P2PCHAT_PUBLIC_PORT` | Public node UDP port | 47100 |
| `P2PCHAT_PRIVATE_PORT` | Private node UDP port | 47101 |
| `P2PCHAT_BIND_ADDR` | IP both endpoints bind to. Not what invites advertise — that is `--addr` | `0.0.0.0` |
| `P2PCHAT_ADDR` | Public node addresses to advertise, comma-separated. `--addr`, and `addr` in `config.toml` | none; an invite without one is refused |
| `P2PCHAT_PRIVATE_ADDR` | Where an accepted requester is told to dial. `--private-addr`, and `private_addr` in `config.toml` | `P2PCHAT_ADDR`'s host with the private port |
| `RUST_LOG` | Log level | `info` |

The last two are also the only values in `config.toml`, read from the config directory. They are there because they are the only settings this process cannot work out for itself — an address reachable from outside is a fact about a network, not about a host — and retyping them at every launch is how a node ends up started without one. Precedence is the same as everywhere else: environment, then flag, then file. A malformed `config.toml` is logged and ignored rather than fatal; a stale config file should not be the reason a node will not start.

**Logs go to a file, never to stdout or stderr.** The TUI owns the terminal; a log line written to stdout corrupts the display. Set this up in M0, before the TUI exists, or the first hour of M9 is spent debugging a scrambled screen. Default path `~/.local/share/p2pchat/p2pchat.log`, daily rotation.

## Dev and CI

| Crate | Role |
|---|---|
| `criterion` | Benchmarks for handshake and AEAD throughput |
| `proptest` | Property tests for wire round-trips and sequence handling |
| `tempfile` | Throwaway databases in tests |
| `tokio-test` | Async test helpers |
| `rexpect` | A pty, for M9's gate 9. Unix only; the tests using it are `#![cfg(unix)]` |

`rexpect` was taken for gate 9 because a `TestBackend` has no line discipline and no terminal, so it cannot say whether raw mode was turned off — only a pty can, and `stty` is what reads it. Unix only, which is where CI runs; `portable-pty` is the fallback if `rexpect` ever fails `cargo deny`.

Required in CI: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo audit`, `cargo deny check`.

---

## Rejected alternatives

**Ignoring the advisories instead of upgrading (M9b).** `ratatui` 0.29 dragged in `paste` (RUSTSEC-2024-0436, unmaintained) and `lru` 0.12 (RUSTSEC-2026-0002 and RUSTSEC-2026-0253). Adding three entries to `deny.toml`'s `ignore` list would have been one line each and would have made the list mean "these are fine", which none of them are. Upgrading to `ratatui` 0.30 dropped `paste` and moved `lru` to 0.18, clearing all three with no waiver. `ignore` stays empty. `Zlib` was added to the licence *allow* list for `foldhash`, which is a different kind of entry: a permissive licence being recognised, not a vulnerability being tolerated.

Recorded so these are not relitigated at 2am.

**RSA (`rsa` crate).** The original spec's choice. Rejected because the crate carries RUSTSEC-2023-0071, an unfixed timing side-channel in decryption, which would sit permanently in `cargo audit` output on a project whose entire point is security. Also: multi-second keygen, 512-byte signatures, and 550-byte public keys that would push the invite blob past comfortable paste length. Ed25519 signatures are 64 bytes and keys are 32.

**AES-256-GCM.** Fine primitive. ChaCha20-Poly1305 chosen instead because it is constant-time in software without AES-NI, keeps the whole crypto stack in pure-Rust audited crates, and has a more forgiving nonce story. No practical downside here.

**`snow` (Noise framework).** Would implement the handshake correctly and in about twenty lines. Rejected because implementing the handshake is the main thing being learned. Worth reading its source as a reference; worth revisiting for V0.2 if the hand-rolled version proves fragile.

**`libp2p`.** Implements roughly 70% of this specification, including peer IDs as public key hashes, Noise sessions, and NAT traversal. Same objection as `snow`, larger. Genuinely the right answer for a product; wrong for this project.

**Raw TCP.** Would mean writing the reliability layer by hand. QUIC was chosen instead, which means TLS 1.3 sits underneath the custom handshake. This is redundancy, and it is a fair criticism of the stack — the channel binding in `architecture.md` §3 turns the redundancy into an asset by using the outer session to prevent relay attacks on the inner one, but it remains true that a TCP build would have taught more about reliability and less about nothing.

**`sled`.** Pure Rust, no C compilation. Rejected because the query patterns are relational (ordering by sequence within a conversation, uniqueness constraints) and SQLite does that natively. `sled` is also still pre-1.0.

**JSON or CBOR on the wire.** Rejected because the transcript hash requires byte-deterministic serialization. `serde_json` does not guarantee key ordering across versions, and CBOR has multiple valid encodings for the same integer. `postcard` has exactly one encoding per value.

**`std::collections::HashMap` keyed by user ID in hot paths.** Use `BTreeMap` or a `HashMap` with a fixed-seed hasher. IDs are attacker-influenced (anyone can generate a key until their ID collides in a bucket), which is a HashDoS vector. Minor, but free to avoid.
