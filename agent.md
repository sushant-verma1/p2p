# agent.md

Instructions for an AI coding agent working in this repository. Read this before writing code, and re-read §3 before touching anything under `p2pchat-crypto`.

---

## 1. Orientation

Read in this order:

1. `project.md` — what this is, what it deliberately is not
2. `architecture.md` — normative protocol specification
3. `plan.md` — which milestone is current and what its gate is
4. `feature.md` — acceptance criteria for the feature being built

Work one milestone at a time, in the order given in `plan.md`. Do not start the next milestone until the current gate passes. Do not implement a feature from a later milestone because it seemed convenient while nearby.

**`architecture.md` is normative.** If an implementation detail contradicts it, the implementation is wrong — unless the document is actually mistaken, in which case say so, explain why, and update the document in the same change. Silent divergence is the failure mode this file exists to prevent.

---

## 2. Hard constraints

These are not style preferences.

- **Never implement a cryptographic primitive.** No hand-rolled hashes, ciphers, signature schemes, padding, or constant-time comparisons. Use the crates in `techstack.md`. If something appears to need a primitive that is not listed, stop and ask.
- **No `unsafe`.** `#![forbid(unsafe_code)]` at the top of every crate.
- **No `unwrap()`, `expect()`, or `panic!()` on any path that touches network input.** A remote peer that can panic the process has a denial of service. In tests, `unwrap()` is fine.
- **Never log key material, plaintext message bodies, or full user IDs.** Log fingerprints. There is a test that greps logs for known-secret patterns; do not weaken it.
- **Never add a dependency** that is not in `techstack.md`. Propose it, with a reason, and wait.
- **Never use `rand` in the message encryption path.** Nonces are derived from `frame_seq`. An RNG call there is a bug even if it appears to work.
- **Never write to stdout or stderr** outside the TUI's own rendering and the CLI subcommands whose whole job is printing — `whoami`, `invite`, `--version`. F-28 requires `invite` to be pipeable, so it prints to stdout and nothing else. Everywhere else, use `tracing`.
  - One exception: **a fatal startup error, before the TUI has taken the terminal, may go to stderr.** One line, then a non-zero exit. There is no display to corrupt yet, and the alternative is a binary that exits zero having done nothing — which is how the no-tty launch behaved until M9a. Log it as well; the terminal message is for whoever ran it, the log line is for whoever reads the log. This is not licence for progress messages: if the TUI is up, or the process is going to carry on, it goes to `tracing` and nowhere else.

---

## 3. Crypto invariants

Each of these can be broken while leaving code that compiles, passes the happy-path test, and is completely insecure. Verify each one explicitly whenever the handshake or session code is touched.

1. Both parties sign a transcript covering: domain separator, QUIC channel binding, both nonces, both ephemeral public keys. Never a value chosen only by the signer.
2. The channel binding is extracted from the QUIC connection and mixed into the transcript. Dropping it makes the handshake relayable and nothing visibly breaks.
3. `BLAKE3(domain || identity_pk) == user_id` is checked on every received handshake.
4. On outbound connections, the peer's user ID is compared against the expected one. Skipping this makes authentication meaningless — any peer can answer.
5. HKDF output is split into two directional keys. One key in both directions with a shared counter is nonce reuse.
6. The AEAD nonce is `[0u8; 4] ‖ frame_seq.to_be_bytes()`. Derived, never random.
7. `frame_seq` (transport, per-session, resets to 0) and `msg_seq` (application, per-conversation, persistent) are distinct. Confusing them causes nonce reuse.
8. Ephemeral secrets and the DH output are zeroized immediately after key derivation.
9. `SharedSecret::was_contributory()` is checked; small-order points are rejected.
10. Handshake failures return a generic error to the peer. Which check failed is an oracle — log it locally only.
11. The QUIC certificate is transport only. It is never identity.
12. The database never stores wire ciphertext.

If a change makes any of these harder to verify, that is a reason to reject the change.

---

## 4. Conventions

**Layout.** Dependencies flow downward: `core` ← `crypto` ← `net`, `core` ← `store`, `core` ← `tui`. Nothing depends on `tui`. Do not introduce an upward or lateral dependency to save a few lines; the layering is what keeps crypto testable without sockets.

**Errors.** `thiserror` enums in library crates, `anyhow` in the binary only. Never `Box<dyn Error>` in a public signature.

**Async.** Channels for cross-task communication, never a `Mutex` held across an `.await`. The SQLite connection is owned by one actor task; no pool, no `Arc<Mutex<Connection>>`.

**Naming.** Types matching `architecture.md` use its exact names — `HelloInit`, `HelloResp`, `HelloConfirm`, `frame_seq`, `msg_seq`. Divergence makes the document useless as a reference.

**Comments.** Explain why, not what. In crypto code, cite the section of `architecture.md` that a given step implements.

**Commits.** One logical change each. Reference the milestone: `M4: add transcript hashing to handshake`.

---

## 5. Testing

Every milestone gate is a test, except where `plan.md` says otherwise. A gate that cannot be expressed as a test is a gate that will be claimed rather than met.

- Unit tests next to the code.
- Integration tests in `tests/`, spawning real endpoints on loopback.
- Property tests for wire round-trips and sequence handling.
- **Negative tests are mandatory for anything security-relevant.** Every abort path in `architecture.md` §6 needs a test that proves it aborts. A handshake tested only on the happy path has been tested for nothing.

Before declaring a milestone done: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all`, `cargo audit`.

---

## 6. When to stop and ask

Ask rather than choose when:

- A decision would change the wire format or any signed structure.
- An open decision (OD-1, OD-2, OD-3 in `project.md`) blocks progress.
- A new dependency seems necessary.
- The specification is ambiguous, or appears to be wrong.
- A gate cannot be met without weakening its criterion.
- A feature is not in `feature.md`. It is either out of scope or an oversight, and guessing which is not the agent's call.

State the options and their consequences. Do not pick a default and mention it afterwards.

---

## 7. Failure modes specific to this project

Observed patterns worth naming, because each produces plausible-looking code:

- **Silently reintroducing random nonces** because a code example used them. The examples are for random-nonce constructions; this design is not one.
- **Dropping the channel binding** during a refactor. Everything still works. The relay test in M4 is the only thing that catches it.
- **Storing wire ciphertext** because it appears in the original specification's §19. It does not appear in `architecture.md` §8, deliberately, and doing it breaks resync after key rotation.
- **Treating the QUIC certificate as identity** because that is what TLS normally means. Here it means nothing.
- **Trusting `display_name` from an invite or profile.** It is attacker-controlled. Identity is the user ID and nothing else.
- **`println!` during TUI development.** It corrupts the display and the cause is not obvious. Use `tracing`.
- **Building the TUI early** because it is the visible part. It is scheduled at M9 for a reason.
