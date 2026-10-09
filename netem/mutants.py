"""M16's mutants: one edit each to a copy of the source, built into
/target/bin/p2pchat-<name>. The source mount is never written to.

    docker run --rm -v "$PWD:/p2p:ro" -v p2p-target:/target -v p2p-cargo:/usr/local/cargo/registry \
        p2p-wan python3 /p2p/netem/mutants.py [NAME ...]

Each edit must match exactly once, so a mutant cannot silently build as the
original after the code it targets has moved. `serial` is not here: it is
alpha = 1, which is a parameter (P2PCHAT_DHT_ALPHA=1) rather than an edit.
"""
import os, shutil, subprocess, sys

DHT = "crates/p2pchat-net/src/dht.rs"
PUBLIC = "crates/p2pchat-net/src/public.rs"
NODE = "crates/p2pchat/src/node.rs"
RECORD = "crates/p2pchat-crypto/src/record.rs"

MUTANTS = {
    # XOR replaced with |a - b| as 256-bit numbers. Used for bucket placement
    # and for every ordering, as XOR was.
    "numeric": (DHT, """    let mut out = [0u8; 32];
    for (o, (x, y)) in out.iter_mut().zip(a.as_bytes().iter().zip(b.as_bytes())) {
        *o = x ^ y;
    }
    out
}""", """    let (a, b) = if a.as_bytes() >= b.as_bytes() {
        (a.as_bytes(), b.as_bytes())
    } else {
        (b.as_bytes(), a.as_bytes())
    };
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = a[i] as i16 - b[i] as i16 - borrow;
        borrow = (d < 0) as i16;
        out[i] = d.rem_euclid(256) as u8;
    }
    out
}"""),
    # Eviction never fires: the one function every eviction goes through.
    "noevict": (DHT, """        let entries = &mut self.buckets[b].entries;
        let before = entries.len();
        entries.retain(|e| e.contact.id != *id);
        entries.len() < before
    }""", """        let _ = b;
        false
    }"""),
    # A STORE is kept without the M15 checks.
    "noverify": (DHT, "if let Err(error) = record::supersedes(&record, self.held.get(&key), now) {",
                 "if let Err(error) = Ok::<(), p2pchat_crypto::CryptoError>(()) {"),
    # A client announces itself as a member, so members add it.
    "clientjoins": (DHT, "from: self.member().map(|port| Member { id: self.me, port }),",
                    "from: Some(Member { id: self.me, port: self.member().unwrap_or(47100) }),"),
    # Not a mutant: an instrument. Both allowances lifted, so that
    # `dht.py demand` sees what the DHT asks for rather than what the limiter
    # let through - M16a, the way M14a lifted the dial-back timeout.
    "wide": [(PUBLIC, "            per_source: 10,\n", "            per_source: 1_000_000,\n"),
             (PUBLIC, "            forward_per_member: 30,\n", "            forward_per_member: 1_000_000,\n")],
    # M17. Each mutant names the publish-harness gate that must reject it.
    "m17-republish-never-fires": (
        NODE,
        "        tokio::select! {\n            () = tokio::time::sleep(wait) => {}\n            () = node.republish.notified() => {}\n        }\n",
        "        return;\n",
    ),
    "m17-noexpiry": (RECORD, "if now > body.expires_at {", "if false {"),
    "m17-unreachable": (
        NODE,
        "            return Diagnosis::Stale {\n                newer: newer.body.addrs.clone(),\n                seq: newer.body.seq,\n            }\n",
        "            return Diagnosis::Unreachable {\n                age: now.saturating_sub(dialled.body.published_at),\n            }\n",
    ),
    "m17-dht-bypass": (
        NODE,
        "let dht = (!config.bootstrap.is_empty()).then(|| {",
        "let dht = false.then(|| {",
    ),
    # M17a: restore the old ordering by making the competing newer-record
    # lookup finish before it asks.  The next command can still succeed, but
    # gate 2 sees the stale dial in front of it and must fail.
    "m17-lookup-after-dial": (
        NODE,
        "            Instant::now() + dial_timeout(),",
        "            Instant::now(), // mutant: do not look while the stale dial runs",
    ),
    # M17a: a capped five-second cadence is part of the redial bound.  The
    # focused cadence gate catches a change even if one loopback run happens
    # to find the record on its very first probe.
    "m17-retry-interval-doubled": (
        NODE,
        "const NEWER_RECORD_POLL_MAX: Duration = Duration::from_secs(1);",
        "const NEWER_RECORD_POLL_MAX: Duration = Duration::from_secs(10);",
    ),
    # M17a: a new cadence tick must not kill a lookup that is traversing stale
    # replicas. This deliberately aborts the just-started probe too: every
    # redial lookup is in flight when the erroneous abort happens, so the
    # redial gate must fail rather than accidentally passing on timing.
    "m17-probe-aborts-lookup": (
        NODE,
        "                (this_attempt, rpcs, value)\n            });",
        "                (this_attempt, rpcs, value)\n            });\n            lookups.abort_all(); // mutant: a new probe aborts in-flight lookup",
    ),
    # M17a: without a refusal bit on the wire, treating the close as death
    # sends the confirming Ping in the same rate window and lets a flood evict
    # a live member.  The focused Rust rate-refusal gate must reject this.
    "m17-refusal-counted-as-death": (
        DHT,
        "            entry\n                .confirm_after\n                .get_or_insert(now + confirming_ping_delay(rate_window));",
        "            entry.confirm_after = Some(now); // mutant: refusal is death",
    ),
    "m17-refusal-as-empty-result": (
        NODE,
        "    found.failed_rpcs != 0\n",
        "    false // mutant: a refusal is treated as an empty result\n",
    ),
}

RUST_GATES = {
    "m17-lookup-after-dial": [
        "cargo", "test", "-q", "-p", "p2pchat", "--test", "lookup",
        "m17_gates_on_loopback", "--", "--nocapture",
    ],
    "m17-refusal-counted-as-death": [
        "cargo", "test", "-q", "-p", "p2pchat-net",
        "rate_limited_refusal_does_not_evict_on_the_second_strike",
    ],
    "m17-retry-interval-doubled": [
        "cargo", "test", "-q", "-p", "p2pchat",
        "newer_record_retries_cap_at_five_seconds",
    ],
    "m17-probe-aborts-lookup": [
        "cargo", "test", "-q", "-p", "p2pchat", "--test", "lookup",
        "m17_gates_on_loopback", "--", "--nocapture",
    ],
    "m17-refusal-as-empty-result": [
        "cargo", "test", "-q", "-p", "p2pchat",
        "a_refused_newer_record_lookup_is_not_an_empty_result",
    ],
}


def build(name):
    edits = MUTANTS[name]
    src = f"/tmp/mutant-{name}"
    shutil.rmtree(src, ignore_errors=True)
    # `shutil.copy`, not the default `copy2`: fresh mtimes, so cargo cannot
    # take a stale build from the shared target directory for this one.
    shutil.copytree("/p2p", src, ignore=shutil.ignore_patterns("target", ".git"),
                    copy_function=shutil.copy)
    for path, old, new in [edits] if isinstance(edits, tuple) else edits:
        with open(os.path.join(src, path), encoding="utf-8") as f:
            text = f.read()
        if text.count(old) != 1:
            sys.exit(f"{name}: the edit matches {text.count(old)} times in {path}")
        with open(os.path.join(src, path), "w", encoding="utf-8") as f:
            f.write(text.replace(old, new))
    env = dict(os.environ, CARGO_TARGET_DIR="/target/mutants")
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "p2pchat"], cwd=src, env=env, check=True)
    if name in RUST_GATES:
        # Focused gates keep the two M17a ordering properties independently
        # falsifiable: the loopback integration gate for stale-dial ordering,
        # and the routing-table assertion for refusal confirmation timing.
        checked = subprocess.run(RUST_GATES[name], cwd=src, env=env)
        if checked.returncode == 0:
            sys.exit(f"{name}: focused Rust gate passed; mutation escaped")
        print(f"{name}: rejected by focused Rust gate", flush=True)
    os.makedirs("/target/bin", exist_ok=True)
    shutil.copy("/target/mutants/release/p2pchat", f"/target/bin/p2pchat-{name}")
    print(f"built /target/bin/p2pchat-{name}", flush=True)


if __name__ == "__main__":
    shutil.rmtree("/target/mutants", ignore_errors=True)
    for name in sys.argv[1:] or list(MUTANTS):
        build(name)
