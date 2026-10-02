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
    "m17-norepublish-loop": (
        NODE,
        "        tokio::select! {\n            () = tokio::time::sleep(wait) => {}\n            () = node.republish.notified() => {}\n        }\n",
        "        return;\n",
    ),
    "m17-norepublish": (
        NODE,
        "            seq = session::now_ms().max(seq + 1);",
        "            seq = 1; // mutant: every later publication is non-newer.",
    ),
    "m17-noexpiry": (RECORD, "if now > body.expires_at {", "if false {"),
    "m17-unreachable": (
        NODE,
        "            return Diagnosis::Stale {\n                newer: newer.body.addrs.clone(),\n                seq: newer.body.seq,\n            }\n",
        "            return Diagnosis::Unreachable {\n                age: now.saturating_sub(dialled.body.published_at),\n            }\n",
    ),
    "m17-nodht": (
        NODE,
        "let dht = (!config.bootstrap.is_empty()).then(|| {",
        "let dht = false.then(|| {",
    ),
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
    os.makedirs("/target/bin", exist_ok=True)
    shutil.copy("/target/mutants/release/p2pchat", f"/target/bin/p2pchat-{name}")
    print(f"built /target/bin/p2pchat-{name}", flush=True)


if __name__ == "__main__":
    shutil.rmtree("/target/mutants", ignore_errors=True)
    for name in sys.argv[1:] or list(MUTANTS):
        build(name)
