"""Many samples of the tight timeouts under one profile — see README.md.

    python tail.py PROFILE [--requests N] [--handshakes N] [--dials N] [--strand N]

requests    connection requests to a reachable public node; time to answer
handshakes  bob restarts and redials an accepted alice; connect/§6 split
dials       `connect` to a port where nothing answers; the error text
strand      the first dial after acceptance blocked by iptables, then unblocked
"""
import argparse, json, time
from wan import (A, B, PROFILES, Node, acceptor_settles, containers, ip, log, netem, phase_split,
                 ping, read_log, stats, docker)

ap = argparse.ArgumentParser()
ap.add_argument("profile", choices=PROFILES)
ap.add_argument("--requests", type=int, default=100)
ap.add_argument("--handshakes", type=int, default=100)
ap.add_argument("--dials", type=int, default=0)
ap.add_argument("--strand", type=int, default=0)
args = ap.parse_args()
name = args.profile

containers()
netem(PROFILES[name])
a_ip = ip(A)
R = {"profile": name, "netem": PROFILES[name], "ping": ping(ip(B), 2000)}
log(name, "ping", R["ping"])
alice_args = ["--addr", f"{a_ip}:47100", "node", "--public-port", "47100",
              "--private-port", "47101", "--name", "alice"]
alice = Node(A, alice_args)
bob = Node(B, ["node", "--name", "bob"])

req = []
for i in range(args.requests):
    if i and i % 5 == 0:  # the public node's limiter is 10 a minute, polls included
        alice.quit()
        alice = Node(A, alice_args)
    t, ans = bob.call(f"request {a_ip}:47100 {alice.me}", 60)
    req.append({"s": t, "ok": bool(ans and ans.startswith("ok")), "answer": (ans or "")[:60]})
    if not req[-1]["ok"]:
        log("request", i, t, ans[:60] if ans else None)
ok = [r["s"] for r in req if r["ok"]]
R["requests"] = {"n": len(req), "failed": len(req) - len(ok), "stats": stats(ok),
                 "sorted": sorted(round(s, 3) for s in ok),
                 "failures": [r for r in req if not r["ok"]]}
log("requests", R["requests"]["stats"], "failed", R["requests"]["failed"])

if args.handshakes:
    while not ok:  # acceptance needs a request on file
        t, ans = bob.call(f"request {a_ip}:47100 {alice.me}", 60)
        ok = ans and ans.startswith("ok")
    alice.cmd(f"accept {bob.me}")
hs = []
seen = len(read_log(B, r"reconnect failed|handshake failed")) if args.handshakes else 0
for i in range(args.handshakes):
    bob.quit()
    ma = alice.mark()
    bob = Node(B, ["node", "--name", "bob"])
    got = bob.wait(lambda l: l.startswith("event\tsession"), 180)
    if not got:
        hs.append({"ok": False})
        log("hs", i, "NO SESSION")
        continue
    s = phase_split(bob.since(0), got[0]) or {}
    s["ok"] = True
    s["dial_failed"] = [l[:120] for _, l in bob.since(0) if "dial-failed" in l]
    s["alice_session"] = acceptor_settles(alice, ma)
    # A restarted bob dials from the reconnect loop, which retries quietly: no
    # dial-failed event, only more phase events (4 per attempt) and a debug
    # line in its log. Keep that line, it is the only record of what failed.
    if s.get("phase_events", 4) > 4:
        failed = read_log(B, r"reconnect failed|handshake failed")
        s["retry_log"] = [l[:300] for l in failed[seen:]]
        seen = len(failed)
    hs.append(s)
    if s["dial_failed"] or s.get("retry_log") or (s.get("handshake") or 0) > 8:
        log("hs", i, {k: v for k, v in s.items()})
if hs:
    R["handshake"] = {"n": len(hs), "failed": sum(1 for s in hs if not s["ok"]),
                      "retried": sum(1 for s in hs if s.get("dial_failed") or s.get("retry_log") is not None),
                      "alice_missed": sum(1 for s in hs if s["ok"] and not s["alice_session"]),
                      "handshake": stats([s.get("handshake") for s in hs]),
                      "connect": stats([s.get("connect") for s in hs]),
                      "dial": stats([s.get("dial") for s in hs]),
                      "handshake_sorted": sorted(round(s["handshake"], 3) for s in hs if "handshake" in s),
                      "samples": hs}
    log("handshake", {k: v for k, v in R["handshake"].items() if k not in ("samples", "handshake_sorted")})

dials = []
for i in range(args.dials):
    t, ans = bob.call(f"connect {a_ip}:47198", 90)
    dials.append({"s": t, "guidance": bool(ans and "no answer from" in ans), "answer": (ans or "")[:90]})
    log("dial", i, round(t, 2) if t else None, dials[-1]["answer"])
if dials:
    R["dials"] = {"n": len(dials), "guidance": sum(d["guidance"] for d in dials), "samples": dials}

# M12c: alice's private port dropped for the first dial after acceptance, then
# reopened. Each trial starts from nothing, so the dial is a first dial.
BLOCK = ["INPUT", "-p", "udp", "--dport", "47101", "-j", "DROP"]
strand = []
for i in range(args.strand):
    alice.quit()
    bob.quit()
    for c in (A, B):
        docker("exec", c, "sh", "-c", "pkill -9 -x p2pchat; rm -rf /data")
    alice = Node(A, alice_args)
    bob = Node(B, ["node", "--name", "bob"])
    docker("exec", A, "iptables", "-A", *BLOCK, check=True)
    t, ans = None, None
    while not (ans and ans.startswith("ok")):
        t, ans = bob.call(f"request {a_ip}:47100 {alice.me}", 60)
    mb = bob.mark()
    t_acc = alice.cmd(f"accept {bob.me}")
    failed = bob.wait(lambda l: l.startswith(("event\tdial-failed", "event\tsession")), 120, mb)
    t_open = time.perf_counter()
    docker("exec", A, "iptables", "-D", *BLOCK, check=True)
    got = bob.wait(lambda l: l.startswith("event\tsession"), 300, mb)
    s = {"first_dial_failed": bool(failed and "dial-failed" in failed[1]),
         "accept_to_first_failure": failed and round(failed[0] - t_acc, 2),
         "session": bool(got), "reopen_to_session": got and round(got[0] - t_open, 2),
         "dial_failures": sum(1 for _, l in bob.since(mb) if l.startswith("event\tdial-failed")),
         "first_failure": failed and failed[1][:100]}
    strand.append(s)
    log("strand", i, s)
if strand:
    R["strand"] = {"n": len(strand), "sessions": sum(s["session"] for s in strand),
                   "first_dial_failed": sum(s["first_dial_failed"] for s in strand),
                   "reopen_to_session": stats([s["reopen_to_session"] for s in strand]),
                   "samples": strand}
    log("strand", {k: v for k, v in R["strand"].items() if k != "samples"})

# Before the containers go: the logs are the only place a quiet failure shows.
R["warnings"] = {c: read_log(c, r" (WARN|ERROR) ") for c in (A, B)}
log("warnings", {c: len(v) for c, v in R["warnings"].items()})
alice.quit()
bob.quit()
netem(None)
for c in (A, B):
    docker("rm", "-f", c)
with open(f"tail-{name}.json", "w", encoding="utf-8") as f:
    json.dump(R, f, indent=1)
