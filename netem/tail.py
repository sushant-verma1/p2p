"""Many samples of the tight timeouts under one profile — see README.md.

    python tail.py PROFILE [--requests N] [--handshakes N] [--dials N]

requests    connection requests to a reachable public node; time to answer
handshakes  bob restarts and redials an accepted alice; connect/§6 split
dials       `connect` to a port where nothing answers; the error text
"""
import argparse, json
from wan import A, B, PROFILES, Node, containers, ip, log, netem, phase_split, ping, stats, docker

ap = argparse.ArgumentParser()
ap.add_argument("profile", choices=PROFILES)
ap.add_argument("--requests", type=int, default=100)
ap.add_argument("--handshakes", type=int, default=100)
ap.add_argument("--dials", type=int, default=0)
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
for i in range(args.handshakes):
    bob.quit()
    bob = Node(B, ["node", "--name", "bob"])
    got = bob.wait(lambda l: l.startswith("event\tsession"), 180)
    if not got:
        hs.append({"ok": False})
        log("hs", i, "NO SESSION")
        continue
    s = phase_split(bob.since(0), got[0]) or {}
    s["ok"] = True
    s["dial_failed"] = [l[:120] for _, l in bob.since(0) if "dial-failed" in l]
    hs.append(s)
    if s["dial_failed"] or (s.get("handshake") or 0) > 8:
        log("hs", i, {k: v for k, v in s.items()})
if hs:
    R["handshake"] = {"n": len(hs), "failed": sum(1 for s in hs if not s["ok"]),
                      "retried": sum(1 for s in hs if s.get("dial_failed")),
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

alice.quit()
bob.quit()
netem(None)
for c in (A, B):
    docker("rm", "-f", c)
with open(f"tail-{name}.json", "w", encoding="utf-8") as f:
    json.dump(R, f, indent=1)
