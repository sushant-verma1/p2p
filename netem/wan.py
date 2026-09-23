"""The debug node under tc netem, in two containers — see README.md.

Driven from the host through `docker exec -i` pipes, so every timestamp is the
host's monotonic clock on the line's arrival. Pipe overhead is a few ms.
"""
import json, os, re, subprocess, sys, threading, time
from datetime import datetime

# WAN_PAIR names the container pair, so two profiles can run side by side.
PAIR = os.environ.get("WAN_PAIR", "wan")
A, B, NET = f"{PAIR}-alice", f"{PAIR}-bob", PAIR
IMAGE = "p2p-wan"
BIN = os.environ.get("P2PCHAT_BIN", "/target/release/p2pchat")
# Applied to the egress of both containers, so the round trip is twice the delay.
PROFILES = {
    "baseline": None,
    "typical": "delay 60ms 20ms distribution normal loss 0.5%",
    "poor": "delay 150ms 50ms loss 3% reorder 1%",
    "bad": "delay 400ms loss 8%",
    # netem's loss correlation is broken: this measures ~1% per leg, not 8%.
    "bursty": "delay 400ms loss 8% 25%",
    # What "8%, 25% correlated" means, as a Gilbert-Elliott chain: 8% of packets
    # lost, P(loss | loss) = 0.25 + 0.75 * 0.08 = 31%, so bursts average 1.45.
    "bursty-ge": "delay 400ms loss gemodel 6% 69% 100% 0%",
}
# Every other P2PCHAT_* on the host (timeout overrides) reaches the nodes too.
ENV = {"P2PCHAT_CONFIG_DIR": "/data/cfg", "P2PCHAT_DATA_DIR": "/data/data",
       "RUST_LOG": "info,p2pchat=debug,p2pchat_net=debug",
       **{k: v for k, v in os.environ.items() if k.startswith("P2PCHAT_") and k != "P2PCHAT_BIN"}}
HS_SAMPLES = 30
REQ_SAMPLES = 12


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def docker(*args, check=False):
    r = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8")
    if check and r.returncode:
        raise RuntimeError(f"docker {args}: {r.stderr}")
    return r.stdout


class Node:
    def __init__(self, ctr, args, extra_env=None):
        env = dict(ENV, **(extra_env or {}))
        flags = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
        self.ctr = ctr
        self.p = subprocess.Popen(["docker", "exec", "-i", *flags, ctr, BIN, *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                  bufsize=1)
        self.lines, self.cv = [], threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()
        got = self.wait(lambda l: l.startswith("ready"), 30)
        if not got:
            raise RuntimeError(f"{ctr} never became ready: {self.lines}")
        self.t_ready, line = got
        _, self.me, self.priv, self.pub, self.adv = line.split("\t")

    def _read(self):
        for line in self.p.stdout:
            t = time.perf_counter()
            with self.cv:
                self.lines.append((t, line.rstrip("\n")))
                self.cv.notify_all()

    def cmd(self, line):
        t = time.perf_counter()
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return t

    def mark(self):
        with self.cv:
            return len(self.lines)

    def wait(self, pred, timeout, since=0):
        deadline = time.perf_counter() + timeout
        i = since
        with self.cv:
            while True:
                while i < len(self.lines):
                    t, l = self.lines[i]
                    i += 1
                    if pred(l):
                        return t, l
                rem = deadline - time.perf_counter()
                if rem <= 0:
                    return None
                self.cv.wait(rem)

    def call(self, line, timeout=60):
        """A command and its ok/err answer: (seconds, answer line)."""
        verb = line.split()[0]
        m = self.mark()
        t0 = self.cmd(line)
        got = self.wait(lambda l: l.startswith(("ok\t" + verb, "err\t" + verb)), timeout, m)
        return (got[0] - t0, got[1]) if got else (None, None)

    def since(self, m):
        with self.cv:
            return list(self.lines[m:])

    def quit(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.kill()

    def kill(self):
        docker("exec", self.ctr, "pkill", "-9", "-x", "p2pchat")
        self.p.wait(10)


def netem(spec):
    for c in (A, B):
        docker("exec", c, "tc", "qdisc", "del", "dev", "eth0", "root")
        if spec:
            docker("exec", c, "tc", "qdisc", "add", "dev", "eth0", "root", "netem",
                   *spec.split(), check=True)


def ping(dst_ip, count=400):
    """Measured RTT, loss, how many replies came back out of order, and how
    lost round trips cluster: independent 8% loss averages ~1.1 per run."""
    out = docker("exec", A, "ping", "-c", str(count), "-i", "0.01", "-W", "3", dst_ip)
    seqs = [int(s) for s in re.findall(r"icmp_seq=(\d+)", out)]
    hi, inversions = -1, 0
    for s in seqs:
        if s < hi:
            inversions += 1
        hi = max(hi, s)
    got, runs, run = set(seqs), [], 0
    for s in range(1, count + 1):
        if s in got:
            if run:
                runs.append(run)
            run = 0
        else:
            run += 1
    if run:
        runs.append(run)
    summ = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    loss = re.search(r"([\d.]+)% packet loss", out)
    return {"replies": len(seqs), "loss_pct": float(loss.group(1)) if loss else None,
            "rtt_min_avg_max_mdev": [float(x) for x in summ.groups()] if summ else None,
            "replies_out_of_order": inversions,
            "loss_runs": len(runs), "loss_run_mean": round(sum(runs) / len(runs), 2) if runs else 0,
            "loss_run_max": max(runs, default=0)}


def phase_split(lines, t_session):
    """Connect and handshake durations of the dial that produced a session.

    A dial reports Connecting, then Handshaking once QUIC is up, and drops
    Handshaking when §6 finishes; each is an `event phase` line. The three
    phase events just before the session event are those three.
    """
    ph = [t for t, l in lines if l.startswith("event\tphase") and t <= t_session]
    if len(ph) < 3:
        return None
    c0, h0, h1 = ph[-3:]
    return {"connect": h1 - c0 - (h1 - h0), "handshake": h1 - h0, "dial": h1 - c0,
            "phase_events": len(ph)}


def pct(xs, p):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    return round(xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))], 3)


def stats(xs):
    xs = [x for x in xs if x is not None]
    return {"n": len(xs), "p50": pct(xs, 50), "p90": pct(xs, 90), "p99": pct(xs, 99),
            "max": round(max(xs), 3) if xs else None}


def read_log(ctr, pattern):
    out = docker("exec", ctr, "sh", "-c", "cat /data/data/p2pchat*.log")
    return [l for l in out.splitlines() if re.search(pattern, l)]


def ts(line):
    return datetime.fromisoformat(line.split()[0].replace("Z", "+00:00")).timestamp()


def run_profile(name, spec):
    R = {"profile": name, "netem": spec}
    for c in (A, B):
        docker("exec", c, "sh", "-c", "pkill -9 -x p2pchat; rm -rf /data")
    netem(spec)
    b_ip, a_ip = ip(B), ip(A)
    R["ping_alice_to_bob"] = ping(b_ip)
    log(name, "ping", R["ping_alice_to_bob"])

    alice_args = ["--addr", f"{a_ip}:47100", "node", "--public-port", "47100",
                  "--private-port", "47101", "--name", "alice"]
    alice = Node(A, alice_args)
    bob = Node(B, ["node", "--name", "bob"])
    pub, priv = f"{a_ip}:47100", f"{a_ip}:47101"

    # --- 2a: the connection request, against its 5 s -------------------------
    req = []
    for i in range(REQ_SAMPLES):
        t, ans = bob.call(f"request {pub} {alice.me}", 30)
        req.append({"s": t, "answer": ans})
        log(name, "request", i, t, ans)
        if i < REQ_SAMPLES - 1:
            time.sleep(12)  # the public node allows 10 per source per minute
    R["request"] = {"samples": req, "stats": stats([r["s"] for r in req if r["answer"] and r["answer"].startswith("ok")]),
                    "failed": sum(1 for r in req if not (r["answer"] or "").startswith("ok"))}

    # --- 2b: accept, the poller notices, the dial against its 20 s -----------
    mb = bob.mark()
    t_acc = alice.cmd(f"accept {bob.me}")
    got = bob.wait(lambda l: l.startswith("event\tsession"), 150, mb)
    first = {"accept_to_session": got and got[0] - t_acc}
    if got:
        first.update(phase_split(bob.since(mb), got[0]) or {})
    first["dial_failed"] = [l for _, l in bob.since(mb) if "dial-failed" in l]
    R["first_session"] = first
    log(name, "first session", first)

    # --- 1: handshake samples, one bob restart each --------------------------
    hs = []
    for i in range(HS_SAMPLES):
        bob.quit()
        bob = Node(B, ["node", "--name", "bob"])
        got = bob.wait(lambda l: l.startswith("event\tsession"), 120)
        if not got:
            hs.append({"ok": False, "lines": [l for _, l in bob.since(0)][-6:]})
            log(name, "hs", i, "NO SESSION")
            continue
        s = phase_split(bob.since(0), got[0]) or {}
        s["ok"] = True
        s["retries"] = sum(1 for _, l in bob.since(0) if "dial-failed" in l)
        hs.append(s)
        log(name, "hs", i, {k: round(v, 3) if isinstance(v, float) else v for k, v in s.items()})
    R["handshake"] = {"samples": hs,
                      "connect": stats([s.get("connect") for s in hs]),
                      "handshake": stats([s.get("handshake") for s in hs]),
                      "dial": stats([s.get("dial") for s in hs]),
                      "extra_phase_events": sum(1 for s in hs if s.get("phase_events", 4) > 4),
                      "failed": sum(1 for s in hs if not s["ok"])}

    # --- give-up paths: nothing listening ------------------------------------
    t, ans = bob.call(f"request {a_ip}:47199 {alice.me}", 30)
    R["giveup_request"] = {"s": t, "answer": ans and ans[:80]}
    t, ans = bob.call(f"connect {a_ip}:47198 {alice.me}", 60)
    R["giveup_dial"] = {"s": t, "answer": ans and ans[:80]}
    log(name, "give-up", R["giveup_request"], R["giveup_dial"])
    bob.wait(lambda l: l.startswith("event\tsession"), 1)

    # --- 3: sustained chat, both directions, then idle -----------------------
    ma, mb = alice.mark(), bob.mark()
    sent = {"a": {}, "b": {}}

    def pump(node, peer, tag, n, gap):
        for i in range(n):
            body = f"{tag}{i:04d}"
            sent[tag][body] = node.cmd(f"send {peer} {body}")
            time.sleep(gap)

    N_CHAT = 240
    th = [threading.Thread(target=pump, args=(alice, bob.me, "a", N_CHAT, 0.25)),
          threading.Thread(target=pump, args=(bob, alice.me, "b", N_CHAT, 0.25))]
    [t.start() for t in th]
    [t.join() for t in th]

    def arrivals(node, m, tag):
        return [(t, l.split("\t")[5]) for t, l in node.since(m)
                if l.startswith("event\trecv") and l.split("\t")[5].startswith(tag)]

    alice.wait(lambda l: l.endswith(f"b{N_CHAT-1:04d}"), 60, ma)
    bob.wait(lambda l: l.endswith(f"a{N_CHAT-1:04d}"), 60, mb)
    time.sleep(5)
    chat = {}
    for tag, rx, m, tx in (("b", alice, ma, bob), ("a", bob, mb, alice)):
        arr = arrivals(rx, m, tag)
        bodies = [b for _, b in arr]
        lat = [t - sent[tag][b] for t, b in arr if b in sent[tag]]
        delivered = sum(1 for _, l in tx.since(mb if tx is bob else ma) if l.startswith("event\tdelivered"))
        chat[f"{tx.ctr}->{rx.ctr}"] = {
            "sent": N_CHAT, "arrived": len(bodies), "unique": len(set(bodies)),
            "in_order": bodies == sorted(bodies), "latency": stats(lat),
            "delivered_acks": delivered}
    chat["closed_during"] = [l for _, l in alice.since(ma) + bob.since(mb) if l.startswith("event\tclosed")]
    log(name, "chat", chat)

    time.sleep(45)  # longer than MAX_IDLE: only keep-alives hold the session
    ma, mb = alice.mark(), bob.mark()
    alice.cmd(f"send {bob.me} after-idle-a")
    bob.cmd(f"send {alice.me} after-idle-b")
    ga = alice.wait(lambda l: l.endswith("after-idle-b"), 30, ma)
    gb = bob.wait(lambda l: l.endswith("after-idle-a"), 30, mb)
    chat["after_45s_idle"] = {"alice_got": bool(ga), "bob_got": bool(gb),
                              "closed": [l for _, l in alice.since(ma) + bob.since(mb) if l.startswith("event\tclosed")]}
    R["chat"] = chat
    log(name, "idle", chat["after_45s_idle"])

    # --- 4 + 5: kill the acceptor, 50 queued, backoff, restart, resync -------
    time.sleep(3)
    mb = bob.mark()
    t_kill = time.perf_counter()
    alice.kill()
    for i in range(50):
        bob.cmd(f"send {alice.me} r{i:02d}")
    got = bob.wait(lambda l: l.startswith("event\tclosed"), 90, mb)
    down = 120
    time.sleep(max(0, down - (time.perf_counter() - t_kill)))
    alice = Node(A, alice_args)
    t_up = alice.t_ready
    gs = bob.wait(lambda l: l.startswith("event\tsession"), 240, mb)
    last = alice.wait(lambda l: l.endswith("\tr49"), 240)
    rs = {"bob_noticed_after": got and got[0] - t_kill, "alice_down_for": t_up - t_kill,
          "restart_to_session": gs and gs[0] - t_up,
          "session_to_all_50": (last and gs) and last[0] - gs[0],
          "restart_to_all_50": last and last[0] - t_up}
    time.sleep(5)
    arr = [l.split("\t")[5] for _, l in alice.since(0) if l.startswith("event\trecv")]
    rbodies = [b for b in arr if re.fullmatch(r"r\d\d", b)]
    rs["arrived"] = len(rbodies)
    rs["exactly_once_in_order"] = rbodies == [f"r{i:02d}" for i in range(50)]
    hist = docker("exec", *[x for k, v in ENV.items() for x in ("-e", f"{k}={v}")], A,
                  BIN, "history", bob.me)
    rs["history_count_each"] = sorted({hist.count(f"r{i:02d}") for i in range(50)})
    rs["bob_delivered_acks"] = sum(1 for _, l in bob.since(mb) if l.startswith("event\tdelivered"))

    # The backoff, from bob's log: when each failed attempt ended and the
    # delay it had slept before starting.
    fails = read_log(B, r"reconnect failed")
    att = []
    for l in fails:
        a = re.search(r"attempt=(\d+)", l)
        d = re.search(r"delay=([\d.]+)(m?s)", l)
        att.append({"t": ts(l), "attempt": int(a.group(1)) if a else None,
                    "delay_s": (float(d.group(1)) / (1000 if d.group(2) == "ms" else 1)) if d else None})
    rs["reconnect_failures"] = att
    rs["reconnect_raw"] = fails[-8:]
    R["resync"] = rs
    log(name, "resync", {k: v for k, v in rs.items() if k != "reconnect_raw"})

    R["warnings"] = {c: read_log(c, r" (WARN|ERROR) ") for c in (A, B)}
    alice.quit()
    bob.quit()
    return R


def containers():
    docker("network", "create", NET)
    for c in (A, B):
        docker("rm", "-f", c)
        docker("run", "-d", "--name", c, "--cap-add=NET_ADMIN", "--network", NET,
               "-v", "p2p-target:/target:ro", IMAGE, "sleep", "infinity", check=True)


def ip(ctr):
    return docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", ctr).strip()


def main():
    names = sys.argv[1:] or list(PROFILES)
    containers()
    results = []
    for n in names:
        results.append(run_profile(n, PROFILES[n]))
        with open(f"wan-{n}.json", "w", encoding="utf-8") as f:
            json.dump(results[-1], f, indent=1, default=str)
    netem(None)


if __name__ == "__main__":
    main()
