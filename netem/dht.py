"""M16's simulation: N DHT nodes, each in its own network namespace, inside one
privileged container. See README.md, "DHT simulation".

Runs inside the container, because it needs `ip netns`, `tc` and `iptables`:

    docker run --rm --privileged -v p2p-target:/target:ro -v "$PWD/netem:/h:ro" \
        -v "$OUT:/out" p2p-wan python3 /h/dht.py selftest

The ground truth is computed here, never taken from a node. It is built from the
IDs the nodes print at startup, from the harness's own record of which nodes are
alive and what each one published, and from XOR distance recomputed in Python,
independently of the Rust code under test. A node's routing table, a lookup's
answer, and a record fetched from the network are all compared against it.

The self-tests (`selftest`) come first for that reason. Each of the four
checkers the gates rest on is shown to report failure when the fault it looks
for is present, and success when it is not. A checker that cannot fail would
make every gate after it vacuous (agent.md section 7).
"""
import argparse, glob, hashlib, json, os, random, re, subprocess, sys, threading, time
from datetime import datetime

ROOT = "/run/dht"
PUB, PRIV = 47100, 47101
SEEDS = 3
# Product public-node limiter timing. Written here rather than read from the
# binary so a changed implementation cannot silently move gate 5's bound.
RATE_LIMIT_WINDOW, RATE_LIMIT_MARGIN = 60, 1
# netem specs, applied to each namespace's egress, so a round trip is twice
# the delay. The same profiles as wan.py.
PROFILES = {
    "baseline": None,
    "typical": "delay 60ms 20ms distribution normal loss 0.5%",
    "poor": "delay 150ms 50ms loss 3% reorder 1%",
    "bad": "delay 400ms loss 8%",
}
T0 = time.monotonic()


def log(*a):
    print(f"{time.monotonic() - T0:7.1f}", *a, flush=True)


def verified_binary(path):
    """Return a harness subject only when the caller named a real binary.

    Do not provide a default here. A result that does not say precisely which
    executable produced it is not evidence, especially for mutant runs.
    """
    if not path:
        raise SystemExit("--binary is required; refusing an unverifiable result")
    if not os.path.isfile(path):
        raise SystemExit(f"--binary does not name a regular file: {path}")
    if not os.access(path, os.X_OK):
        raise SystemExit(f"--binary is not executable: {path}")
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return path, digest


def sh(cmd, input=None, check=True):
    r = subprocess.run(cmd, shell=True, input=input, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{cmd}: {r.stderr.strip()}")
    return r.stdout


# ---------------------------------------------------------------------------
# Truth: XOR distance, recomputed here
# ---------------------------------------------------------------------------

def xor(a, b):
    return int(a, 16) ^ int(b, 16)


def bucket(me, other):
    """Kademlia bucket index: the number of leading bits `me` and `other` share."""
    return 256 - xor(me, other).bit_length()


def k_closest(target, ids, k):
    return sorted(ids, key=lambda i: xor(target, i))[:k]


def rand_id():
    return "%064x" % random.getrandbits(256)


# ---------------------------------------------------------------------------
# Network: one namespace per node, routed through the container's own
# ---------------------------------------------------------------------------

GW = "10.99.255.254"


class Net:
    """A routed star, not a bridge. On a bridge every node ARPs for every
    other, N*(N-1) neighbour entries, and the kernel caps neighbour entries
    across all namespaces together (gc_thresh3, 1024 by default, not settable
    from inside Docker Desktop's VM). At 50 nodes that is 2450: past the cap,
    sends fail with ENOBUFS, which shows in no interface counter, and every
    RPC times out. The first 50-node self-test hit exactly that. Here each
    node's one neighbour is the gateway, and the gateway's are the nodes: 2N.
    """

    def __init__(self):
        sh("sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0"
           " net.ipv4.conf.default.rp_filter=0")
        self.made = set()

    @staticmethod
    def ip(i):
        return f"10.99.{i // 200}.{i % 200 + 10}"

    def add(self, i):
        if i in self.made:
            return
        ns, ip = f"n{i}", self.ip(i)
        sh(f"ip netns del {ns} 2>/dev/null; ip link del h{i} 2>/dev/null; true")
        sh(f"ip netns add {ns}")
        sh(f"ip link add h{i} type veth peer name e{i} && ip link set e{i} netns {ns}"
           f" && ip addr add {GW}/32 dev h{i} && ip link set h{i} up"
           f" && ip route add {ip}/32 dev h{i}")
        sh(f"ip netns exec {ns} sh -c 'ip addr add {ip}/32 dev e{i} && ip link set e{i} up"
           f" && ip link set lo up && ip route add {GW}/32 dev e{i}"
           f" && ip route add default via {GW} dev e{i}'")
        self.made.add(i)

    def mesh(self, idx):
        """Every namespace pings every other once. Returns those that could
        not reach someone, and whom. Run before any fault is injected: a
        network that cannot carry a ping cannot carry a gate."""
        idx = list(idx)
        ips = [self.ip(j) for j in idx]

        def one(i):
            cmd = "; ".join(f"ping -c1 -W2 -q {ip} >/dev/null 2>&1 || echo {ip}"
                            for ip in ips if ip != self.ip(i))
            return sh(f"ip netns exec n{i} sh -c '{cmd}'", check=False).split()
        bad = par(one, idx)
        return {i: b for i, b in zip(idx, bad) if b}

    def netem(self, i, spec):
        sh(f"ip netns exec n{i} tc qdisc del dev e{i} root 2>/dev/null; true")
        if spec:
            sh(f"ip netns exec n{i} tc qdisc add dev e{i} root netem {spec}")

    def rules(self, i, lines):
        """Replaces namespace i's filter table. No lines: everything passes."""
        text = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        text += "".join(l + "\n" for l in lines) + "COMMIT\n"
        sh(f"ip netns exec n{i} iptables-restore", input=text)

    def partition(self, groups):
        """groups: node index -> group label. Drops every packet between groups,
        both ways, in every member's own namespace."""
        for i, g in groups.items():
            other = [self.ip(j) for j, h in groups.items() if h != g]
            self.rules(i, [f"-A INPUT -s {ip} -j DROP" for ip in other]
                       + [f"-A OUTPUT -d {ip} -j DROP" for ip in other])

    def isolate(self, i, allow):
        """Node i talks to the IPs in `allow` and to nobody else on the bridge."""
        lines = []
        for ip in allow:
            lines += [f"-A INPUT -s {ip} -j ACCEPT", f"-A OUTPUT -d {ip} -j ACCEPT"]
        lines += ["-A INPUT -s 10.99.0.0/16 -j DROP", "-A OUTPUT -d 10.99.0.0/16 -j DROP"]
        self.rules(i, lines)

    def heal(self, nodes):
        for i in nodes:
            self.rules(i, [])


# ---------------------------------------------------------------------------
# One node: `p2pchat dht`, driven over its stdin and stdout
# ---------------------------------------------------------------------------

class Node:
    """The protocol, which `p2pchat dht` implements:

    ready <id hex> <public addr|-> k=<k> alpha=<a> replication=<r>   once
    event joined <table size>               a member, when its join lookups end
    table            -> ok table <n> <hex>@<addr> ...
    records          -> ok records <n> <hex>:<seq> ...
    find <hex>       -> ok find <ms> <rpcs> <stop> <hex> ...       FIND_NODE lookup
    get <hex>        -> ok get <ms> <rpcs> <stop> <seq|-> <addr,..|->  FIND_VALUE
    publish <seq> <addr,..>  -> ok publish <accepted> <hex> ...
    forge <kind> <seq>       -> ok forge <key hex> <accepted>
    ask <addr> <hex>         -> ok ask value <seq> | ok ask nodes <n> <hex> ...
                                FIND_VALUE, one RPC, nothing checked on this side
    """

    def __init__(self, h, i, client=False, boot=None, binary=None, env=None):
        self.h, self.i, self.client = h, i, client
        self.ip = Net.ip(i)
        self.addr = None if client else f"{self.ip}:{PUB}"
        d = f"{ROOT}/n{i}"
        sh(f"mkdir -p {d}")
        e = {"P2PCHAT_CONFIG_DIR": f"{d}/cfg", "P2PCHAT_DATA_DIR": f"{d}/data",
             "RUST_LOG": "info,p2pchat_net::dht=debug,p2pchat_net::public=debug", **h.env, **(env or {})}
        boot = h.seeds() if boot is None else boot
        args = ["dht", "--private-port", str(PRIV)]
        for b in boot:
            args += ["--bootstrap", b]
        if client:
            args += ["--client"]
        else:
            args += ["--public-port", str(PUB), "--addr", self.addr]
        self.p = subprocess.Popen(
            ["ip", "netns", "exec", f"n{i}", "env", *[f"{k}={v}" for k, v in e.items()],
             binary or h.binary, *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        self.lines, self.cv, self.lock = [], threading.Condition(), threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        got = self.wait(lambda l: l.startswith("ready\t"), 30)
        if not got:
            raise RuntimeError(f"n{i} never became ready: {self.lines[-5:]}")
        f = got[1].split("\t")
        self.id = f[1]
        self.params = dict(x.split("=") for x in f[3:])
        self.alive = True

    def _read(self):
        for line in self.p.stdout:
            with self.cv:
                self.lines.append((time.monotonic(), line.rstrip("\n")))
                self.cv.notify_all()

    def wait(self, pred, timeout, since=0):
        deadline = time.monotonic() + timeout
        i = since
        with self.cv:
            while True:
                while i < len(self.lines):
                    t, l = self.lines[i]
                    i += 1
                    if pred(l):
                        return t, l
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return None
                self.cv.wait(rem)

    def call(self, line, timeout=300):
        """One command, one answer: its tab-separated fields after ok/err."""
        verb = line.split()[0]
        with self.lock:
            with self.cv:
                m = len(self.lines)
            self.p.stdin.write(line + "\n")
            self.p.stdin.flush()
            got = self.wait(lambda l: l.startswith(("ok\t" + verb + "\t", "err\t" + verb + "\t")),
                            timeout, m)
        if not got:
            return None
        f = got[1].split("\t")
        return f[2:] if f[0] == "ok" else None

    def table(self):
        f = self.call("table", 30)
        if f is None:
            return None
        return [tuple(x.split("@")) for x in f[1].split()] if len(f) > 1 else []

    def records(self):
        f = self.call("records", 30)
        return {} if f is None or len(f) < 2 else {
            k: int(s) for k, s in (x.split(":") for x in f[1].split())}

    def find(self, target):
        f = self.call(f"find {target}")
        if f is None:
            return None
        return {"ms": int(f[0]), "rpcs": int(f[1]), "stop": f[2],
                "ids": f[3].split() if len(f) > 3 else []}

    def get(self, key):
        f = self.call(f"get {key}")
        if f is None:
            return None
        return {"ms": int(f[0]), "rpcs": int(f[1]), "stop": f[2],
                "seq": None if f[3] == "-" else int(f[3]),
                "addrs": None if f[4] == "-" else f[4]}

    def kill(self):
        self.p.kill()
        self.p.wait(10)
        self.alive = False

    def quit(self):
        if self.alive:
            try:
                self.p.stdin.close()
                self.p.wait(10)
            except (OSError, subprocess.TimeoutExpired):
                self.p.kill()
            self.alive = False


# ---------------------------------------------------------------------------
# The harness: nodes, truth and the checkers
# ---------------------------------------------------------------------------

def par(fn, items):
    """fn over items, one thread each; results in order."""
    out = [None] * len(items)

    def run(n, x):
        out[n] = fn(x)
    th = [threading.Thread(target=run, args=(n, x)) for n, x in enumerate(items)]
    [t.start() for t in th]
    [t.join() for t in th]
    return out


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else None


def stats(xs):
    xs = [x for x in xs if x is not None]
    return {"n": len(xs), "min": min(xs) if xs else None,
            "p50": pct(xs, 50), "p90": pct(xs, 90), "p99": pct(xs, 99),
            "max": max(xs) if xs else None, "mean": round(sum(xs) / len(xs), 2) if xs else None}


class H:
    def __init__(self, args, binary=None, env=None):
        self.args = args
        self.binary, self.binary_sha256 = verified_binary(binary or args.binary)
        self.k = None       # from the first node's ready line
        self.env = {
            "P2PCHAT_DHT_REFRESH_MS": str(args.refresh_ms),
            # Keep the stdin driver's public limiter and the DHT's
            # confirmation clock on exactly the same configured window.
            "P2PCHAT_HARNESS_WINDOW_MS": str(RATE_LIMIT_WINDOW * 1000),
            "P2PCHAT_DHT_RATE_LIMIT_WINDOW_MS": str(RATE_LIMIT_WINDOW * 1000),
            # The namespace is RFC1918 by construction.  Normal nodes reject
            # non-public DHT addresses unless this test-only opt-in is set.
            "P2PCHAT_ALLOW_NONPUBLIC_DHT_ADDRS": "1",
            # `p2pchat dht` has no reachability phase: the harness controls
            # which processes are members. Model the post-dial-back state
            # explicitly, rather than letting an on-wire Member claim raise
            # an allowance. The M14/M16a loopback tests exercise the actual
            # proof path.
            "P2PCHAT_HARNESS_PROVEN_IPS": ",".join(
                Net.ip(i) for i in range(args.n + args.clients + 2 * getattr(args, "redials", 0) + 16)
            ),
        }
        # The simulation refreshes every 30 seconds, thirty times faster than
        # the product. Its limits are therefore an instrument setting, never
        # `public::Limits::default`.
        if args.refresh_ms < 15 * 60 * 1000:
            self.env.update({
                "P2PCHAT_HARNESS_PER_SOURCE": "40",
                "P2PCHAT_HARNESS_FORWARD_PER_MEMBER": "60",
            })
        if getattr(args, "trace_m16", False):
            self.env["P2PCHAT_M16_TRACE"] = "1"
        for name in ("k", "alpha", "replication", "rpc_timeout_ms"):
            v = getattr(args, name)
            if v is not None:
                self.env[f"P2PCHAT_DHT_{name.upper()}"] = str(v)
        self.env.update(env or {})
        sh(f"pkill -9 -x p2pchat; rm -rf {ROOT}; mkdir -p {ROOT}", check=False)
        self.net = Net()
        self.nodes = {}     # index -> Node
        self.truth = {}     # user id -> (seq, "addr,addr") as published

    # --- population --------------------------------------------------------

    def seeds(self):
        return [f"{Net.ip(i)}:{PUB}" for i in range(SEEDS)]

    def start(self, i, **kw):
        self.net.add(i)
        self.net.netem(i, PROFILES[self.args.profile])
        n = self.nodes[i] = Node(self, i, **kw)
        if self.k is None:
            self.k = int(n.params["k"])
        return n

    def preflight(self, n):
        for i in range(n):
            self.net.add(i)
        bad = self.net.mesh(range(n))
        if bad:
            raise RuntimeError(f"preflight: {len(bad)} namespaces cannot reach every other: "
                               f"{dict(list(bad.items())[:3])}")
        log("preflight", n, "namespaces, full mesh reachable")

    def boot(self, n, gap=0.2):
        """Seeds first, then the rest, `gap` apart; waits for every join."""
        for i in range(n):
            self.start(i)
            if i >= SEEDS:
                time.sleep(gap)
        return self.wait_joined(range(n))

    def wait_joined(self, idx, timeout=120):
        t0 = time.monotonic()
        out = {}
        for i in idx:
            got = self.nodes[i].wait(lambda l: l.startswith("event\tjoined"),
                                     max(1, timeout - (time.monotonic() - t0)))
            out[i] = got is not None
        return out

    def members(self):
        """Live members: index -> id."""
        return {i: n.id for i, n in self.nodes.items() if n.alive and not n.client}

    def clients(self):
        return {i: n.id for i, n in self.nodes.items() if n.alive and n.client}

    def tables(self, idx=None):
        idx = list(self.members()) if idx is None else idx
        got = par(lambda i: self.nodes[i].table(), idx)
        return dict(zip(idx, got))

    def teardown(self):
        for n in self.nodes.values():
            if n.alive:
                n.p.kill()
        sh("pkill -9 -x p2pchat", check=False)

    # --- checkers ----------------------------------------------------------

    def joined(self, tables, idx):
        """Checker 1. A node has joined when its own table is not empty *and*
        some other member holds it. Either alone is not enough: a node can
        fill its table from answers while nobody can reach it back."""
        held = {i: False for i in idx}
        ids = {self.nodes[i].id: i for i in idx}
        for j, t in tables.items():
            for c in t or []:
                if c[0] in ids and ids[c[0]] != j:
                    held[ids[c[0]]] = True
        out = {}
        for i in idx:
            own = tables.get(i)
            if own is None:
                own = self.nodes[i].table() or []
            out[i] = {"own_table": len(own), "held_by_others": held[i],
                      "joined": len(own) > 0 and held[i]}
        return out

    def convergence(self, tables):
        """Checker 2. For each live member, per bucket, how many live members
        the table holds against how many it should: min(k, live members in
        that bucket). A node is converged only when every bucket is full to
        that mark. The network is converged only when *every* node is: an
        average would let one stuck node hide behind forty-nine good ones."""
        live = self.members()
        per = {}
        for i, me in live.items():
            t = tables.get(i) or []
            want, have = {}, {}
            for j, other in live.items():
                if j != i:
                    b = bucket(me, other)
                    want[b] = want.get(b, 0) + 1
            live_ids = set(live.values())
            for c in t:
                if c[0] in live_ids and c[0] != me:
                    b = bucket(me, c[0])
                    have[b] = have.get(b, 0) + 1
            short = {b: min(self.k, w) - min(have.get(b, 0), self.k)
                     for b, w in want.items() if have.get(b, 0) < min(self.k, w)}
            total = sum(min(self.k, w) for w in want.values())
            per[i] = {"complete": round(sum(min(have.get(b, 0), min(self.k, w))
                                            for b, w in want.items()) / total, 4) if total else 1.0,
                      "short": short, "converged": not short}
        return per

    def check_find(self, requester, target, got):
        """Checker 3a. A FIND_NODE answer is right when it is exactly the k
        live members closest to the target by XOR, less the requester."""
        pool = [m for i, m in self.members().items() if i != requester]
        want = k_closest(target, pool, self.k)
        ok = got is not None and got["ids"] == want
        return ok, want

    def check_get(self, key, got):
        """Checker 3b. A FIND_VALUE answer is right when it carries what the
        owner published last, as the harness recorded it: seq and addresses."""
        want = self.truth.get(key)
        if got is None:
            return False
        if want is None:
            return got["seq"] is None
        return got["seq"] == want[0] and got["addrs"] == want[1]

    def reaches(self, a, b):
        """Checker 4. Whether node a's lookup for node b's ID reaches b
        itself: b is the closest node to its own ID, so it is first in the
        answer only if a's lookup got an answer from it. A record could be
        found on a replica on a's side of a partition; b cannot."""
        got = self.nodes[a].find(self.nodes[b].id)
        return bool(got and got["ids"] and got["ids"][0] == self.nodes[b].id)

    # --- helpers the scenarios share ----------------------------------------

    def publish_all(self, seq=1):
        live = self.members()

        def pub(i):
            n = self.nodes[i]
            addr = f"{n.ip}:{PRIV}"
            f = n.call(f"publish {seq} {addr}")
            return (i, addr, f)
        for i, addr, f in par(pub, list(live)):
            if f is not None:
                self.truth[self.nodes[i].id] = (seq, addr)

    def converge(self, limit, every=2.0):
        """Polls until every node is converged, or `limit` seconds. Returns the
        time taken (None if never) and the timeline."""
        t0 = time.monotonic()
        timeline = []
        while True:
            c = self.convergence(self.tables())
            el = round(time.monotonic() - t0, 1)
            comp = [v["complete"] for v in c.values()]
            bad = sorted(i for i, v in c.items() if not v["converged"])
            timeline.append({"t": el, "min": min(comp), "mean": round(sum(comp) / len(comp), 4),
                             "unconverged": len(bad)})
            if not bad:
                return el, timeline, c
            if el >= limit:
                return None, timeline, c
            time.sleep(every)

    def rate_limited(self):
        """Requests refused by a public node's rate limiter, all nodes. A
        refused RPC looks like a dead node to the asker, so any count here
        taints what a run measured, and is reported with it."""
        return sum(len(self.logs(i, r"rate limited")) for i in self.nodes)

    def rate_limited_between(self, started, ended):
        """Limiter refusals during one named interval, from every server log."""
        return sum(
            1 for i in self.nodes for t, _ in self.logs(i, r"rate limited")
            if started <= t <= ended
        )

    def demand(self, marks, window=60):
        """M16a. What each source asked of each server, counted the way the
        limiter counts: a window opens at a source's first request after its
        last window lapsed. A pair's peak is the most requests in one window,
        which is the per-source limit it would need to be refused nothing.
        Taken from the servers' own `admitted` and `rate limited` lines, so
        with the limits lifted (the `wide` build) it is the whole demand, and
        with them in place what was refused is counted too.

        `marks` is phase name -> wall-clock start, to say when a peak fell."""
        seeds = {Net.ip(i) for i in range(SEEDS)}
        clients = {n.ip for n in self.nodes.values() if n.client}
        order = sorted(marks.items(), key=lambda kv: kv[1])

        def phase(t):
            name = "before"
            for n, at in order:
                if t >= at:
                    name = n
            return name

        pairs = []
        for i, n in self.nodes.items():
            by = {}
            for t, l in self.logs(i, r"\b(admitted|rate limited) source="):
                src = re.search(r"\b(?:admitted|rate limited) source=(\S+)", l).group(1)
                by.setdefault(src, []).append(t)
            # `kind` is a string field, which the log quotes.
            kinds = [(t, m.group(1), m.group(2)) for t, l in self.logs(i, r"dht request")
                     for m in [re.search(r"source=(\S+) kind=\"?(\w+)", l)] if m]
            for src, ts in by.items():
                peak, at, start, count = 0, None, None, 0
                for t in ts:
                    if start is None or t - start >= window:
                        start, count = t, 0
                    count += 1
                    if count > peak:
                        peak, at, opened = count, t, start
                what = {}
                for t, s, k in kinds:
                    if s == src and opened <= t < opened + window:
                        what[k] = what.get(k, 0) + 1
                pairs.append({"server": i, "server_kind": "seed" if n.ip in seeds else "member",
                              "source": src,
                              "source_kind": "seed" if src in seeds else "client" if src in clients else "member",
                              "total": len(ts), "peak": peak, "peak_phase": phase(at), "peak_kinds": what})
        groups = {}
        for p in pairs:
            groups.setdefault(f"{p['source_kind']}->{p['server_kind']}", []).append(p["peak"])
        by_phase = {}
        for p in pairs:
            by_phase.setdefault(p["peak_phase"], []).append(p["peak"])
        return {"pairs": len(pairs),
                "peak": stats([p["peak"] for p in pairs]),
                "by_kind": {g: stats(v) for g, v in sorted(groups.items())},
                "by_phase_of_peak": {g: stats(v) for g, v in sorted(by_phase.items())},
                "over": {n: sum(1 for p in pairs if p["peak"] > n) for n in (10, 20, 30, 45, 60)},
                "top": sorted(pairs, key=lambda p: -p["peak"])[:12]}

    def logs(self, i, pattern):
        out = []
        for path in glob.glob(f"{ROOT}/n{i}/data/p2pchat*.log"):
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if re.search(pattern, line):
                        ts = datetime.fromisoformat(line.split()[0].replace("Z", "+00:00")).timestamp()
                        out.append((ts, line.rstrip("\n")))
        return sorted(out)


def fp(hexid):
    """The fingerprint a node's log prints for an ID."""
    return " ".join(hexid[n:n + 4] for n in range(0, 16, 4))


# ---------------------------------------------------------------------------
# Self-test: every checker, with the fault and without it
# ---------------------------------------------------------------------------

def selftest(args):
    h = H(args, binary=args.binary)
    R = {}
    N = args.n
    try:
        # The fault for checker 2 is in place before node X joins: X can talk
        # to seed 0 and to nobody else, so its table can never fill.
        X = N - 1
        h.preflight(N + 3)
        h.net.isolate(X, [Net.ip(0)])
        joined = h.boot(N)
        # Checker 1's fault: a node whose only bootstrap address answers
        # nothing. It is started last and given two refresh rounds.
        ghost = N
        h.start(ghost, boot=["10.99.250.250:47100"])
        time.sleep(2 * args.refresh_ms / 1000 + 5)
        tables = h.tables()
        j = h.joined(tables, list(h.members()))
        R["1_never_joins"] = {
            "fault_ghost_joined": j[ghost]["joined"], "ghost": j[ghost],
            "controls_joined": sum(1 for i, v in j.items() if i not in (ghost, X) and v["joined"]),
            "controls": N - 1,
        }
        R["1_never_joins"]["detected"] = (not j[ghost]["joined"]
                                          and R["1_never_joins"]["controls_joined"] == N - 1)
        h.nodes[ghost].kill()
        log("self-test 1", R["1_never_joins"])

        # Checker 2 with X isolated: must not report convergence.
        t, timeline, c = h.converge(limit=3 * args.refresh_ms / 1000)
        R["2_never_converges"] = {"fault_converged_after": t, "x": c.get(X),
                                  "others_unconverged": [i for i, v in c.items() if not v["converged"] and i != X],
                                  "timeline_tail": timeline[-3:]}
        h.net.heal([X])
        t2, timeline2, c2 = h.converge(limit=4 * args.refresh_ms / 1000)
        R["2_never_converges"]["healed_converged_after"] = t2
        R["2_never_converges"]["detected"] = t is None and t2 is not None
        log("self-test 2", {k: v for k, v in R["2_never_converges"].items() if k != "timeline_tail"})

        # Checker 3: one node republishes covertly, so the network holds a
        # value the truth does not. Lookups for it must be reported wrong.
        h.publish_all(seq=1)
        live = list(h.members())
        Y = live[5]
        y = h.nodes[Y]
        took = y.call(f"publish 2 {y.ip}:1")        # not recorded in h.truth
        held = {i: h.nodes[i].records().get(y.id) for i in live}
        askers = random.sample([i for i in live if i != Y], 10)
        wrong = [h.check_get(y.id, h.nodes[a].get(y.id)) for a in askers]
        h.truth[y.id] = (2, f"{y.ip}:1")     # now recorded
        right = [h.check_get(y.id, h.nodes[a].get(y.id)) for a in askers]
        R["3_wrong_value"] = {"fault_reported_right": sum(wrong), "control_reported_right": sum(right),
                              "asked": len(askers), "republish_took": took and took[0],
                              "held_seq_by_node": held, "rate_limited": h.rate_limited(),
                              "detected": sum(wrong) == 0 and sum(right) == len(askers)}
        log("self-test 3", R["3_wrong_value"])

        # Checker 4: a partition, then a "heal" that is not applied. Pairs are
        # sampled across the split; the partition must first be shown real.
        halves = {i: (0 if i < N // 2 else 1) for i in h.members()}
        A = [i for i, g in halves.items() if g == 0]
        B = [i for i, g in halves.items() if g == 1]
        pairs = [(random.choice(A), random.choice(B)) for _ in range(6)]
        pairs += [(b, a) for a, b in pairs[:3]]
        h.net.partition(halves)
        # Long enough for liveness checks to evict the other half.
        hold = 2 * args.refresh_ms / 1000 + 30
        time.sleep(hold)
        during = par(lambda p: h.reaches(*p), pairs)
        time.sleep(2 * args.refresh_ms / 1000)   # the "heal" window, heal skipped
        unhealed = par(lambda p: h.reaches(*p), pairs)
        h.net.heal(list(h.members()))
        t0 = time.monotonic()
        healed, heal_t = [], None
        while time.monotonic() - t0 < 4 * args.refresh_ms / 1000 + 30:
            time.sleep(5)
            healed = par(lambda p: h.reaches(*p), pairs)
            if all(healed):
                heal_t = round(time.monotonic() - t0, 1)
                break
        R["4_partition_never_heals"] = {
            "pairs": len(pairs), "reached_during_partition": sum(during),
            "fault_reached_after_skipped_heal": sum(unhealed),
            "control_reached_after_heal": sum(healed), "control_heal_seconds": heal_t,
            "detected": sum(during) == 0 and sum(unhealed) < len(pairs) and heal_t is not None}
        log("self-test 4", R["4_partition_never_heals"])

        # Gate 4's checker too, cheaply: a node started with refresh switched
        # off must be reported as not refreshing.
        R["gate4_checker"] = refresh_checker_selftest(h, args)
        log("self-test gate-4 checker", R["gate4_checker"])
    finally:
        h.teardown()
    R["all_detected"] = all(v.get("detected") for v in R.values() if isinstance(v, dict))
    return R


def refresh_checker_selftest(h, args):
    i = max(h.nodes) + 1
    h.start(i, env={"P2PCHAT_DHT_REFRESH_MS": str(10 ** 9)})
    time.sleep(3 * args.refresh_ms / 1000)
    frozen = refresh_ok(h, [i], window=(time.monotonic() - 3 * args.refresh_ms / 1000, None), args=args)
    live = [j for j in h.members() if j != i][:5]
    normal = refresh_ok(h, live, window=(time.monotonic() - 3 * args.refresh_ms / 1000, None), args=args)
    h.nodes[i].kill()
    return {"fault_frozen_node_ok": frozen["ok"], "control_ok": normal["ok"],
            "detected": (not frozen["ok"]) and normal["ok"]}


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

def refresh_ok(h, idx, window, args):
    """Gate 4's checker. Over a window with no user lookups, every bucket a
    node refreshes must be refreshed again within refresh + one tick + slack,
    and every node must refresh at least its buckets that hold contacts.
    `window` is (monotonic start, end or None)."""
    every = args.refresh_ms / 1000
    slack = every / 4 + 3
    start = time.time() - (time.monotonic() - window[0])
    end = time.time() if window[1] is None else time.time() - (time.monotonic() - window[1])
    per = {}
    for i in idx:
        ev = [(t, int(re.search(r"bucket=(\d+)", l).group(1)))
              for t, l in h.logs(i, r"bucket refreshed") if start <= t <= end]
        by = {}
        for t, b in ev:
            by.setdefault(b, []).append(t)
        gaps = [round(b - a, 1) for ts in by.values() for a, b in zip(ts, ts[1:])]
        # Every bucket refreshed in the window must come round again before
        # the window closes, unless it was first seen in the last interval.
        missed = [b for b, ts in by.items() if end - ts[-1] > every + slack]
        per[i] = {"events": len(ev), "buckets": len(by), "max_gap": max(gaps, default=None),
                  "missed": missed,
                  "ok": len(ev) > 0 and not missed and all(g <= every + slack for g in gaps)}
    return {"per_node": per, "ok": all(v["ok"] for v in per.values())}


def gates(args, binary=None, env=None, only=None):
    """The seven gates, in order. `only` limits which run (for mutants)."""
    h = H(args, binary=binary, env=env)
    R = {"binary": h.binary, "env": h.env, "n": args.n}
    want = lambda g: only is None or g in only
    N = args.n
    marks = {}
    try:
        h.preflight(N + args.clients)
        marks["boot"] = time.time()
        t_boot = time.monotonic()
        joined = h.boot(N)
        R["boot_seconds"] = round(time.monotonic() - t_boot, 1)
        clients = [h.start(N + c, client=True) for c in range(args.clients)]

        # --- gate 2: convergence, measured ----------------------------------
        marks["converge"] = time.time()
        if want(2) or want(1):
            t, timeline, c = h.converge(limit=args.converge_s)
            R["gate2"] = {"converged_after_s": t, "timeline": timeline,
                          "unconverged": {i: v for i, v in c.items() if not v["converged"]},
                          "joined": sum(1 for v in h.joined(h.tables(), list(h.members())).values()
                                        if v["joined"]),
                          "pass": t is not None}
            log("gate 2", {k: v for k, v in R["gate2"].items() if k != "timeline"})

        # --- gate 1: lookups -------------------------------------------------
        marks["publish"] = time.time()
        h.publish_all(seq=1)
        marks["lookups"] = time.time()
        live = list(h.members())
        if want(1) or want(6):
            def lookups(i):
                n = h.nodes[i]
                keys = random.sample([h.nodes[j].id for j in live if j != i], args.gets)
                gets = [(key, n.get(key)) for key in keys]
                finds = []
                for _ in range(args.finds):
                    target = rand_id()
                    finds.append((target, n.find(target)))
                return gets, finds
            askers = live + [c.i for c in clients]
            res = dict(zip(askers, par(lookups, askers)))
            get_ok = [h.check_get(k, g) for i in res for k, g in res[i][0]]
            find_ok = [h.check_find(i, t, f)[0] for i in res for t, f in res[i][1]]
            wrong = [(i, t[:16], f and f["ids"][:3]) for i in res for t, f in res[i][1]
                     if not h.check_find(i, t, f)[0]][:5]
            allres = [g for i in res for _, g in res[i][0]] + [f for i in res for _, f in res[i][1]]
            R["gate1"] = {"gets": len(get_ok), "gets_right": sum(get_ok),
                          "finds": len(find_ok), "finds_exact": sum(find_ok),
                          "failed_examples": wrong,
                          "ms": stats([x["ms"] for x in allres if x]),
                          "rpcs": stats([x["rpcs"] for x in allres if x]),
                          "stops": {s: sum(1 for x in allres if x and x["stop"] == s)
                                    for s in {x["stop"] for x in allres if x}},
                          "pass": all(get_ok) and all(find_ok)}
            log("gate 1", {k: v for k, v in R["gate1"].items()})
            R["_lookup_ids"] = sorted({x for r in res.values() for _, f in r[1] if f for x in f["ids"]})

        # --- gate 3: an absent key terminates --------------------------------
        marks["gates3-7"] = time.time()
        if want(3):
            askers = random.sample(live, 10) + [c.i for c in clients]
            got = par(lambda i: h.nodes[i].get(rand_id()), askers)
            R["gate3"] = {"lookups": len(got),
                          "answered": sum(1 for g in got if g is not None),
                          "not_found": sum(1 for g in got if g and g["seq"] is None),
                          "stops": [g and g["stop"] for g in got],
                          "ms": stats([g["ms"] for g in got if g]),
                          "rpcs": stats([g["rpcs"] for g in got if g]),
                          "pass": all(g and g["seq"] is None and g["stop"] == "exhausted" for g in got)}
            log("gate 3", R["gate3"])

        # --- gate 6: clients hold nothing and are never handed out ----------
        if want(6):
            cids = {c.id for c in clients}
            tables = h.tables()
            in_tables = {i: [x[0][:16] for x in t if x[0] in cids] for i, t in tables.items() if t}
            in_tables = {i: v for i, v in in_tables.items() if v}
            client_tables = {c.i: len(c.table() or []) for c in clients}
            returned = [x[:16] for x in R.get("_lookup_ids", []) if x in cids]
            # Every member asked directly for each client's own ID, which is
            # where a member holding the client would put it first.
            asked = [(c, i) for c in clients for i in h.members()]
            answers = par(lambda ci: ci[0].call(f"ask {Net.ip(ci[1])}:{PUB} {ci[0].id}"), asked)
            handed = sorted({i for (c, i), a in zip(asked, answers)
                             # The IDs come as one space-separated field.
                             if a and a[0] == "nodes"
                             and any(x in cids for x in " ".join(a[2:]).split())})
            R["gate6"] = {"clients": len(clients), "client_table_sizes": client_tables,
                          "members_holding_a_client": in_tables,
                          "members_handing_out_a_client": handed,
                          "asks_answered": sum(1 for a in answers if a),
                          "clients_returned_by_lookups": returned,
                          "pass": not in_tables and not returned and not handed
                          and all(v == 0 for v in client_tables.values())}
            log("gate 6", R["gate6"])

        # --- gate 7: forged records neither stored nor served ----------------
        if want(7):
            R["gate7"] = gate7(h)
            log("gate 7", {k: v for k, v in R["gate7"].items() if k != "steps"})

        # --- gate 4: refresh on schedule, in a quiet window -----------------
        marks["quiet"] = time.time()
        if want(4):
            w0 = time.monotonic()
            time.sleep(3 * args.refresh_ms / 1000 + 5)
            r = refresh_ok(h, list(h.members()), (w0, None), args)
            bad = {i: v for i, v in r["per_node"].items() if not v["ok"]}
            R["gate4"] = {"nodes": len(r["per_node"]), "not_ok": bad,
                          "events": sum(v["events"] for v in r["per_node"].values()),
                          "max_gap": max((v["max_gap"] or 0) for v in r["per_node"].values()),
                          "refresh_s": args.refresh_ms / 1000, "pass": r["ok"]}
            log("gate 4", R["gate4"])

        # --- gate 5: dead nodes are evicted ----------------------------------
        marks["kill"] = time.time()
        if want(5):
            R["gate5"] = gate5(h, args)
            log("gate 5", R["gate5"])
    finally:
        h.teardown()
    R.pop("_lookup_ids", None)
    R["rate_limited"] = h.rate_limited()
    R["demand"] = h.demand(marks)
    log("demand", {k: v for k, v in R["demand"].items() if k != "top"})
    R["pass"] = {g: R[g]["pass"] for g in ("gate1", "gate2", "gate3", "gate4", "gate5", "gate6", "gate7") if g in R}
    return R


def gate7(h):
    """Each forged kind is stored by one member at the nodes closest to its
    key. Then every member's store is read, and every member is asked for the
    key directly, one RPC with no checking on the asking side, so what a
    node would serve is seen as it is."""
    live = list(h.members())
    forger = h.nodes[live[7]]
    steps = []
    ok = True
    # (kind, seq). `rollback` publishes seq 50 properly, then forges seq 40.
    for kind, seq in (("tampered", 100), ("unbound", 300), ("expired", 200), ("rollback", 40)):
        if kind == "rollback":
            forger.call(f"publish 50 {forger.ip}:{PRIV}")
            h.truth[forger.id] = (50, f"{forger.ip}:{PRIV}")
        f = forger.call(f"forge {kind} {seq}")
        key = f[0] if f else None
        claimed = int(f[1]) if f else None
        stored = {i: s for i, s in zip(live, par(lambda i: h.nodes[i].records().get(key), live))}
        held_forged = [i for i, s in stored.items() if s == seq]
        served = par(lambda i: h.nodes[forger.i].call(f"ask {Net.ip(i)}:{PUB} {key}"), live)
        served_forged = [i for i, s in zip(live, served) if s and s[0] == "value" and int(s[1]) == seq]
        step = {"kind": kind, "seq": seq, "key": key and key[:16], "nodes_claiming_stored": claimed,
                "nodes_holding_it": held_forged, "nodes_serving_it": served_forged,
                "holding_other_seq": sorted({s for s in stored.values() if s is not None})}
        steps.append(step)
        ok = ok and f is not None and not held_forged and not served_forged
    return {"steps": steps, "pass": ok}


def gate5(h, args):
    live = [i for i in h.members() if i >= SEEDS]
    dead = random.sample(live, 5)
    ids = {h.nodes[i].id: i for i in dead}
    before = h.tables()
    survivors = set(before) - set(dead)
    held_before = {i: sum(1 for t in before.values() if t and any(c[0] == h.nodes[i].id for c in t))
                   for i in dead}
    t0 = time.monotonic()
    for i in dead:
        h.nodes[i].kill()
    rpc = (args.rpc_timeout_ms or 20000) / 1000
    # A refresh lookup can spend one RPC discovering the dead contact, then
    # the refusal/silence ambiguity holds its confirming Ping beyond the
    # limiter window. The old bound already covered one final Ping and 30 s
    # of harness/table-poll slack; retain those and add the first RPC plus the
    # configured confirmation delay. Defaults: 37.5 + 20 + 61 + 20 + 30.
    limit = (args.refresh_ms / 1000 * 1.25 + rpc
             + RATE_LIMIT_WINDOW + RATE_LIMIT_MARGIN + rpc + 30)
    gone_at = {}
    # For each killed contact, retain the time each survivor's table first
    # stopped holding it.  ``None`` means that table did not hold it at the
    # kill; it is not silently counted as an eviction.
    held_by = {
        i: [owner for owner, table in before.items() if owner in survivors
            if table and any(c[0] == h.nodes[i].id for c in table)]
        for i in dead
    }
    evicted_by = {i: {} for i in dead}
    while time.monotonic() - t0 < limit and len(gone_at) < len(dead):
        time.sleep(3)
        tables = h.tables()
        for d, i in ids.items():
            for owner in held_by[i]:
                if owner not in evicted_by[i] and not any(c[0] == d for c in (tables.get(owner) or [])):
                    evicted_by[i][owner] = round(time.monotonic() - t0, 1)
            if i not in gone_at and not any(t and any(c[0] == d for c in t) for t in tables.values()):
                gone_at[i] = round(time.monotonic() - t0, 1)
    still = {i: sum(1 for t in h.tables().values() if t and any(c[0] == h.nodes[i].id for c in t))
             for i in dead}
    evict_lines = sum(len([1 for _, l in h.logs(j, r"contact evicted") if any(fp(d) in l for d in ids)])
                      for j in h.members())
    confirmations = sum(len([1 for _, l in h.logs(j, r"m16 trace confirming ping failed")
                             if any(fp(d) in l for d in ids)])
                        for j in h.members())
    return {"killed": len(dead), "tables_holding_each_before": held_before,
            "evicted_everywhere_after_s": gone_at, "tables_still_holding": still,
            "per_table_eviction_after_s": evicted_by,
            "limiter_window_s": RATE_LIMIT_WINDOW,
            "limiter_margin_s": RATE_LIMIT_MARGIN,
            "confirmation_delay_s": RATE_LIMIT_WINDOW + RATE_LIMIT_MARGIN,
            "confirming_pings": confirmations,
            "eviction_log_lines": evict_lines, "limit_s": round(limit, 1),
            "pass": len(gone_at) == len(dead) and evict_lines > 0}


# ---------------------------------------------------------------------------
# OD-7: one configuration, measured under churn
# ---------------------------------------------------------------------------

def trial(args, env):
    """Boot, converge, publish, then kill `args.kill` of the members at once
    and look up from every survivor straight away.

    Each survivor runs its lookups one after another, so a lookup's moment
    relative to the kill depends on how long the ones before it took, and
    that depends on the configuration: slow lookups push the later ones past
    the liveness checks that evict the dead, into a cleaner network. The first
    run of this trial compared alpha across exactly that confound. So every
    lookup records when it started, and each survivor's first lookup starts at
    the kill (half with a find, half with a get). That first wave sees every
    configuration in the same state, with the dead still in every table, and
    it is what the configurations are compared on. Records whose owner died
    are looked up too: finding them is what the replication factor buys."""
    h = H(args, env=env)
    R = {"env": h.env, "profile": args.profile}
    try:
        h.preflight(args.n)
        h.boot(args.n)
        t, _, _ = h.converge(limit=args.converge_s)
        R["converged_after_s"] = t
        R["table_size"] = stats([len(t or []) for t in h.tables().values()])
        h.publish_all(seq=1)
        live = list(h.members())
        dead = random.sample([i for i in live if i >= SEEDS], int(args.kill * len(live)))
        t_kill = time.monotonic()
        for i in dead:
            h.nodes[i].kill()
        survivors = list(h.members())
        dead_ids = {h.nodes[i].id for i in dead}
        r = int(h.nodes[survivors[0]].params["replication"])

        def look(i):
            n = h.nodes[i]
            keys = random.sample([h.nodes[j].id for j in live if j != i], args.gets)
            ops = [("get", k) for k in keys] + [("find", rand_id()) for _ in range(args.finds)]
            if i % 2:
                ops = ops[args.gets:] + ops[:args.gets]
            out = []
            for wave, (kind, key) in enumerate(ops):
                at = time.monotonic() - t_kill
                got = n.get(key) if kind == "get" else n.find(key)
                out.append({"asker": i, "kind": kind, "key": key, "got": got,
                            "at": round(at, 1), "wave": wave})
            return out
        ops = [o for out in par(look, survivors) for o in out]
        for o in ops:
            if o["kind"] == "get":
                o["right"] = h.check_get(o["key"], o["got"])
                o["dead_owner"] = o["key"] in dead_ids
            else:
                ok, want = h.check_find(o["asker"], o["key"], o["got"])
                ids = o["got"]["ids"] if o["got"] else []
                o["right"] = ok
                o["top1"] = ids[:1] == want[:1]
                o["topr"] = ids[:r] == want[:r]
                o["returned"] = len(ids)

        def summary(sel):
            gets = [o for o in sel if o["kind"] == "get"]
            finds = [o for o in sel if o["kind"] == "find"]
            dead_gets = [o for o in gets if o["dead_owner"]]
            return {
                "gets": len(gets), "gets_right": sum(o["right"] for o in gets),
                "gets_dead_owner": len(dead_gets),
                "gets_dead_owner_right": sum(o["right"] for o in dead_gets),
                "finds": len(finds), "finds_exact": sum(o["right"] for o in finds),
                "finds_top1": sum(o["top1"] for o in finds),
                "finds_topr": sum(o["topr"] for o in finds),
                "finds_returned": stats([o["returned"] for o in finds]),
                "get_ms": stats([o["got"]["ms"] for o in gets if o["got"]]),
                "find_ms": stats([o["got"]["ms"] for o in finds if o["got"]]),
                "rpcs": stats([o["got"]["rpcs"] for o in sel if o["got"]]),
            }
        R["first_wave"] = summary([o for o in ops if o["wave"] == 0])
        R["all"] = summary(ops)
        R["first_wave_started_within_s"] = max(o["at"] for o in ops if o["wave"] == 0)
        R["dead"] = len(dead)
        R["survivors"] = len(survivors)
        R["replication"] = r
        R["rate_limited"] = h.rate_limited()
    finally:
        h.teardown()
    return R


# ---------------------------------------------------------------------------
# M17: real nodes publishing into the DHT and dialled out of it
# ---------------------------------------------------------------------------

# OD-6 as shipped, for the bounds below. Written here, not read from the
# node: a bound taken from the code under test moves with it (agent.md 7).
LIFETIME, REPUBLISH, DIAL_TIMEOUT = 180, 90, 20
# Once an unrelated member can read the newer record, the reconnect must not
# spend the stale address's dial deadline. Five seconds covers the bounded
# 1/2/4-second probe schedule plus the poor-profile lookup and handshake tail;
# it is one quarter of the shipped 20-second dial deadline.
REDIAL_AFTER_NEW_RECORD = 5


class Subject(Node):
    """One `p2pchat node` - the real node, M17's subject - in its own
    namespace, driven over the debug CLI:

    ready <id> <private bound> <public|-> <private advertised|->
    event session <peer> <initiator> | event dial-failed <peer> <reason>
    event request <from> <state> <name> | event closed <peer>
    accept|reject <id>, connect <id>, request <addr> <id>  -> ok|err <verb> ...

    `--addr` is its namespace IP, so the private address it advertises is
    that IP and the private port; the harness knows it without asking."""

    def __init__(self, h, i, public=False, boot=None):
        self.h, self.i, self.client = h, i, True
        self.ip = Net.ip(i)
        self.addr = f"{self.ip}:{PUB}" if public else None
        d = f"{ROOT}/n{i}"
        sh(f"mkdir -p {d}")
        e = {"P2PCHAT_CONFIG_DIR": f"{d}/cfg", "P2PCHAT_DATA_DIR": f"{d}/data",
             "RUST_LOG": "info,p2pchat=debug,p2pchat_net::public=debug", **h.env}
        args = ["node", "--private-port", str(PRIV), "--addr", f"{self.ip}:{PUB}"]
        if public:
            args += ["--public-port", str(PUB)]
        for b in (h.seeds() if boot is None else boot):
            args += ["--bootstrap", b]
        self.started = time.monotonic()
        self.p = subprocess.Popen(
            ["ip", "netns", "exec", f"n{i}", "env", *[f"{k}={v}" for k, v in e.items()],
             h.binary, *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        self.lines, self.cv, self.lock = [], threading.Condition(), threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()
        got = self.wait(lambda l: l.startswith("ready\t"), 30)
        if not got:
            raise RuntimeError(f"n{i} never became ready: {self.lines[-5:]}")
        f = got[1].split("\t")
        self.id = f[1]
        self.private = f"{self.ip}:{PRIV}"
        self.alive = True

    def connect(self, peer):
        """`connect <id>`: (ok, answer, seconds, dial-failed reasons for peer)."""
        with self.cv:
            m = len(self.lines)
        t = time.monotonic()
        verb = "connect"
        with self.lock:
            self.p.stdin.write(f"connect {peer}\n")
            self.p.stdin.flush()
            got = self.wait(lambda l: l.startswith(("ok\tconnect\t", "err\tconnect\t")), 300, m)
        took = round(time.monotonic() - t, 2)
        with self.cv:
            lines = self.lines[m:]
        failed = [(round(tl - t, 2), l.split("\t", 3)[3]) for tl, l in lines
                  if l.startswith(f"event\tdial-failed\t{peer}\t")]
        if not got:
            return False, "no answer", took, failed
        f = got[1].split("\t", 2)
        return f[0] == "ok", f[2] if len(f) > 2 else "", took, failed

    def begin_connect(self, peer):
        """Start a connect and return its event marker and monotonic start.

        The CLI's `ok connect` acknowledges queueing, not an established QUIC
        session. M17 gates must therefore observe `dial-failed` and `session`
        events after this marker rather than treating that acknowledgement as
        the result.
        """
        with self.cv:
            marker = len(self.lines)
        started = time.monotonic()
        with self.lock:
            self.p.stdin.write(f"connect-async {peer}\n")
            self.p.stdin.flush()
        got = self.wait(lambda l: l.startswith(("ok\tconnect-async\t", "err\tconnect-async\t")), 30, marker)
        return bool(got and got[1].startswith("ok\tconnect-async\t")), started, marker

    def wait_event(self, kind, peer, timeout, marker):
        return self.wait(
            lambda l: l.startswith(f"event\t{kind}\t{peer}"), timeout, marker
        )

    def events(self, kind, peer, since=0):
        with self.cv:
            return [(t, l) for t, l in self.lines[since:] if l.startswith(f"event\t{kind}\t{peer}")]


def classify(reason):
    """Checker 4's reading of one failure, by the words the node uses."""
    if reason is None:
        return None
    if reason.startswith("not found"):
        return "not found"
    # "its record is stale" (abandoned) contains "is stale" (moved): first.
    if "record is stale" in reason or "Abandoned" in reason:
        return "abandoned"
    if "is stale" in reason or "Stale" in reason:
        return "stale"
    # No newer record leaves the address unverified, not proven stale. Keep
    # the OD-4 caveat in the node's text, but classify this as unreachable.
    if "may be stale" in reason:
        return "unreachable"
    if ("look same" in reason or "look the same from here" in reason
            or "Unreachable" in reason):
        return "unreachable"
    return "other"


def findable(u, key, addr, limit, poll=0.5, newer_than=None):
    """Checker 1 and 2. Seconds until member `u`'s lookup for `key` returns
    a record carrying `addr` - the address the harness gave the subject or
    moved it to - or None within `limit`."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit:
        g = u.get(key)
        if (g and g["addrs"] and addr in g["addrs"].split(",")
                and (newer_than is None or int(g["seq"]) > newer_than)):
            return round(time.monotonic() - t0, 2)
        time.sleep(poll)
    return None


def move(h, i, new):
    """Changes subject i's IP under it, as a network change does: the
    process keeps running, its sockets stay bound to 0.0.0.0, and packets
    for the old address go nowhere."""
    old = h.nodes[i].ip
    sh(f"ip route add {new}/32 dev h{i}")
    sh(f"ip netns exec n{i} sh -c 'ip addr add {new}/32 dev e{i} && ip addr del {old}/32 dev e{i}"
       f" && ip route replace {GW}/32 dev e{i} && ip route replace default via {GW} dev e{i}'")
    sh(f"ip route del {old}/32 dev h{i}")
    h.nodes[i].ip = new
    if hasattr(h.nodes[i], "private"):
        h.nodes[i].private = f"{new}:{PRIV}"


def moved_ip(i, generation=0):
    """A non-overlapping destination for one or many real address moves."""
    return f"10.99.{2 + generation + i // 200}.{i % 200 + 10}"


def publish(args):
    """M17. Self-test of every checker first, each against a fault it exists
    to see and against the same thing without the fault; then the gates;
    then the OD-6 timings, from the gates' own events and the nodes' logs."""
    h = H(args, binary=args.binary)
    R = {"profile": args.profile, "selftest": {}, "gates": {}}
    N = args.n
    subjects = []

    def mutation_failure():
        """Persist the first escaped checker in a fast mutant run."""
        R["selftest_all_detected"] = all(
            value["detected"] for value in R["selftest"].values()
        )
        R["gate_assertions"] = {}
        R["failed_gates"] = [key for key, value in R["selftest"].items()
                             if not value["detected"]]
        R["pass"] = False
        return R

    def subject(k, **kw):
        i = N + k
        h.net.add(i)
        h.net.netem(i, PROFILES[args.profile])
        s = h.nodes[i] = Subject(h, i, **kw)
        subjects.append(s)
        return s

    try:
        h.preflight(N + 12)
        h.boot(N)
        R["converged_after_s"] = h.converge(limit=args.converge_s)[0]
        pool = [h.nodes[i] for i in h.members() if i >= SEEDS]
        random.shuffle(pool)
        unrelated = iter(pool)      # a fresh member for each lookup poller
        startup = {}                # subject -> findable seconds after start

        def measure_startup(s):
            u = next(unrelated)
            t = findable(u, s.id, s.private, args.findable_s)
            startup[s.i] = None if t is None else round(time.monotonic() - s.started, 2)
            return startup[s.i]

        # --- self-test 1: findable -----------------------------------------
        # Fault: a node whose only bootstrap address answers nothing cannot
        # publish, so its record must be reported not findable.
        ghost = subject(0, boot=["10.99.250.250:47100"])
        ctl = subject(1)
        f_ghost, f_ctl = par(measure_startup, [ghost, ctl])
        ghost.kill()
        R["selftest"]["1_findable"] = {"fault_findable_after_s": f_ghost, "control_findable_after_s": f_ctl,
                                       "detected": f_ghost is None and f_ctl is not None}
        log("self-test 1", R["selftest"]["1_findable"])
        if args.selftest_only and not R["selftest"]["1_findable"]["detected"]:
            return mutation_failure()

        a = subject(2)
        mover = subject(3)
        par(measure_startup, [a, mover])
        for s in (ctl, mover):
            a.call(f"accept {s.id}")
            s.call(f"accept {a.id}")

        # --- self-test 2: propagated ----------------------------------------
        # Fault: the truth says the node moved, and it did not. The checker
        # must not find the new address however long it waits (a republish
        # and then some), and must still find the old one.
        observer = next(unrelated)
        before_move = observer.get(mover.id)
        before_seq = int(before_move["seq"]) if before_move else None
        new = moved_ip(mover.i)
        f_fault = findable(next(unrelated), mover.id, f"{new}:{PRIV}", REPUBLISH + 15)
        f_old = findable(next(unrelated), mover.id, mover.private, 10)
        # Control: the move made.  Gate 2 below measures the reconnect; this
        # self-test is only about whether the findability checker sees a move.
        move(h, mover.i, new)
        f_ctl2 = findable(observer, mover.id, f"{new}:{PRIV}", REPUBLISH + 30,
                          newer_than=before_seq)
        R["selftest"]["2_propagated"] = {"fault_new_found_after_s": f_fault, "fault_old_still_found": f_old is not None,
                       "control_old_seq": before_seq,
                       "control_new_found_after_s": f_ctl2,
                       "detected": (before_seq is not None and f_fault is None
                                    and f_old is not None and f_ctl2 is not None)}
        log("self-test 2", R["selftest"]["2_propagated"])
        if args.selftest_only and not R["selftest"]["2_propagated"]["detected"]:
            return mutation_failure()

        # --- self-test 4: stale versus unreachable -------------------------
        # Fault: a peer at its current address, with a fresh record, that
        # drops everything from A. Silent exactly as a stale address is; it
        # must read as unreachable, not stale.
        h.net.rules(ctl.i, [f"-A INPUT -s {a.ip} -j DROP"])
        ok4, answer4, took4, failed4 = a.connect(ctl.id)
        h.net.heal([ctl.i])
        fault4 = classify(failed4[0][1] if failed4 else (None if ok4 else answer4))
        R["selftest"]["4_stale"] = {"fault_firewalled_read_as": fault4, "fault_answer": answer4[:300],
                                    "detected": fault4 == "unreachable"}
        log("self-test 4", {k: v for k, v in R["selftest"]["4_stale"].items() if "answer" not in k})
        if args.selftest_only and not R["selftest"]["4_stale"]["detected"]:
            return mutation_failure()

        # --- self-test 3: not found -----------------------------------------
        # Fault: the peer is online. Control: an ID nobody ever published.
        ok3, answer3, _, _ = a.connect(ctl.id)
        ghost_id = rand_id()
        a.call(f"accept {ghost_id}")
        okg, answerg, tookg, _ = a.connect(ghost_id)
        nf = lambda ok, ans: (not ok) and classify(ans) == "not found"
        R["selftest"]["3_not_found"] = {"fault_online_reported_not_found": nf(ok3, answer3), "fault_answer": answer3[:120],
                                        "control_ghost_reported_not_found": nf(okg, answerg),
                                        "control_answer": answerg[:200], "control_seconds": tookg,
                                        "detected": not nf(ok3, answer3) and nf(okg, answerg)}
        log("self-test 3", {k: v for k, v in R["selftest"]["3_not_found"].items() if "answer" not in k})

        # M17's expiry control. A live peer must not read as not found; once
        # that same peer is offline for a strict record lifetime, it must. An
        # expiry-ignored mutant leaves its record resolvable and this checker
        # reports the fault before the real gates run.
        ctl.kill()
        time.sleep(LIFETIME + 1)
        ok_expired, answer_expired, took_expired, _ = a.connect(ctl.id)
        expired_not_found = (not ok_expired) and classify(answer_expired) == "not found"
        R["selftest"]["3_offline_after_expiry"] = {
            "fault_offline_reported_not_found": expired_not_found,
            "fault_answer": answer_expired[:200],
            "after_offline_s": took_expired,
            "control_online_reported_not_found": nf(ok3, answer3),
            "detected": expired_not_found and not nf(ok3, answer3),
        }
        log("self-test 3 expiry", {k: v for k, v in R["selftest"]["3_offline_after_expiry"].items()
                                    if "answer" not in k})

        if args.selftest_only and not R["selftest"]["3_offline_after_expiry"]["detected"]:
            return mutation_failure()

        # --- self-test 5: invite -------------------------------------------
        # Fault: the owner rejects. Control: the owner accepts.
        owner = subject(4, public=True)
        q1, q2 = subject(5), subject(6)
        par(measure_startup, [owner, q1, q2])

        def invited(q, accept):
            m = len(q.lines)
            q.call(f"request {owner.addr} {owner.id}")
            owner.wait(lambda l: l.startswith(f"event\trequest\t{q.id}"), 60)
            owner.call(f"{'accept' if accept else 'reject'} {q.id}")
            return q.wait(lambda l: l.startswith(f"event\tsession\t{owner.id}"), 60, m) is not None
        f5, c5 = invited(q1, False), invited(q2, True)
        R["selftest"]["5_invite"] = {"fault_rejected_has_session": f5, "control_accepted_has_session": c5,
                                     "detected": (not f5) and c5}
        log("self-test 5", R["selftest"]["5_invite"])
        R["selftest_all_detected"] = all(v["detected"] for v in R["selftest"].values())

        # Mutation runs need only the checker fault they target.  Retain the
        # normal non-zero `publish` contract and name every failed logical
        # gate in the persisted result, without spending another full gate
        # run after the self-test has already proved the mutant escaped it.
        if args.selftest_only:
            R["gate_assertions"] = {}
            R["failed_gates"] = [key for key, value in R["selftest"].items()
                                 if not value["detected"]]
            R["pass"] = R["selftest_all_detected"]
            return R

        # ===================================================================
        # Gates
        # ===================================================================
        b = subject(7)
        q3 = subject(8)
        par(measure_startup, [b, q3])
        a.call(f"accept {b.id}")
        b.call(f"accept {a.id}")

        # Gate 5: an invite, with the DHT running on both ends.
        g5 = invited(q3, True)
        R["gates"]["5_invite"] = {"session": g5, "pass": g5}

        # Gate 1: every subject that should be findable was, in the bound.
        found = {k: v for k, v in startup.items() if k != ghost.i}
        R["gates"]["1_findable"] = {"bound_s": args.findable_s, "subjects": len(found),
                                    "seconds_after_start": stats(list(found.values())),
                                    "missed": [k for k, v in found.items() if v is None],
                                    "pass": all(v is not None for v in found.values())}
        log("gate 1", R["gates"]["1_findable"])

        # Gates 2 and 4: B moves; A dials it straight after, from the old
        # record, while the move propagates.
        observer = next(unrelated)
        before_move = observer.get(b.id)
        before_seq = int(before_move["seq"]) if before_move else None
        new = moved_ip(b.i)
        changed_at = time.monotonic()
        move(h, b.i, new)

        # This observer is independent of A's reconnect.  Starting the clock
        # at the first externally readable newer record, rather than at A's
        # command, makes a stale 20-second dial visible to the gate.
        observed_new = {}
        observed_started = time.monotonic()

        def observe_new_record():
            observed_new["after_s"] = findable(
                observer, b.id, f"{new}:{PRIV}", REPUBLISH + 30,
                newer_than=before_seq,
            )

        observer_thread = threading.Thread(target=observe_new_record)
        observer_thread.start()
        queued, dial_started, marker = a.begin_connect(b.id)
        session = a.wait_event("session", b.id, DIAL_TIMEOUT + 10, marker)
        deadline = changed_at + LIFETIME
        retried = False
        while session is None and time.monotonic() < deadline:
            retried = True
            retry_queued, _, retry_marker = a.begin_connect(b.id)
            queued = queued or retry_queued
            session = a.wait_event(
                "session", b.id,
                min(DIAL_TIMEOUT + 10, max(0, deadline - time.monotonic())),
                retry_marker,
            )
        ok = queued and session is not None
        observer_thread.join(REPUBLISH + 35)
        prop = observed_new.get("after_s")
        new_record_at = (
            observed_started + prop if prop is not None else None
        )
        redial_after_new_record = (
            round(session[0] - new_record_at, 2)
            if session is not None and new_record_at is not None else None
        )
        failed_events = a.events("dial-failed", b.id, marker)
        failed = [
            (round(t - dial_started, 2), line.split("\t", 3)[3])
            for t, line in failed_events
        ]
        answer = ""
        took = round((session[0] if session else time.monotonic()) - dial_started, 2)
        redial_after_move = round((session[0] if session else time.monotonic()) - changed_at, 2)
        # A stale address can legitimately time out before the newer signed
        # record becomes visible under loss. Gate the useful outcome instead:
        # established redial within five seconds of independent findability.
        R["gates"]["2_propagated"] = {"bound_s": LIFETIME, "refresh_s": REPUBLISH,
                                      "old_seq": before_seq,
                                      "retried_after_new_record": retried,
                                      "new_address_findable_after_move_s": prop,
                                      "successful_redial_after_new_address_s": redial_after_new_record,
                                      "redial_bound_after_new_address_s": REDIAL_AFTER_NEW_RECORD,
                                      "stale_dial_failed_before_redial": bool(failed),
                                      "successful_redial_after_move_s": redial_after_move,
                                      "pass": before_seq is not None and prop is not None and prop <= REPUBLISH + 30
                                      and redial_after_move <= LIFETIME and ok
                                      and redial_after_new_record is not None
                                      and redial_after_new_record <= REDIAL_AFTER_NEW_RECORD
                                      }
        log("gate 2", R["gates"]["2_propagated"])
        R["gates"]["4_stale"] = {"m12_no_newer_control": R["selftest"]["4_stale"]["fault_firewalled_read_as"],
                                 "stale_dial_failures": len(failed),
                                 "connected": ok, "connect_seconds": took, "answer": answer[:300],
                                 "pass": R["selftest"]["4_stale"]["fault_firewalled_read_as"] == "unreachable"
                                 and not failed and ok}
        log("gate 4", {k: v for k, v in R["gates"]["4_stale"].items() if k not in ("reasons", "answer")})

        # Gate 3: B goes offline for good. A dialled the session, so A's
        # reconnect loop runs (architecture.md 10); it must end by reporting
        # B not found, before the record-lifetime bound, and dial no more.
        # The lifetime starts at the signed `published_at`, not at process
        # death: the old result measured the latter and made a valid record's
        # pre-existing age look like an expiry overrun.
        publishes = []
        for published, line in h.logs(b.i, r"record published"):
            stamp = re.search(r"published_at=(\d+)", line)
            stored = re.search(r"stored=(\d+)", line)
            if stamp and stored and int(stored.group(1)) > 0:
                publishes.append(int(stamp.group(1)))
        published_at = max(publishes) if publishes else None
        since = len(a.lines)
        t_off = time.monotonic()
        off_wall = time.time()
        b.kill()
        expiry_probe = {}

        def check_strict_expiry():
            if published_at is None:
                return
            # `published_at` is whole seconds and `Records::get` expires
            # strictly (`now > expires_at`). Leave a full extra two seconds
            # beyond the nominal lifetime so neither integer-second
            # truncation nor a cross-container clock edge probes at equality.
            time.sleep(max(0, published_at + LIFETIME + 10 - time.time()))
            expiry_probe["record"] = observer.get(b.id)
            expiry_probe["after_published_s"] = round(time.time() - published_at, 1)

        expiry_thread = threading.Thread(target=check_strict_expiry)
        expiry_thread.start()
        limit = LIFETIME + 180
        got = a.wait(lambda l: l.startswith(f"event\tdial-failed\t{b.id}\t")
                     and classify(l.split("\t", 3)[3]) in ("not found", "other"), limit, since)
        reported = got and got[1].split("\t", 3)[3]
        at = got and round(got[0] - t_off, 1)
        age_at_offline = (round(off_wall - published_at, 1)
                          if published_at is not None else None)
        after_last_publish = (round(age_at_offline + at, 1)
                              if age_at_offline is not None and at is not None else None)
        expiry_thread.join(60)
        expiry_result = expiry_probe.get("record")
        expiry_checked = "record" in expiry_probe
        served_after_expiry = expiry_result is not None and expiry_result.get("seq") is not None
        time.sleep(60)
        after = [l for t, l in h.logs(a.i, r"reconnect failed|dial from the record failed")
                 if got and t > time.time() - (time.monotonic() - got[0])]
        diagnoses = [re.search(r"diagnosis=(\w+)", l).group(1) for _, l in h.logs(a.i, r"dial from the record failed")
                     if re.search(r"diagnosis=(\w+)", l)]
        gave_up = h.logs(a.i, r"giving up: the peer did not answer inside the budget")
        R["gates"]["3_not_found"] = {"reported": reported and reported[:200], "after_offline_s": at,
                                     "published_at": published_at, "record_age_at_offline_s": age_at_offline,
                                     "after_last_publish_s": after_last_publish,
                                     "expiry_probe_after_published_s": expiry_probe.get("after_published_s"),
                                     "expiry_probe_completed": expiry_checked,
                                     "served_after_expiry": served_after_expiry,
                                     "bound_s": LIFETIME + 36 + 40, "diagnoses_in_order": diagnoses,
                                     "dials_after_report": len(after), "gave_up_on_budget": len(gave_up),
                                     "pass": bool(got) and classify(reported) == "not found" and not after
                                     and not gave_up and published_at is not None
                                     and after_last_publish is not None
                                     and after_last_publish <= LIFETIME + 36 + 40
                                     and expiry_checked and not served_after_expiry}
        log("gate 3", R["gates"]["3_not_found"])

        # --- OD-6 timings, from the subjects' own logs ------------------------
        pubs = []
        for sj in subjects:
            for t, l in h.logs(sj.i, r"record published"):
                m = re.search(r"stored=(\d+) elapsed_ms=(\d+)", l)
                if m:
                    pubs.append((sj.i, t, int(m.group(1)), int(m.group(2))))
        gaps = []
        for sj in subjects:
            ts = [t for i, t, st, ms in pubs if i == sj.i and st > 0]
            gaps += [round(y - x, 1) for x, y in zip(ts, ts[1:])]
        R["od6"] = {"publish_ms": stats([ms for _, _, st, ms in pubs if st > 0]),
                    "publish_stored": stats([st for _, _, st, _ in pubs]),
                    "publishes": len(pubs), "republish_gap_s": stats(gaps),
                    # From A's `connect` to its report of the stale dial: the
                    # self-test's move and the gate's.
                    "stale_dial_failed_after_s": [t for t, _ in failed],
                    "successful_redial_after_new_address_s": [redial_after_new_record]
                    if redial_after_new_record is not None else [],
                    "address_change_to_successful_redial_s": [redial_after_move] if ok else []}
    finally:
        # The subjects' logs outlive the container, so a failed gate can be
        # read afterwards.
        keep = os.path.join(args.out, f"publish-logs{('-' + args.tag) if args.tag else ''}")
        os.makedirs(keep, exist_ok=True)
        for sj in subjects:
            for path in glob.glob(f"{ROOT}/n{sj.i}/data/p2pchat*.log"):
                sh(f"cp {path} {keep}/n{sj.i}.log", check=False)
        h.teardown()
    R["gate_assertions"] = {g: v["pass"] for g, v in R["gates"].items()}
    R["failed_gates"] = [g for g, passed in R["gate_assertions"].items() if not passed]
    R["pass"] = R["selftest_all_detected"] and not R["failed_gates"]
    return R

# ---------------------------------------------------------------------------

def redials(args):
    """Twenty real stale-address reconnects per profile, without expiry waits.

    Each sample starts a fresh client so it has no session or cached outcome,
    waits until it has actually begun the stale dial, then moves the same live
    peer.  The observer and all timestamps are independent of that client.
    """
    h = H(args, binary=args.binary, env={"P2PCHAT_M17_TRACE": "1"})
    offsets = [float(value) for value in args.move_offsets.split(",")]
    if not offsets or any(offset < 0 for offset in offsets):
        raise SystemExit("--move-offsets must be one or more non-negative seconds")
    R = {"profile": args.profile, "redial_bound_s": REDIAL_AFTER_NEW_RECORD,
         "findability_bound_s": REPUBLISH + 30,
         "end_to_end_bound_s": REPUBLISH + 30 + REDIAL_AFTER_NEW_RECORD,
         # A start every second plus a three-second lookup budget is the
         # five-second claim below. The product caps concurrency at four.
         "retry_probe_starts_s": "every 1s while stale dial is in flight",
         "lookup_budget_s": 3, "move_offsets_s": offsets, "samples": []}
    b = None
    try:
        h.preflight(args.n)
        h.boot(args.n)
        R["converged_after_s"] = h.converge(limit=args.converge_s)[0]
        b_i = args.n
        h.net.add(b_i)
        h.net.netem(b_i, PROFILES[args.profile])
        b = h.nodes[b_i] = Subject(h, b_i)
        observer = h.nodes[SEEDS]
        if findable(observer, b.id, b.private, args.findable_s) is None:
            raise RuntimeError("initial moved-peer record was not externally findable")

        for sample in range(args.redials):
            before = observer.get(b.id)
            before_seq = int(before["seq"]) if before and before["seq"] else None
            old_addr = b.private
            if before_seq is None or old_addr not in (before.get("addrs") or "").split(","):
                raise RuntimeError(f"sample {sample}: old record was not externally readable")

            a_i = args.n + 1 + sample
            h.net.add(a_i)
            h.net.netem(a_i, PROFILES[args.profile])
            a = h.nodes[a_i] = Subject(h, a_i)
            a.call(f"accept {b.id}")
            b.call(f"accept {a.id}")
            a_mark, b_mark = len(a.lines), len(b.lines)
            member_marks = {i: len(n.lines) for i, n in h.nodes.items() if not n.client and n.alive}
            # A loopback-old address can handshake before a user-space trace
            # line is observed.  Silence it only until the stale dial has
            # begun, then remove the rule immediately after the real move so
            # the new address is an ordinary profile dial.
            h.net.rules(b.i, [f"-A INPUT -s {a.ip} -j DROP"])
            queued, dial_started, marker = a.begin_connect(b.id)
            stale_started = a.wait(
                lambda line: ("m17 trace stale dial started" in line
                              or line.startswith(f"event\tphase\t{b.id}")),
                30,
                a_mark,
            )
            if not queued or stale_started is None:
                with a.cv:
                    tail = [line for _, line in a.lines[a_mark:]][-20:]
                raise RuntimeError(
                    f"sample {sample}: stale dial did not start; queued={queued}; tail={tail}"
                )

            offset = offsets[sample % len(offsets)]
            # Deliberately de-phase the address change from the probe clock.
            # This makes a short result depend on the actual cadence rather
            # than repeatedly landing just before a favourable probe.
            remaining = offset - (time.monotonic() - stale_started[0])
            if remaining > 0:
                time.sleep(remaining)
            new = moved_ip(b.i, sample + 1)
            changed_at = time.monotonic()
            move(h, b.i, new)
            h.net.heal([b.i])
            observed = {}
            observed_started = time.monotonic()

            def observe():
                observed["after_s"] = findable(
                    observer, b.id, f"{new}:{PRIV}", REPUBLISH + 30,
                    newer_than=before_seq,
                )

            observer_thread = threading.Thread(target=observe)
            observer_thread.start()
            redial_started = a.wait(
                lambda line: line.startswith("m17 trace redial started"),
                REPUBLISH + 30 + REDIAL_AFTER_NEW_RECORD,
                a_mark,
            )
            # M17's five-second bound ends when the fresh dial starts.  The
            # following session is intentionally separate: it owns its own
            # dial budget under packet loss.
            session = a.wait_event("session", b.id, DIAL_TIMEOUT + 10, marker)
            observer_thread.join(REPUBLISH + 35)
            prop = observed.get("after_s")
            new_record_at = observed_started + prop if prop is not None else None
            redial = (round(redial_started[0] - new_record_at, 3)
                      if redial_started is not None and new_record_at is not None else None)
            end_to_end = (round(redial_started[0] - changed_at, 3)
                          if redial_started is not None else None)
            detection = b.wait(lambda line: "m17 trace observed address changed" in line and new in line,
                               30, b_mark)
            published = b.wait(lambda line: "m17 trace publish completed" in line and new in line,
                               REPUBLISH + 30, b_mark)
            stores = []
            for i, line_mark in member_marks.items():
                with h.nodes[i].cv:
                    lines = h.nodes[i].lines[line_mark:]
                for t, line in lines:
                    seq = re.search(r"seq=(\d+)", line)
                    if ("m17 trace store landed" in line and fp(b.id) in line and seq
                            and int(seq.group(1)) > before_seq):
                        stores.append(t)
            with a.cv:
                trace = [{"after_move_s": round(t - changed_at, 3), "line": line}
                         for t, line in a.lines[a_mark:] if "m17 trace" in line]
            probe_rpcs = sum(
                int(match.group(1)) for item in trace
                for match in [re.search(r"rpcs=(\d+)", item["line"])] if match
            )
            probe_starts = sum("newer lookup started" in item["line"] for item in trace)
            failed = a.events("dial-failed", b.id, marker)
            redial_ended = redial_started[0] if redial_started is not None else time.monotonic()
            sample_result = {
                "sample": sample + 1,
                "move_offset_s": offset,
                "old_seq": before_seq,
                "old_addr": old_addr,
                "new_addr": f"{new}:{PRIV}",
                "stale_dial_started_after_move_s": round(stale_started[0] - changed_at, 3),
                "change_detection_s": round(detection[0] - changed_at, 3) if detection else None,
                "publish_completed_s": round(published[0] - changed_at, 3) if published else None,
                "newer_store_landed_s": round(min(stores) - changed_at, 3) if stores else None,
                "new_address_findable_s": prop,
                "redial_after_findability_s": redial,
                "end_to_end_s": end_to_end,
                "session_established_s": (round(session[0] - changed_at, 3)
                                          if session is not None else None),
                "probe_starts": probe_starts,
                "probe_rpcs": probe_rpcs,
                "limiter_refusals_during_redial": h.rate_limited_between(changed_at, redial_ended),
                "stale_dial_failures": [line for _, line in failed],
                "trace": trace,
            }
            sample_result["pass"] = (
                redial_started is not None and prop is not None and prop <= REPUBLISH + 30
                and redial is not None and redial <= REDIAL_AFTER_NEW_RECORD
                and end_to_end is not None and end_to_end <= REPUBLISH + 30 + REDIAL_AFTER_NEW_RECORD
                and not failed and sample_result["limiter_refusals_during_redial"] == 0
            )
            R["samples"].append(sample_result)
            log("redial", args.profile, sample + 1,
                {k: sample_result[k] for k in ("new_address_findable_s", "redial_after_findability_s",
                                                 "end_to_end_s", "pass")})
            a.kill()
            # Each distribution point is one move of one fresh peer.  Reusing
            # B would make the next point depend on its prior reachability
            # watcher and record chain rather than just this redial.
            b.kill()
            if sample + 1 < args.redials:
                b_i = args.n + args.redials + 1 + sample
                h.net.add(b_i)
                h.net.netem(b_i, PROFILES[args.profile])
                b = h.nodes[b_i] = Subject(h, b_i)
                if findable(observer, b.id, b.private, args.findable_s) is None:
                    raise RuntimeError(f"sample {sample + 1}: fresh moved peer was not externally findable")
        R["redial_after_findability_s"] = stats([s["redial_after_findability_s"] for s in R["samples"]])
        R["end_to_end_s"] = stats([s["end_to_end_s"] for s in R["samples"]])
        R["session_established_s"] = stats([s["session_established_s"] for s in R["samples"]])
        R["change_detection_s"] = stats([s["change_detection_s"] for s in R["samples"]])
        R["publish_completed_s"] = stats([s["publish_completed_s"] for s in R["samples"]])
        R["newer_store_landed_s"] = stats([s["newer_store_landed_s"] for s in R["samples"]])
        R["new_address_findable_s"] = stats([s["new_address_findable_s"] for s in R["samples"]])
        R["probe_starts"] = stats([s["probe_starts"] for s in R["samples"]])
        R["probe_rpcs"] = stats([s["probe_rpcs"] for s in R["samples"]])
        R["limiter_refusals_during_redials"] = sum(
            s["limiter_refusals_during_redial"] for s in R["samples"]
        )
        R["pass"] = all(s["pass"] for s in R["samples"])
        return R
    finally:
        h.teardown()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", choices=["selftest", "gates", "trial", "publish", "redials"])
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--clients", type=int, default=3)
    p.add_argument("--profile", default="baseline", choices=list(PROFILES))
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--alpha", type=int, default=None)
    p.add_argument("--replication", type=int, default=None)
    p.add_argument("--rpc-timeout-ms", type=int, default=None)
    p.add_argument("--refresh-ms", type=int, default=30000)
    p.add_argument("--converge-s", type=int, default=120)
    p.add_argument("--gets", type=int, default=4)
    p.add_argument("--finds", type=int, default=2)
    p.add_argument("--kill", type=float, default=0.3)
    p.add_argument("--only", default=None, help="comma-separated gate numbers")
    p.add_argument("--binary", required=True,
                   help="exact executable to test; no default is permitted")
    p.add_argument("--env", action="append", default=[], help="K=V passed to every node")
    p.add_argument("--findable-s", type=int, default=30, help="M17 gate 1's bound")
    p.add_argument("--out", default="/out")
    p.add_argument("--tag", default="")
    p.add_argument("--trace-m16", action="store_true",
                   help="log each gate-5 confirmation Ping")
    p.add_argument("--selftest-only", action="store_true",
                   help="run M17 checker faults only (used by mutants)")
    p.add_argument("--redials", type=int, default=20,
                   help="real address moves in the redials scenario")
    p.add_argument("--move-offsets", default="0",
                   help="comma-separated seconds after stale dial begins (redials only)")
    args = p.parse_args()
    env = dict(e.split("=", 1) for e in args.env)
    if args.scenario == "selftest":
        R = selftest(args)
    elif args.scenario == "gates":
        only = {int(x) for x in args.only.split(",")} if args.only else None
        R = gates(args, binary=args.binary, env=env, only=only)
    elif args.scenario == "publish":
        R = publish(args)
    elif args.scenario == "redials":
        R = redials(args)
    else:
        R = trial(args, env)
    R["args"] = vars(args)
    binary, digest = verified_binary(args.binary)
    R["binary"] = {"path": binary, "sha256": digest}
    name = f"dht-{args.scenario}{('-' + args.tag) if args.tag else ''}.json"
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, name), "w", encoding="utf-8") as f:
        json.dump(R, f, indent=1, default=str)
    log("result", json.dumps({k: v for k, v in R.items()
                              if k in ("pass", "all_detected", "selftest_all_detected", "failed_gates")} or {"written": name}))
    if args.scenario == "publish" and not R["pass"]:
        raise SystemExit(f"M17 failed gates: {', '.join(R['failed_gates']) or 'selftest'}")


if __name__ == "__main__":
    main()
