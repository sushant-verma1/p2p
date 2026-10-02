# netem harness

Runs the debug node (`p2pchat node`) in two containers with `tc netem` on the
egress of both, and times what the user would wait for. M12a's margins and
M12b's timeout choices come from here. Any later timeout change should be
measured here too, the same way.

Delay applies on both egresses, so the round trip is twice the profile's
delay: `bad` is 800 ms.

| profile     | netem                                     |
|-------------|-------------------------------------------|
| `baseline`  | none                                      |
| `typical`   | `delay 60ms 20ms distribution normal loss 0.5%` |
| `poor`      | `delay 150ms 50ms loss 3% reorder 1%`     |
| `bad`       | `delay 400ms loss 8%`                     |
| `bursty`    | `delay 400ms loss 8% 25%`                 |
| `bursty-ge` | `delay 400ms loss gemodel 6% 69% 100% 0%` |

### netem's loss correlation does not make bursts

`bursty` is a trap, and it cost M12b an afternoon. `loss 8% 25%` reads as "8%
loss, 25% correlated", but netem's correlation parameter does not produce
bursts. It does not even keep the rate: the loss drops to about 1% per leg and
the runs are no longer than independent loss would give. The Gilbert-Elliott
model, `loss gemodel`, is what produces bursts. `bursty-ge` is what `bursty`
was meant to be: 8% loss, where a loss follows a loss 31% of the time
(0.25 + 0.75 × 0.08), for a mean burst of 1.45.

Measured by the harness, 2000 pings at 10 ms each (round trip, so both
directions' loss):

| profile     | netem                     | loss   | loss runs | mean run | longest |
|-------------|---------------------------|--------|-----------|----------|---------|
| `bad`       | `loss 8%`                 | 16.35% | 273       | 1.20     | 5       |
| `bursty`    | `loss 8% 25%`             | 1.95%  | 36        | 1.08     | 2       |
| `bursty-ge` | `loss gemodel 6% 69% 100% 0%` | 16.95% | 226   | 1.50     | 7       |

Independent 8% a leg is about 15.4% round trip with runs averaging about
1.2, which is what `bad` shows. `bursty` has neither the rate nor the runs.
`bursty-ge` has the rate, longer runs and fewer of them. Its 16.95% is about
8.9% a leg, a little over the 8% intended.

Every run starts by pinging 2000 times and records the measured loss and
loss-run lengths, so check them before trusting a profile.

## Setup

Needs Docker and Python 3. Nothing is installed on the host.

From the repo root:

```sh
docker build -t p2p-wan netem
docker volume create p2p-target
# Linux / macOS
docker run --rm -v "$PWD:/p2p:ro" -v p2p-target:/target -e CARGO_TARGET_DIR=/target \
    -w /p2p p2p-wan cargo build --release -p p2pchat
# Git Bash: MSYS rewrites `-w /p2p` into C:/Program Files/Git/p2p unless told not to
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/p2p:ro" -v p2p-target:/target \
    -e CARGO_TARGET_DIR=/target -w /p2p p2p-wan cargo build --release -p p2pchat
```

PowerShell rejects `"$PWD:..."` (a `:` after a variable name), so use the braced form there:

```powershell
docker run --rm -v "${PWD}:/p2p:ro" -v p2p-target:/target -e CARGO_TARGET_DIR=/target -w /p2p p2p-wan cargo build --release -p p2pchat
```

Cold, the build takes a few minutes. Afterwards `/target/release/p2pchat` in the
volume is the binary every run uses.

The containers mount `p2p-target` read-only and run `/target/release/p2pchat`.
They are created fresh, with `--cap-add=NET_ADMIN`, by every run.

## Running

```sh
python netem/wan.py [PROFILE ...]    # the full M12a run; all profiles if none named
python netem/tail.py PROFILE [--requests N] [--handshakes N] [--dials N] [--strand N]
```

`wan.py` covers the following for each profile:
- ping;
- connection requests;
- the first dial after acceptance;
- 30 handshakes;
- the give-up paths;
- 240 messages each way, then a 45 s idle;
- killing the acceptor, queueing 50 messages, then the restart, resync and backoff.

`tail.py` takes many samples of one thing:
- `--requests`: time to answer a request against a reachable node. Alice restarts every 5 requests, because the product stranger limit is 10 a minute, polls included; the restarts are more than enough.
- `--handshakes`: bob restarts and redials. Each dial is split into connect and §6. Each sample also waits for alice's session before bob quits (see below).
- `--dials`: `connect` to a port nobody answers on. Records whether the error carries the guidance.
- `--dialbacks`: M14a, M14b. Bob asks alice's public node for a reachability dial-back, and alice forwards it to carol, a third container started for this mode with the same netem profile. Three timings are recorded, each from where it happens: carol's dial from her log (what `dial_back_timeout` bounds), alice's whole forward from hers (what `forward_timeout` bounds), and bob's whole request (what `request_timeout` bounds). Measuring past the shipped limits needs a binary with those limits and the rate limits raised. M14b used `/target/bin/p2pchat-forward-wide`: dial-back 60 s, forward 80 s, request 90 s, rate limits lifted.
- `--strand`: M12c. Each trial starts both nodes from nothing, and drops UDP to alice's private port with iptables before bob's request. Alice accepts, bob's first dial fails, the port reopens, and the trial records whether bob's poller still reaches a session and how long after the reopen.

Results go to `wan-PROFILE.json` / `tail-PROFILE.json` in the current
directory, so run it from somewhere outside the repo.

Environment:
- `WAN_PAIR`: container-pair name (default `wan`). Give each concurrent run its own.
- `P2PCHAT_BIN`: the binary inside the container. To measure a timeout past its current limit, build a variant with the limit raised into `/target/bin/` and point at it. M12b's request and handshake numbers used a copy with both raised to 30 s.
- Any other `P2PCHAT_*` variable, e.g. `P2PCHAT_DIAL_TIMEOUT_MS=60000`, is passed to the nodes.
- In Git Bash, also set `MSYS2_ENV_CONV_EXCL=P2PCHAT_BIN`, or the path gets rewritten into a Windows one.

Bob reports a session once `HELLO_CONFIRM` is written, not once alice has it,
so both scripts wait for alice's session before quitting bob, and count the
samples where it never came as `alice_missed`. Before M12c they quit bob at
once. If that confirm was lost, nothing resent it, and 14 s later alice logged
`handshake timed out` on a session bob had counted: 5 warnings in M12c's
sweep, all spurious.

Timestamps are the host's `perf_counter` when each stdout line arrives through
`docker exec`, so they include a few ms of pipe.

## DHT simulation (M16)

`dht.py` runs N `p2pchat dht` nodes in one privileged container, each in its
own network namespace with its own IP, and drives them over their stdin and
stdout. `netem` goes on each namespace's egress and `iptables` into each
namespace's own filter table. Churn is `kill -9` of a node's process. The
nodes are routed through the container's namespace, not bridged: see
"Why routed" below.

```sh
docker build -t p2p-wan netem            # python3 is in the image from M16
# the release binary, as in Setup above; then, from the repo root:
MSYS_NO_PATHCONV=1 docker run --rm --privileged -v p2p-target:/target:ro \
    -v "$(pwd -W)/netem:/h:ro" -v "$OUT:/out" p2p-wan python3 -u /h/dht.py selftest
# ... dht.py gates  [--only 1,2,...] [--binary /target/bin/p2pchat-MUTANT]
# ... dht.py trial  --k K --alpha A --replication R [--profile poor] [--kill 0.3]
```

`--n` sets the members (default 50), `--clients` the clients (3),
`--refresh-ms` the refresh and liveness interval (30 s here, 15 min shipped),
and `--profile` a netem profile from the table above. Results go to
`/out/dht-SCENARIO[-TAG].json`.

**Ground truth is the harness's own.** It uses the IDs the nodes print at
startup, the harness's record of who is alive and what each node published,
and XOR distance recomputed in Python. A table, a lookup answer or a fetched
record is compared against that truth, and nothing a node says about the
network is trusted.

**`selftest` comes first.** It injects each fault a checker exists for and
requires the checker to report it. It then removes the fault and requires the
checker to pass:
1. a node whose only bootstrap address answers nothing is reported not joined;
2. a node that can reach only one seed keeps the network unconverged, and
   once it is released the network converges;
3. a record republished behind the harness's back is reported as a wrong
   value, and once the truth is updated it is reported right;
4. a partition is first shown to be real (no lookup crosses it); a "heal"
   that is never applied is reported as not healed, and the real heal is
   seen to heal;
5. gate 4's checker: a node with refresh switched off is reported as not
   refreshing.

**Preflight.** Before any fault goes in, every namespace pings every other.
A network that cannot carry a ping cannot carry a gate, and the run stops.

### Why routed

The first 50-node self-test failed its positive controls: healthy nodes were
evicted, and RPCs timed out at exactly 20 s with processes idle. No interface,
softnet or socket-receive counter showed a drop. `dmesg` did:
`neighbour: arp_cache: neighbor table overflow!`. On a bridge every node ARPs
for every other, so 50 nodes need about 2450 neighbour entries. The kernel
caps entries across all namespaces together (`gc_thresh3`, 1024 by default).
Inside Docker Desktop that cap cannot be raised: the sysctl is not visible
even from PID 1's namespaces. Past the cap, sends fail with `ENOBUFS`, which
counts only as `SndbufErrors`. Twelve nodes need 132 entries, which is why
the smoke runs were clean. In the routed star, a node's one neighbour is the
gateway, so 50 nodes need about 100 entries. Run over the old bridge, the
preflight reports 519 unreachable pairs across 53 namespaces. Run over the
star, it reports none.

### Mutants

`mutants.py` builds one-edit copies of the node into `/target/bin/`. The
edits are `numeric` (XOR replaced with `|a - b|`), `noevict`, `noverify` and
`clientjoins`. The M17 edits are `m17-norepublish` (gate 2),
`m17-noexpiry` (gate 3), `m17-unreachable` (gate 4), and `m17-nodht` (gates
1 and 2). `serial` is not an edit: it is `--alpha 1`.

```sh
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/p2p:ro" -v p2p-target:/target \
    -v p2p-cargo:/usr/local/cargo/registry p2p-wan python3 /p2p/netem/mutants.py
```

It copies the source with fresh mtimes into a clean target directory. Copies
that kept their mtimes, sharing one target directory, once gave a result
with exactly the shape of two builds swapped: the original failed where the
`clientjoins` mutant should, and that mutant passed.

`wide` is not a mutant but an instrument: both public-node allowances lifted
to a million, so that `gates` measures the DHT's demand rather than what the
limiter let through (M16a, as M14a lifted the dial-back timeout).

### Demand (M16a)

Every `gates` run ends with `demand`: for each (server, source IP) pair, the
most requests in one limiter window, counted the way the limiter counts
(a window opens at a source's first request after its last one lapsed),
from the servers' own `admitted` and `rate limited` log lines. Split by
who asked whom (member, seed, client) and by the phase the peak fell in. With
`--binary /target/bin/p2pchat-wide` it is the whole demand; with the shipped
binary, refused requests are counted too, so the refusals must fall exactly
where the lifted run's demand exceeds the limit. That was checked before the
numbers were used (M16a: 33 refusals at the old 30, 0 lifted).

### Publish and lookup (M17)

```sh
MSYS_NO_PATHCONV=1 docker run --rm --privileged -v p2p-target:/target:ro \
    -v "$(pwd -W)/netem:/h:ro" -v "$(pwd -W)/netem/results:/out" \
    p2p-wan python3 -u /h/dht.py publish --profile baseline --tag baseline
```

The 50 `p2pchat dht` members are the network. The subjects are real
`p2pchat node` processes, each in a namespace of its own and bootstrapping
from the seeds. A subject moves by having its namespace's IP changed under
the running process (`move`). The self-test runs first, and each of the five
checkers must see its fault:

1. **findable** (the subject's own address, from an unrelated member's
   lookup): a node whose only bootstrap address is dead is never found; one
   that can publish is found;
2. **propagated**: the new address of a node that did not move is never found,
   even after a republish, and the old one still is; after a real move the
   new one is;
3. **not found**: a peer that is online is not reported not found; an ID
   nobody published is;
4. **stale versus unreachable**: a peer at its current address that drops the
   dialler reads as unreachable; a peer that moved reads as stale;
5. **invite**: a rejected request has no session; an accepted one does.

The gates then use fresh subjects, and OD-6's timings are taken from their
events and logs: each publish's `elapsed_ms`, the gaps between republishes,
the stale dial, and the time from an address change to the successful redial.
Each run writes `netem/results/dht-publish-PROFILE.json` and its retained
subject logs before returning. A failed self-test or gate records
`failed_gates` in that JSON and exits non-zero. Run the profiles sequentially
(`baseline`, `typical`, then `poor`) so every completed profile remains on
disk if a later one fails.
