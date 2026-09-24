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
- `--requests`: time to answer a request against a reachable node. Alice restarts every 5 requests, because the public node's limit is 10 a minute, polls included.
- `--handshakes`: bob restarts and redials. Each dial is split into connect and §6. Each sample also waits for alice's session before bob quits (see below).
- `--dials`: `connect` to a port nobody answers on. Records whether the error carries the guidance.
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
