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

`bursty` is a trap. netem's loss correlation is broken: it measures about 1%
per leg, not 8%. `bursty-ge` is what it was meant to be. It loses 8% of
packets, and a loss follows a loss 31% of the time (0.25 + 0.75 × 0.08). Every
run starts by pinging 2000 times and records the measured loss and loss-run
lengths, so check them before trusting a profile.

## Setup

Needs Docker and Python 3. Nothing is installed on the host.

```sh
docker build -t p2p-wan netem
docker volume create p2p-target
docker run --rm -v "$PWD:/p2p:ro" -v p2p-target:/target -e CARGO_TARGET_DIR=/target \
    -w /p2p p2p-wan cargo build --release -p p2pchat
```

The containers mount `p2p-target` read-only and run `/target/release/p2pchat`.
They are created fresh, with `--cap-add=NET_ADMIN`, by every run.

## Running

```sh
python netem/wan.py [PROFILE ...]    # the full M12a run; all profiles if none named
python netem/tail.py PROFILE [--requests N] [--handshakes N] [--dials N]
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
- `--handshakes`: bob restarts and redials. Each dial is split into connect and §6.
- `--dials`: `connect` to a port nobody answers on. Records whether the error carries the guidance.

Results go to `wan-PROFILE.json` / `tail-PROFILE.json` in the current
directory, so run it from somewhere outside the repo.

Environment:
- `WAN_PAIR`: container-pair name (default `wan`). Give each concurrent run its own.
- `P2PCHAT_BIN`: the binary inside the container. To measure a timeout past its current limit, build a variant with the limit raised into `/target/bin/` and point at it. M12b's request and handshake numbers used a copy with both raised to 30 s.
- Any other `P2PCHAT_*` variable, e.g. `P2PCHAT_DIAL_TIMEOUT_MS=60000`, is passed to the nodes.
- In Git Bash, also set `MSYS2_ENV_CONV_EXCL=P2PCHAT_BIN`, or the path gets rewritten into a Windows one.

Timestamps are the host's `perf_counter` when each stdout line arrives through
`docker exec`, so they include a few ms of pipe.
