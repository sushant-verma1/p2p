# M17a evidence ledger

| item | status | evidence file |
|---|---|---|
| Schedule-derived causal redial gate, 20 samples/profile | pending rerun from HEAD | replacement `dht-redials-m17a-head-*.json` |
| Per-lookup duration/success and dialler-position replication lag | pending instrumentation and run | replacement redial JSON |
| Move-to-STORE timeline and reachability/re-publish ordering | pending instrumentation and run | replacement redial JSON |
| HEAD/clean-tree binary provenance refusal | pending harness enforcement | provenance refusal transcript |
| Product-default ten-minute client peer-down load | pending | `dht-peerdown-m17a-product.json` |
| Fake-clock half-allowance schedule test | pending | Rust test output |
| Refused-lookup-as-empty mutation | pending rerun | mutant transcript |
| Slow-binary REDIAL self-test | pending rerun | mutant transcript |
| Netem mutant table, including dht-bypass | pending rerun | `m17a-mutants.json` |
| Per-node eviction / limiter-window evidence | pending recheck | gate-5 result JSON |
| FIND/GET kill latency (reported, due before M18c) | pending | trial result JSON |
| Loopback redial, 20 runs (reported) | pending | redial result JSON |
| `tail.py --handshakes 100`, clean-HEAD hashed Linux binary | baseline complete: 100/100; p99 dial 0.003 s; SHA-256 `51abe573c8a954cf4bb4c5d252d38f20f905c7b3f7ac6d42b1bc518742739fe1` | `tail-m17b-handshakes-baseline.json` |
| `tail.py --handshakes 100`, typical and poor | owed: typical did not complete before the run was stopped; poor not started | no result — do not substitute the baseline result |
| Client destination-pacer property/mutations | code checked; focused test binary link is currently blocked by a locked Windows test executable | `p2pchat-net::public::tests` |
| cargo audit raw output / deny ignores (reported) | pending container run | audit output / `deny.toml` |
| Branch hygiene inventory | pending final WIP audit | git inventory transcript |
