# M17a evidence status

Superseded — do not cite as gate results:

- `dht-redials-m17b2-redials-baseline.json`
- `dht-redials-m17b2-redials-typical-final.json`
- `dht-redials-m17b2-redials-poor-final.json`

Those distributions used an unrelated observer's first read of the newer
record as their reference and gated a redial *start*. They may contain
negative observer-relative values and are retained only for auditability.

The replacement records one atomic on-disk sample at a time. Its causal
reference is the member-side `STORE`-accepted timestamp and it reports, per
profile and per sample, `move_to_session_established_s` and
`store_accepted_to_session_established_s`. The gate is on the former; neither
metric accepts a negative value. Containers share the host monotonic clock;
that is recorded beside the metric as an explicit harness assumption.
