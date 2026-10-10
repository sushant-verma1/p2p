# M17a evidence status

Superseded — do not cite as gate results:

- `dht-redials-m17b2-redials-baseline.json`
- `dht-redials-m17b2-redials-typical-final.json`
- `dht-redials-m17b2-redials-poor-final.json`

Those distributions used an unrelated observer's first read of the newer
record as their reference and gated a redial *start*. They may contain
negative observer-relative values and are retained only for auditability.

Also superseded (a harness audit found that these runs could select a
pre-move STORE with a newer sequence):

- `dht-redials-m17a-causal-baseline.json`
- `dht-redials-m17a-causal-typical.json`

The replacement records one atomic on-disk sample at a time. Its causal
reference is the member-side `STORE`-accepted timestamp and it reports, per
profile and per sample, `move_to_session_established_s` and
`store_accepted_to_session_established_s`. The gate is on the former; neither
metric accepts a negative value. Containers share the host monotonic clock;
that is recorded beside the metric as an explicit harness assumption.

Superseded after the bound audit (retain, do not cite as gate results):

- `dht-redials-m17a-causal2-baseline.json`
- `dht-redials-m17a-causal2-typical.json`
- `dht-redials-m17a-causal2-poor.json`

These files correctly use post-move STORE acceptance and atomic sample writes,
but they applied `REPUBLISH + 30 + 5 s` to move-to-session.  That is not the
M17a schedule-derived gate and incorrectly labels breached samples as passing.
They remain useful raw observations only; replacement runs must use the bound
recorded in their result JSON.
