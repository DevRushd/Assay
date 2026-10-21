# Observation history

`GET /api/v1/history` returns an asset's recorded observations, in time order,
together with the transitions derived between them. It is how a consumer reaches
the comparison in [`internal/temporal`](../internal/temporal): `scan` answers
*what is true now*, `history` answers *what did we observe, and what changed*.

```sh
curl 'http://localhost:8080/api/v1/history?asset=USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR'
```

This is a significant architectural addition — it is the first component in
Assay that retains anything — so the storage choice, the retention policy, and
the meaning of an empty history are recorded here rather than left implicit. The
comparison itself is specified in [transitions.md](transitions.md).

## Where observations come from

There is exactly one write path: **a successful `GET /api/v1/scan` records one
observation** for the asset it scanned. `history` never scans; it reads what has
been recorded.

```
GET /api/v1/scan?asset=CODE-ISSUER     →  scan, respond, and append an observation
GET /api/v1/history?asset=CODE-ISSUER  →  read the recorded observations, derive transitions
```

A scan that fails (the asset is not on the ledger, Horizon is down) records
nothing. A scan that succeeds but is `undetermined` **is** recorded, marked, and
returned — see [undetermined](#unknown-an-observation-is-incomplete).

Nothing schedules scans. History grows exactly as fast as someone scans, and
this document does not claim otherwise.

## The response

```json
{
  "asset": { "code": "USDZ", "issuer": "GAKTLPC4…U6XPR" },
  "state": "valid",
  "count": 2,
  "observations": [
    {
      "asset": { "code": "USDZ", "issuer": "GAKTLPC4…U6XPR" },
      "at": "2026-08-15T05:27:31Z",
      "mechanics": 6,
      "base_severity": "high",
      "severity": "high",
      "undetermined": false
    }
  ],
  "transitions": [],
  "latest_at": "2026-08-15T05:27:31Z",
  "latest_age_secs": 3542400,
  "retention": 256
}
```

| Field | Meaning |
| --- | --- |
| `asset` | the asset the history is for, echoed in `CODE`/`issuer` form |
| `state` | `valid`, `unknown`, or `missing` — the completeness of the history, not of any request |
| `reason` | plain-language explanation of a non-`valid` state; never omitted when the state is not `valid` |
| `count` | number of observations returned |
| `observations` | the recorded observations, oldest first, each with its own completeness |
| `transitions` | the derived difference between each consecutive pair; empty for fewer than two observations |
| `latest_at` | the most recent observation's time |
| `latest_age_secs` | its age in seconds, so a consumer can apply its own staleness policy |
| `retention` | the per-asset cap these observations were read against |

An observation carries `mechanics` (the full bitset, as a number), `base_severity`
and `severity` (level names), and `undetermined` with `undetermined_checks`. The
full bitset is stored rather than only the capability bits, so a later question
about a bit the comparison does not handle yet can be answered without re-taking
the observation.

`transitions` entries are the same shape `internal/temporal` produces from two
observations: `added`/`removed` capability bits with names, severity before and
after, and an `attribution` (`capability`, `reputation`, `both`, or `none`). They
are computed per request, never stored.

## Semantics

The four states below are why the history view has a `state` field at all:
"nothing changed", "we have never looked", and "we could not tell" are different
answers and must never render the same. That rule is repo-wide; it was stated
first in [checks.md](checks.md) and applied to a comparison in
[transitions.md](transitions.md).

### valid — history returned in time order, each observation marked for completeness

The ordinary case: at least one observation exists and every one returned is
complete. `state` is `valid`. An empty `transitions` array is a real answer — for
a single observation it means "there is no second point to compare against", and
the observation itself is returned so the caller can see which point exists.

### missing — no history, an explicit empty result

An asset nobody has scanned returns **HTTP 200** with `state: "missing"`,
`count: 0`, `observations: []`, `transitions: []`, and a `reason` saying so. It
is never a 404 and never silence: a consumer must be able to tell "we have never
looked" from "the request failed" without interpreting a status code.

This mirrors the on-chain rule that an unattested asset returns `None` rather
than a `clear` attestation. Unknown is not safe, and an empty history is not an
error.

### unknown — an observation is incomplete

If any returned observation has `undetermined: true`, the history is `unknown`,
the observation is **returned marked rather than omitted**, `state` names the
checks that did not complete, and every transition that involves it is itself
`unknown` rather than a derived difference. Nothing may be read from what an
undetermined observation omits: a source that failed could have hidden exactly
the change being asked about.

This is the same failure that
[attestation-run.md](attestation-run.md#finding-1) fixed for a single scan, now
applied to a comparison. A history read must not silently drop the partial
observation, because a shorter history that looks complete is worse than a
marked one.

### stale — the age is reported, the policy is yours

`latest_at` and `latest_age_secs` describe the most recent observation. Assay
does **not** declare a history stale and has no freshness threshold: a deposit
gate and a large settlement have different tolerances, so the consumer decides,
exactly as `max_age_secs` works on-chain. The API reports the age; it does not
act on it.

## Storage decision

**Decision: append-only JSON Lines, written with the standard library. No new
third-party dependency.**

The registry's whole threat model is that third-party trust is taken on only by
an explicit decision. Keeping a few hundred small records per asset does not
justify inheriting a database's supply chain, and `encoding/json` and `os` are
already part of the toolchain. A dependency here would need a maintainer
decision, and this design does not ask for one. (The merge gate holds any change
to `go.mod`/`go.sum` for review for the same reason.)

The store lives in [`internal/history`](../internal/history):

- **In-memory by default.** `api.NewServer` uses an in-memory store, so a
  bare `assay serve` keeps history for the life of the process and loses it on
  restart. That is deliberate: losing history is honest, whereas writing to a
  path nobody configured would be a surprise.
- **File-backed on request.** `assay serve -history /var/lib/assay/history.jsonl`
  loads the log at startup and rewrites it on every append. The rewrite is whole
  and atomic (a temporary file renamed over the target), so after each append
  the file is exactly the retained set and a crash cannot leave a half-written
  observation. The log is small and written at human rates; a full rewrite is
  simpler and more obviously correct than an append log with periodic
  compaction, and it means a restart cannot resurrect an evicted observation.
- **The on-disk record is versioned and separate from the wire shape.**
  Severity is stored as the number the model is built from, not the level name
  the API displays, and every record carries a `v` field. A future change to
  either shape cannot be read as this one.

### What is retained, and for how long

**Retention is a count per asset, not a time window.** The cap is
`history.DefaultRetention` — **256 observations per asset** — and when it is
exceeded the **oldest observation is evicted first**. The bound exists to make an
unbounded log impossible, not to save space: an observation is a few hundred
bytes, and 256 of them far exceeds what any asset Assay has scanned has
accumulated.

The response reports `retention` so a consumer that sees exactly that many
observations can read the history as possibly truncated at the oldest end rather
than as complete. Eviction is never silent: the cap is visible in every response.

Transitions are recomputed from retained observations on every request, so
evicting an old observation can make an old transition unavailable. That is the
honest consequence of a bounded history, and it is why the pair is returned
alongside each difference.

## What this does not do

- **No scheduling.** Nothing scans on a timer; history grows when someone calls
  `/api/v1/scan`.
- **No backfill.** There is no history for scans that happened before the store
  existed, and no way to import one.
- **No CLI surface change.** The `assay history` subcommand is a separate,
  report-derived view ([cli.md](cli.md)); this document describes the HTTP
  endpoint. The issue that added the endpoint explicitly scoped the CLI out.
- **No deletion API.** Retention is the only removal, and it is oldest-first.

## Tests

The endpoint's four required cases — empty history, a single observation,
multiple observations with a transition, and an observation that is
undetermined — are covered hermetically, with no network:

```sh
go test ./internal/api/ -run History -v
go test ./internal/history/ -v
```

## Verification

```sh
go test -race ./...
```

## Related

- [transitions.md](transitions.md) — what a transition is and why it is computed
  rather than stored.
- [checks.md](checks.md) — the rule that "we could not check" and "this is fine"
  must never render the same.
- [cli.md](cli.md) — the `serve` flag that enables persistence.
