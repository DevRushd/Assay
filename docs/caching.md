# Caching consumed signals

Every scan consumes StellarExpert's curated directory and blocklist. Both are
free, neither documents a request budget, and re-fetching an answer that has not
changed is both slow and discourteous to a service Assay depends on — a
rate-limit would degrade scans exactly when the tool is most used. So Assay
caches them, with a bounded lifetime, per process.

The hard part is not the cache. It is the timestamp.

## The rule: a cached claim keeps its original fetch time

`Evidence.RetrievedAt` is a claim about **when data was fetched**, and it appears
in reports and in the [evidence_hash preimage](contract-interface.md). A cache
that stamped the cache-hit time would make Assay assert a freshness it does not
have: a report saying "blocklist checked: not blocked" stamped seconds ago,
built from an answer fetched half an hour ago.

So a cached answer carries the instant the *source* produced it:

```
first scan  09:00:00  fetch     -> FetchedAt = 09:00:00
second scan 09:20:00  cache hit -> FetchedAt = 09:00:00   (not 09:20:00)
```

The report's `scanned_at` stays the moment the scan ran; each evidence entry
keeps its own source's answer time. A consumer comparing the two sees exactly
how stale each claim is, which is the whole point.

The mechanical guarantee is in [`internal/cache`](../internal/cache): the fetch
time is stored *with* the value and handed back unchanged on every hit, and
expiry is measured from the fetch time rather than from insertion. The scan
layer copies that value into `Subject.DirectoryFetchedAt` /
`BlockedFetchedAt` and nothing re-stamps it. It is asserted by
`TestCacheHitDoesNotRefreshEvidenceTime` in
[`internal/scan/scan_test.go`](../internal/scan/scan_test.go), which runs two
real scans through one Scanner and requires the second report's evidence to
carry the first scan's fetch times.

This does **not** change any `evidence_hash`: the preimage commits to claims
(`evidence SOURCE URL CLAIM`), not to retrieval times. That is deliberate — it
is what lets a re-scan reproduce a stored hash while still reporting honest
ages.

## Expiry: a stale negative is a re-fetch, never an assumption

Two answers matter here, and they are the two that look like "nothing to see":

- directory: *not listed*
- blocklist: *not blocked*

**An expired negative is re-fetched.** Expiry always means a miss, so a domain
that was clean when it was cached and has since been listed is read fresh at the
next lookup after the TTL. Serving the cached negative past its TTL would turn a
stale observation into a safety assumption, which is the exact shape of a false
clean bill of health. `TestExpiredNegativeIsNotServedAsAPositive` pins it.

Within the TTL the cached negative *is* served — that is what caching means —
but it is served with its true age, so nothing claims it was just checked.

A **failure is never cached**. An outage returns an error, uncached, so recovery
is picked up on the next lookup instead of being masked by a stored 429.

## The lifetimes, and why they differ

| Signal | Default TTL | Why |
| --- | --- | --- |
| Directory entry (SEP-0037) | 20 s | The window StellarExpert advertises (`Cache-Control: max-age=20`). Carries the `malicious`/`unsafe` tags that can escalate severity. |
| Blocklist (`blocked-domains`) | 20 s | Same advertised window. Answers the most decisive question Assay asks, and has its own knob so a deployment can tighten it further. |
| Horizon asset / account / trustline | **not cached** | See below. |
| SEP-1 stellar.toml | not cached | The document a domain's own claim lives in; it is fetched once per scan either way. |

The defaults are not a guess. **StellarExpert tells callers how long its answers
stay current**, in two places:

1. Its OpenAPI document advises caching outright: "The effective API request
   rate may be a subject to rate limiting. In such cases the server returns 429
   HTTP status code error. To avoid potential problems caused by those
   limitations it is advised to consider response caching or group queries on
   the caller side in case of heavy API utilization."
   (https://stellar.expert/openapi, retrieved 2026-09-27.)
2. Both endpoints Assay reads answer every request with a concrete number:

   ```
   cache-control: max-age=20
   ```

   Verified live 2026-09-27 on `/explorer/directory/{address}` and
   `/explorer/directory/blocked-domains/{domain}`. `AdvertisedMaxAge` in
   [`internal/stellarexpert`](../internal/stellarexpert/client.go) is that
   value, and a test pins the defaults to it so they cannot drift from this
   documentation.

So the default lifetime is exactly the advertised one and never longer: 20
seconds of reuse, after which the answer is re-fetched. A deployment may set a
shorter TTL, per source, or disable caching entirely with `-no-cache`.

The two knobs stay separate even though they default to the same number, because
the blocklist is the safety-critical one. A cache can only ever *delay* an
escalation — severity never falls because an answer is old — so the edge it adds
is bounded by its TTL. **What does the blocklist's 20-second window cost?** The
blocklist endpoint is a paged list (`/explorer/directory/blocked-domains`) with
over a thousand entries and no per-entry timestamp, so its change rate cannot be
measured from the API. It is also machine-readable: if an entry appears, the
next lookup past the window sees it. The exposure is therefore bounded by the
TTL and nothing else, which is the argument for not exceeding the operator's own
number and for exposing a knob to go lower. A deployment that cannot tolerate
even 20 seconds can pass `-cache-blocklist-ttl 0` and read the list on every
scan.

## Why the ledger is not cached

Horizon lookups are deliberately outside this cache, and it is not an oversight.

Issuer authorization flags **are** the capability axis: severity is derived from
them and from nothing else. They can change in a single ledger close (~5 s) —
see [freshness.md](freshness.md) for the measured rate. There is also nowhere to
put a stale flag's age: an attestation stores a severity and an `attested_at`,
and a contract reading `severity <= MEDIUM` gets no retrieved-at for the flags
that produced it.

That leaves two options, both bad. A TTL short enough to be honest about a
five-second ledger would not save a request; a TTL long enough to save one would
let the report understate what the issuer can do, with no field in which to say
so. So the ledger is read every scan, and the reputation answers — which do
carry their own timestamps into the report — are the ones cached.

## Configuring it

The cache is per Scanner (per process), keyed by request URL. It is on by
default with the TTLs above, and every scanning command accepts:

```sh
assay scan -no-cache CODE-ISSUER                     # re-fetch everything
assay scan -cache-blocklist-ttl 5s CODE-ISSUER       # stricter safety window
assay scan -cache-directory-ttl 0 CODE-ISSUER        # disable one source only
assay attestation -no-cache CODE-ISSUER              # freshest possible inputs
```

Programmatically, `scan.Options` carries the same knobs, and a single lookup can
bypass the cache without rebuilding the client:

```go
answer, err := expert.BlockedDomain(ctx, domain, stellarexpert.BypassCache())
```

A bypassed lookup asks the source and **replaces** the cached copy, so a refresh
does not leave a superseded answer behind.

`serve` is where the cache earns its keep: the Scanner lives as long as the
process, so repeated scans of the same issuer reuse answers instead of
re-reading a free service on every request. A one-shot `scan` run mostly does
not benefit — `-no-cache` is the honest choice there if you want it.

## What this does not do

- **No single-flight.** Two concurrent lookups of the same absent key can both
  miss and both fetch. The cache is concurrency-safe (`sync.Mutex`, exercised
  under `-race`) but it does not deduplicate in-flight requests.
- **No persistence.** The cache is in-process and starts empty. A restart, or a
  fresh CLI invocation, re-fetches.
- **No staleness warning in the report.** The times *are* the warning: a
  consumer reads `retrieved_at` against `scanned_at`. Nothing is silently
  smoothed into "just now".
- **Not a licence to run at any rate.** Caching reduces request volume; it does
  not make polling StellarExpert equivalent to a bulk mirror of their data.
