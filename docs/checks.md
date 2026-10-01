# Checks

A check is a pure function from a pre-fetched `Subject` to a `Finding`. Checks
perform **no I/O**: the [`scan`](../internal/scan) package fetches everything
once, up front, and hands the result to classifiers that only compute.

That split buys three things. Checks are deterministic and testable from
fixtures with no network. Each fetcher stays in its own package with a clean
signature, so it can be extracted later without untangling judgment logic from
transport. And a check cannot quietly add a network dependency, because it has
nowhere to put one.

```go
type Check interface {
    ID() string
    Describe() string
    Run(ctx context.Context, s *Subject) (Finding, error)
}
```

## `capability`

**Concludes:** what the issuer is able to do to a holder's balance.
**Sets:** base severity.

Maps issuer authorization flags to a level, per
[the severity model](severity-model.md). Severity is the highest single
capability present, not a sum — `auth_revocable` is a protocol precondition for
`auth_clawback_enabled`, so counting both would double-count a rule CAP-0035
enforces.

The reasoning always states the raw capability in plain language, whatever the
level works out to. A reader is never told a number without being told what the
issuer can actually do.

`auth_immutable` is not scored here: whether the flag set can still change is a
separate, first-class finding — see [`mutability`](#mutability).

### The two copies of the flags

Horizon publishes the issuer's authorization flags **twice**: on the `/assets`
record and on the issuer's `/accounts` record. They are separate ingestion
paths. The check reads both and compares them; it never classifies from one
copy silently.

Field names were verified independently on both endpoints (2026-09-25): both
carry the identical four booleans — `auth_required`, `auth_revocable`,
`auth_immutable`, `auth_clawback_enabled`. Across USDC, AQUA, USDZ, DOGE, KALE,
BERKSHIRE and SHX — assets spanning the whole severity range — the two copies
agreed in every case. Agreement is the normal state, which is exactly why a
disagreement is worth surfacing rather than averaging away.

**The resolution rule, stated normatively: on disagreement, take the more
dangerous of the two readings.** A power is counted as held if either copy
reports it. The two copies can disagree only if one is wrong or stale
(indexer lag, a flag change mid-scan), and a single scan cannot tell which.
Resolving in the holder's favour would let a stale copy *lower* a severity —
the one direction this project never resolves. Severity stays capability-only:
this rule decides which capability reading is used, and adds no reputation
input.

`auth_immutable` is resolved the other way, and deliberately. It is not a power
over a holder, and its reasoning is cited protectively as well as as an
aggravator ("the issuer can never add confiscation later"). Asserting the lock
when one copy contradicts it would hand the reader a reassurance the evidence
does not support, so the lock is claimed only when **both** copies agree it is
set; on disagreement the report keeps the cautious reading that the flags may
still change.

On disagreement the report says so explicitly, and each source is attributed
with its own URL — the `/assets` record and the `/accounts` record — so a
reader can re-fetch both copies and settle the question themselves. The second
copy is cited **only** when the two disagree: attaching it to every report
would restate a fact already in evidence and would change the `evidence_hash`
of every attestation already written for an asset whose copies agree, which is
all of them. The disagreement path is exercised by
`check_capability_disagreement_test.go` against
`testdata/synthetic-flag-disagreement/` — a deliberately mismatched fixture,
not a live capture, because no disagreeing asset has ever been observed.

**Cannot conclude:** whether the issuer will ever use the power; whether an
existing holder is exposed (clawback is inherited at trustline creation, so this
answers the prospective question only); or anything about who the issuer is.

## `mutability`

**Concludes:** whether the issuer's authorization flag set can still change.
**Sets:** nothing. Severity stays `Clear` in every case.

`auth_immutable` is not a power over holders, so it is deliberately not a
severity level — see [the severity model](severity-model.md). Its meaning is
conditional, and this check reports the condition rather than folding it into a
number. There are three states, each with its own reasoning:

- **Locked with no dangerous flags** — a durable safety property. Because the
  flag set can never change, `auth_revocable` and `auth_clawback_enabled` can
  never be added, so a `clear` verdict today is also `clear` for a trustline
  opened later.
- **Locked with freeze or clawback** — permanence. No flag in the set can be
  given up, because `AUTH_IMMUTABLE_FLAG` cannot be cleared once set (CAP-0035
  makes all `AUTH_*` flags read-only). Locking does not make the power safer; it
  removes any future in which the issuer relinquishes it.
- **Not locked** — the issuer may add freeze or confiscation later. Under
  CAP-0035 a flag added later does not reach trustlines that already exist, but
  it applies to any trustline opened after the change. This is the state a
  prospective holder wants surfaced, because it is the one where today's `clear`
  is not a durable answer.

**Flag source.** The check reads the issuer flags from the same Horizon
`/assets` record the `capability` check derives severity from, so the two
findings cannot disagree about the flag set. `auth_immutable` is also carried on
the issuer `/accounts` record; that is a second ingestion path Assay does not yet
reconcile, and taking the `/assets` record here keeps this finding consistent
with the severity reported beside it. The gap is recorded in
[the attestation run](attestation-run.md#what-the-checks-can-get-wrong).

**No evidence.** The flag read is already attributed by the `capability`
finding's Horizon evidence. `evidence_hash` is a SHA-256 over a **sorted list**
of evidence lines, so a second copy of the same claim — or a new claim about the
same read — would change the hash of every attestation whose underlying evidence
did not change, which the encoding is explicitly designed to prevent. This check
therefore reasons over the read that is already attributed rather than
re-emitting it.

**Cannot conclude:** what the issuer will do with the power, or whether an
existing holder is exposed. It reports only the durability of the flag set,
which is a fact about the issuer account. It is not a safety verdict on its own:
an unlocked `clear` asset is still only clear about issuer capability, not about
whether the asset is genuine.

## `sep1-domain`

**Concludes:** whether an identifiable party has publicly claimed this asset.
**Sets:** accountability. **Never touches severity.**

Reciprocal verification, requiring both directions to agree:

1. The issuer account advertises `home_domain`.
2. That domain serves `/.well-known/stellar.toml`.
3. The toml's `CURRENCIES` lists **this code and this issuer**.

Either half alone is worthless. `home_domain` is free text any account can set
to any string; a stellar.toml can list any code it likes. Matching on code alone
would let any domain claim any asset — the exact impersonation this check
exists to catch — so both must match.

Two states are decided before any toml is fetched. **No `home_domain` at all**
means nobody has claimed the asset: accountability is `unknown`, and the
reasoning says so plainly — an absent claim is not a failed one. **A
`home_domain` that disagrees with the curated directory's `domain`** is
reported as `unverified` with both claims attributed to their source and URL,
because a holder cannot tell a benign brand migration from an impersonation
setup while the two sources simply contradict each other.

Verification failures are reported verbatim, including the HTTP status. "We
could not check" and "this is fine" are different answers and must never render
the same.

That rule is repo-wide, not local to this check. It was stated here first
because `stellar.toml` was the only source that honoured it; the two
StellarExpert endpoints did not, and a scan during an outage claimed reputation
had been read when it had not. Fixed, with the history in
[the attestation run](attestation-run.md#finding-1).

The same rule applies to negatives. SEP-0001 permits a currency entry carrying
`toml="https://DOMAIN/.well-known/CURRENCY.toml"`, delegating the declaration to
a separate file; the link need not be the entry's only field, so one entry may
carry both a link and a code. Assay does not follow those links yet, so every
entry that carries one and does not already declare this asset inline makes the
answer **unconfirmed** rather than a claim that the domain failed to name it —
overstating a negative is the same class of error as overstating a positive.
An entry that does match inline is the claim itself and is not an unresolved
link. Following those links is not implemented yet.

### Redirects

`.well-known/stellar.toml` may answer with a redirect. Because `home_domain` is
attacker-controlled free text, a redirect is part of the claim surface rather
than an implementation detail, and two rules bound it.

**The chain is bounded at five hops** (`sep1.MaxRedirects`). net/http follows
ten by default; the number is stated explicitly here because a redirect chain is
attacker-controlled and the bound is part of the security argument, not a copied
default.

**A redirect may not leave the requested host's namespace.** The target must be
the requested host itself or a subdomain of it, compared case-insensitively on
the hostname. This admits the ordinary `circle.com` → `www.circle.com` move
while refusing a hop to an unrelated host: without this rule a hostile
`home_domain` could redirect the fetch to any host it likes and have that host's
document recorded as this domain's claim, defeating the reciprocity the check
exists to establish. The test is deliberately one-directional — a requested
subdomain may not climb to a parent domain, which may be a shared host whose
content another party controls.

A same-site redirect is **not hidden from the audit**. Evidence records
`requested_url` — the well-known location derived from `home_domain` — alongside
`url`, the location the document was actually read from, so a reader can tell
whether the claim came from the requested host or from a subdomain a redirect
moved it to. `requested_url` is outside the `evidence_hash` preimage and `url`
keeps its original per-path meaning, so no attestation already on chain moves;
the field is new information, not a change to what was hashed.

Concretely, the only redirect observed in the on-chain corpus is `circle.com` →
`www.circle.com` (see [the attestation run](attestation-run.md)); the policy
admits it, so USDC's evidence bytes and `evidence_hash` are unchanged. The other
nine attestations were written from direct, non-redirecting fetches. Excluding
`requested_url` from the preimage is what keeps adding it from moving any of
them; a run that *did* move an existing hash here would be a bug, not an
acceptable cost.

**Exceeding the bound, or a refused cross-host redirect, is an error naming the
final host** — not a silent 404 and not a claim. A document served by a
disallowed host is never treated as this domain's claim.

**Cannot conclude:** that a verified issuer is honest. It establishes that a
named party has published a claim, nothing more. A scammer can register a domain
and publish a valid toml in ten minutes; that is precisely why this sets
accountability rather than severity.

## `reputation`

**Concludes:** nothing of its own. It relays curated third-party determinations.
**Sets:** escalation only, upward only.

Consumes StellarExpert's address directory (the data set standardized by
SEP-0037) and malicious-domain blocklist. A `malicious`/`unsafe` directory tag
or a blocklist hit escalates to `critical`.

Any configured [SEP-0042 asset list](asset-lists.md) is consumed here too, one
`Evidence` entry per list, attributed by the list's own name and URL. A list can
neither escalate nor lower the level: inclusion is not endorsement — the spec
says so itself — and absence from a list is not an observation. When the lists
disagree, or disagree with StellarExpert, the report says so and leaves it
unresolved rather than averaging two providers into one verdict. A list that
could not be read is recorded as failure evidence rather than as an absence, and
does not mark the report `undetermined`, because it is not a source the verdict
depends on.

Everything it produces is `Evidence{Source, URL, Claim, RetrievedAt}` naming
StellarExpert and the URL the claim came from. Attribution is structural: a
check can only surface an outside claim by constructing an `Evidence`, so there
is no code path that renders someone else's data as an Assay conclusion.

`RetrievedAt` is the instant the source produced its answer. A scan may reuse a
cached answer ([caching.md](caching.md)), and when it does this is the original
fetch time rather than the time of the scan, so a report states a claim's true
age instead of implying it was just checked.

Assay does not maintain a scam list, a rating, or a domain blocklist. That layer
exists, is actively curated, and is better than anything this project would
produce. **Do not re-derive it.**

**Cannot conclude:** that an unlisted asset is safe. Absence from a curated list
is not an observation — most legitimate assets are absent, and so is every scam
nobody has reported yet. The check says so explicitly in its reasoning rather
than staying silent and letting absence read as approval.

**Cannot conclude anything at all when a source did not answer.** A 404 means
the source was read and had no entry; a 429, a 5xx, or a timeout means it was
never read. Those produce different reports: an unreachable source is recorded
as attributed evidence carrying the failure verbatim, the finding is marked
`undetermined`, and the report names the check on `undetermined_checks`.

A third case is the same gap pointed the other way: an issuer with **no
`home_domain`** leaves the domain-keyed blocklist with nothing to look up, so
the question is never put. A missing question is not a clean answer — a
blocklist hit would escalate — so this too marks the finding `undetermined`,
with reasoning that says the lookup could not be keyed rather than that it came
back empty. The scanner records the skip explicitly (`Subject.BlockedSkipped`)
rather than leaving the fields empty, because an empty result reads as "read
and found nothing".

Severity is **not** raised to compensate. Capability stays exactly what the
ledger says, because inventing a level Assay did not measure would be the same
error pointed the other way. What changes is that the report states the level is
a floor, and that `attest.FromReport` refuses to write it on-chain at all —
`get_safety` returns a severity and a timestamp with nowhere to carry the
caveat, so a partial scan must not become an attestation. The contract already
handles the resulting absence correctly: `None`, and every gate fails closed.

A listing that *did* arrive still escalates even if the other source is down.
Evidence of abuse does not become less true because a second endpoint timed out,
and `critical` is the ceiling, so nothing still missing could raise the level
further.

Note that the two sources are not interchangeable and neither is complete. When
`BERKSHIRE-GA22QHSH…` was scanned, the directory tagged the issuer `malicious`
while blocked-domains returned `blocked=false` for the same domain. Consulting
only one of them would have missed a confirmed scam.

## Capability transitions

The checks above answer a prospective question: what can this issuer do to a
trustline opened now. Comparing two of those answers over time is a separate,
pure computation in [`internal/temporal`](../internal/temporal): what capability
bits were added or removed between two observations, and which axis — capability
or reputation — moved severity. It performs no I/O and stores nothing. The
representation and the on-demand-versus-stored decision are in
[transitions.md](transitions.md).

## Adding a check

See [CONTRIBUTING.md](../CONTRIBUTING.md). The short version: implement the
interface, verify every flag name and endpoint against a live source, and add
eval subjects for both a true positive **and** a legitimate use of the same
mechanics. A check whose judgment is not evaluated does not ship.
