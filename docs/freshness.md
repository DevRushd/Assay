# Freshness

An attestation is a snapshot. This page answers the question every consumer
eventually asks: **how old may one be before it should not be relied on?**

The short answer is that the registry refuses to answer that question for you,
and this page is the reasoning you need to answer it yourself — including the
measured data on how often the thing underneath the snapshot actually changes.

## Who decides

Three parties are involved, and none of them decides for another:

| Party | Role in freshness |
| --- | --- |
| The registry | Stores `attested_at` and nothing else. It takes a caller-supplied `max_age_secs` on `is_safe` and enforces no freshness rule of its own. |
| The attester (Assay) | Writes attestations. Nothing re-attests on a schedule; every attestation is exactly as fresh as its `attested_at` implies. |
| The consuming gate | The only party that can hold an opinion, because it is the only party that knows what it is protecting. It picks `max_age_secs` (or the equivalent check on `attested_at`). |

This split is deliberate. A deposit gate holding other people's balances, a
one-shot settlement, and an explorer displaying asset badges should not be
forced to agree on how fresh is fresh enough — and a policy frozen into the
registry would be wrong for most of them and upgradeable only by contract
migration. So the registry exposes the timestamp and takes the tolerance as a
parameter: [integrating.md](integrating.md) calls this "your policy, not
Assay's", and this page is what makes that choice an informed one instead of a
copy-pasted constant. See [timestamps.md](timestamps.md) for the exact clock
sources, precision, and authority definitions separating observation, scan, and
attestation timestamps.

## What can change under an attestation

An attestation records what a scan observed: the issuer's authorization flags,
the SEP-1 domain claim, StellarExpert's directory and blocklist answers, and
the severity those produced. Each of those can move after the write:

| Underlying fact | Who can change it | How fast it can move | What it does to a stale attestation |
| --- | --- | --- | --- |
| Issuer auth flags (`auth_required`, `auth_revocable`, `auth_clawback_enabled`, `auth_immutable`) | The issuer's signer, in one `set_options` transaction | One ledger close (~5 s) from decision to effect | Flags can gain a power the attestation says the issuer does not have |
| Trustline-level clawback | Nobody, after creation (CAP-0035 fixes it at trustline creation) | Never per-trustline | No effect — but a stale attestation says nothing about trustlines opened since |
| `home_domain` and its stellar.toml | The issuer | One transaction; the toml is a web page | Accountability can flip without the flags moving |
| StellarExpert directory tags / blocklist | StellarExpert curators | On their review cycle, any time | A malicious listing can appear that a stale severity does not carry |
| Held balances / trustlines | Holders and issuer ops | Continuous | Not attested at all — this is per-holder state, out of scope here |

Two of those rows deserve emphasis, because they differ in direction:

- **Turning `auth_revocable` on endangers balances that already exist.** A
  freeze applies to current trustlines immediately.
- **Turning `auth_clawback_enabled` on does not endanger balances that already
  exist.** Under [CAP-0035](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md)
  clawback is inherited at trustline creation; only trustlines opened after the
  flag was set are exposed. See `internal/mechanics/check_trustline.go` for the
  per-holder reading of the same fact.

A scan reuses cached third-party answers within a bounded lifetime, which does
not change any of the reasoning above — an attestation's age is still its
`attested_at` — but it does mean one report can carry evidence of several
different ages. Each `evidence[].retrieved_at` records the instant its own
source produced its answer, and never the moment a cache served it, so the true
age of every claim stays readable. The lifetimes and the guarantee are specified
in [caching.md](caching.md).

So the freshest-dangerous-direction for a gate holding *existing* balances is a
flag flip to `auth_revocable`, and it is instant. That asymmetry — staleness
can only ever under-report danger, never over-report it — is why every window
below errs short rather than long.

## How often do issuer flags actually change?

The honest answer requires data, not intuition, so this was measured from
Horizon's effect history rather than asserted. Method and results follow; both
the numbers and the caveat about the method are part of the record.

### Method

Horizon records every flag mutation as an `account_flags_updated` effect.
Walking those effects for an issuer account and counting the events inside a
window yields that issuer's flag-change history.

**One caveat, verified live on 2026-09-24:** Horizon's server-side filtering
for effects is currently unreliable. The public Horizon instances
(pubnet `28.0.1`, testnet `29.0.0`) silently ignore the documented `type=` and
`type_i=` parameters on `/effects` — a request for flag effects returns
unfiltered effects with HTTP 200 and no warning. Any measurement (or
monitoring pipeline) built on this endpoint must therefore fetch account-scoped
pages and filter client-side, which is what the numbers below did. Until that
changes, do not trust a flag-change count that was produced by `?type=account_flags_updated`.

The subjects were the seven unique issuers behind the ten attested assets
(see [attestation-run.md](attestation-run.md)). The window was the six months
preceding 2026-09-24 (2026-03-24 through 2026-09-24), walked back page by page
until the window's start, with client-side filtering.

### Results: the attested set

| Issuer (asset) | Flag-value changes in window | Notes |
| --- | --- | --- |
| BERKSHIRE (`BERKSHIRE`) | 0 | 4 events in 2025-11-06 → 2026-02-01, adjacent to the window — see below |
| USDC (`USDC`) | 0 | Full history walked: 27 pages of effects, zero flag events |
| AQUA (`AQUA`) | 0 | |
| USDZ (`USDZ`) | 0 | One `account_flags_updated` effect on 2026-05-20 carrying **no** flag values — a no-op effect, not a change |
| USDGLO (`USDGLO`) | 0 | |
| ARST (`ARST`) | 0 | Issuer's pubnet effect history was walkable but the account no longer resolves on either network — consistent with a merged-away account; contributed no events |
| VELO / REPO / KALE | 0 | Issuer (`GCZMWSOII…`) has no resolvable account or effect history on either network; contributed no events |

Zero confirmed flag-value changes across the attested set in six months, on
the five issuers with full pubnet history. (The one in-window flag effect, on
the USDZ issuer, changed nothing — Horizon emits the effect type even when a
`set_options` call sets a flag to the value it already had. A monitoring
pipeline that counts raw effects rather than value changes will overcount; the
no-op is recorded here so nobody re-derives it wrong.)

### Results: the adversarial contrast

The same walk, extended past the window on the BERKSHIRE issuer — the scam
asset Assay was built to catch — shows why class matters more than averages:

| Period | Flag-change events |
| --- | --- |
| 2025-11-06 → 2026-02-01 (3 months, just before the window) | **4** |
| 2026-03-24 → 2026-09-24 (the 6-month window) | 0 |

The scam class mutates its flags on month timescales: the BERKSHIRE issuer was
actively rearranging its authorization flags as recently as one window-width
ago, and the legitimate issuers were not. A rate measured over honest issuers
does not bound the rate of an adversarial one — which is the whole reason
freshness policy defaults short, and why [reputation](severity-model.md)
escalates on evidence rather than waiting for mechanics to catch up.

### Exposure context

For scale: a census of the 5,000 most recently created assets on pubnet
(`/assets`, 2026-09-24) found **373 (7.5%)** carrying at least one
authorization flag — 370 `auth_revocable`, 304 `auth_clawback_enabled`. A flag
flip is not a rare event type in the abstract; it is rare *so far* among the
specific issuers that have been attested, and most of the network's flagged
assets have never been attested at all.

## What the data supports

The measurement bounds the answer rather than pinpointing it:

- **Legitimate-issuer class:** 0 flag changes over 6 months among the issuers
  with full history. With so few change events, the 95% upper bound on the
  change rate is on the order of one event per issuer per ~90 days (the rule of
  three: zero events in six issuer-half-years). The true rate is *somewhere*
  below that; the sample is too small and too well-behaved to say where.
- **Adversarial class:** at least one flag mutation per quarter, demonstrated.
  No window longer than weeks bounds the damage an adversarial issuer can do
  between attestation and action.

That gap — legitimate issuers changing flags slower than once a quarter,
adversarial ones faster than once a quarter — is the actual input to a window:
it says the binding constraint is the adversary, not the median issuer.

## Recommended windows

Every number in this section is a **provisional default**: chosen, reasoned,
and reproducible from the data above, but not itself a measurement. The
measurements are the 0/4/373 figures in the previous sections; the windows are
policy layered on top of them.

| Use class | Window | Provisional default | Reasoning |
| --- | --- | --- | --- |
| **Custodial deposit gate** — you hold the balance on behalf of users | Hours, not days | 24 h (`86 400` s) | A balance survives contact with the issuer indefinitely, so what must be bounded is the exposure window to a flag flip. The adversarial class demonstrated month-scale churn; a day-long window bounds the worst case at ~1/30 of the observed adversarial mutation interval, while still being achievable given re-attestation is a manual process today. This is the example gate's value, and it now has a stated derivation. |
| **One-shot settlement / pre-trade check** — you move your own balance once | Minutes; in practice, a fresh scan at execution time | ≤ 1 h (3 600 s) if a cached attestation must be used | The check and the action land in the same transaction, so the cheapest correct policy is to re-scan at execution time and consume an attestation only as a cross-check. A day-old snapshot is indefensible when a fresh one costs one scan. |
| **Portfolio monitoring / dashboards** — informational, not gating | Days | 7 d | Staleness here wastes attention, not funds. The window should be shorter than the legitimate-issuer bound (~90 d) by a wide margin so that a flag change is caught in days, not months. |
| **Explorer display / public badge** — context, never a decision | Weeks | 30 d | Must be framed "as of attested_at", never as a verdict. The safest presentation couples the badge to its timestamp explicitly. |

Two rules cut across the table:

1. **Staleness is asymmetric.** A stale attestation can only ever under-report
   danger — flags move by gaining powers, and reputation only escalates. There
   is no scenario where an older attestation is safer than a newer one, so when
   a window is uncomfortable, shorten it.
2. **A window without a re-attestation path is a countdown.** Nothing refreshes
   attestations on a schedule today ([contract-interface.md](contract-interface.md),
   "Not done yet"): every attestation ages out of *every* window eventually, and
   a gate with a strict window plus no refresher will refuse everything —
   which is exactly what the example gate does right now: **all ten live
   attestations are past its 24-hour window as of this writing.** That is the
   policy working, not a malfunction; the gate is being honest about what it
   knows. A production deployment needs either a scheduled re-scan-and-attest
   loop or a window matched to how often it is actually willing to re-verify.

## What the registry does and does not enforce

To be precise about where the walls are:

- `get_safety` returns `attested_at` and lets the caller decide everything.
- `is_safe(asset, max_severity, max_age_secs)` enforces *the caller's* age
  policy against the ledger timestamp. `max_age_secs = 0` disables the check —
  pass it only when staleness is an accepted property of the query, never to
  make a call stop failing.
- Attestation writes do not check the age of any prior attestation, and the
  contract holds no notion of expiry: an attestation never expires on its own,
  it only goes stale relative to a caller's policy.
- The one invariant the registry *does* enforce on writes is the
  confiscation-severity consistency check — an asset whose flags include
  clawback may not be attested below severity 3 — which is a statement about
  internal consistency, not about time.

That is the whole mechanism. It is intentionally thin, because freshness is a
property of the *use*, not of the asset: the correct window for "should my
vault accept a deposit right now" is different from "should this explorer show
a green badge", and only the caller knows which question it is asking.

## Off-chain freshness and report state

Off-chain, `internal/mechanics.Report` represents freshness directly via its `state` and `stale` fields:

| State (`state`) | `stale` | Meaning |
| --- | --- | --- |
| `valid` | `false` | A fresh, complete verdict within the policy window. |
| `unknown` | `false` | A check could not conclude (`undetermined` or `unevaluated`). |
| `stale` | `true` | The verdict was complete when made, but is older than the policy window. |

The freshness evaluator (`internal/mechanics.FreshnessEvaluator`) checks a report against a policy window (defaulting to 24 hours). If stale, `attest.FromReport` refuses attestation (`ErrStale`), ensuring an expired verdict is never attested as fresh on-chain.

## Re-deriving these numbers

Everything measured here is reproducible without trust in this document:

```sh
# Flag history for one issuer. NOTE: server-side filtering is unreliable on
# current Horizon (type= / type_i= silently ignored — verified 2026-09-24),
# so fetch account-scoped pages and filter client-side:
curl -s "https://horizon.stellar.org/accounts/<ISSUER>/effects?limit=200&order=desc" \
  | jq '[._embedded.records[] | select(.type=="account_flags_updated")]'

# Exposure census, most recent assets first:
curl -s "https://horizon.stellar.org/assets?limit=200&order=desc" \
  | jq '[._embedded.records[] | select(.flags.auth_required or .flags.auth_revocable or .flags.auth_clawback_enabled)] | length'
```

If you re-run the measurement and get different counts, update this page —
the windows are only as good as the data underneath them, and the data is
supposed to be re-checked, not remembered.
