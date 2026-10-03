# Eval

The mechanics detection is deterministic — a flag is either set or it is not,
and there is nothing to measure. What this eval measures is the **judgment**:
does the severity model separate a trap from a legitimate compliance feature,
and does escalation fire only on reputation?

**A check whose judgment is not evaluated against this set does not ship.**

Run it with `make test`. The eval is `TestEval` (aggregate) and
`TestEvalPerCheck` (per check) in
[`internal/mechanics/eval_test.go`](../internal/mechanics/eval_test.go); both
run from fixtures with no network access, so a result cannot drift because a
third-party API had a bad day. Their labels live in one place,
[`internal/eval`](../internal/eval), so the aggregate and per-check
expectations cannot describe different runs.

## The labelled set

Every subject is a real pubnet asset. Fixtures were captured from live sources
with provenance recorded in
[`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).

| Subject | Label | Why it is in the set |
| --- | --- | --- |
| `AQUA` | legitimate | No auth flags at all, reciprocal domain. The baseline: the model must not manufacture risk. |
| `SHX` | legitimate | No auth flags **and** `auth_immutable`. Tests that flag-locking is not mistaken for danger. |
| `XRP` (fchain.io) | legitimate | The unlocked counterpart to SHX: no auth flags, `auth_immutable` **unset**. Capability is clear, but the flag set can still change, so the `mutability` finding must report that without moving severity. |
| `USDC` (Circle) | **legitimate, uses the flags** | The critical case. A real regulated stablecoin that legitimately uses `auth_revocable`. |
| `USDZ` (Zeam Money) | **legitimate, uses clawback** | The other critical case. A regulated stablecoin (FSCA-licensed issuer, reciprocal SEP-1) that legitimately uses `auth_clawback_enabled` — the only subject in the set that measures the model's central claim that legitimate clawback is handled fairly. |
| `BERKSHIRE` (nasdaq.finance) | trap | Impersonation asset with clawback. Confiscation capability *and* confirmed-bad reputation. |
| `DOGE` (darkpool.digital) | trap | Known scam carrying **no auth flags**. The case that justifies the second axis. |
| `VELO` (no domain) | legitimate | An issuer account with no `home_domain` at all — the field is absent from the ledger record. Nothing was ever claimed, so accountability must be `unknown` rather than `unverified`, and severity must stay `clear` (#3). |

## Results

Measured output from fixtures captured on 2026-08-10. `TestEval` asserts every
row on each test run, so the table cannot drift from the code without a red test:

| Subject | Asset | Base | Final | Escalated | Accountability | Mechanics |
| --- | --- | --- | --- | --- | --- | --- |
| aqua-clear-verified | `AQUA` | clear | **clear** | false | verified | — |
| shx-clear-flagslocked | `SHX` | clear | **clear** | false | verified | `auth_immutable` |
| xrp-clear-unlocked | `XRP` | clear | **clear** | false | verified | — |
| usdc-revocable-regulated | `USDC` | medium | **medium** | false | unverified | `auth_revocable`, `domain_unverified` |
| usdz-clawback-regulated | `USDZ` | high | **high** | false | verified | `auth_revocable`, `auth_clawback_enabled` |
| berkshire-clawback-scam | `BERKSHIRE` | high | **critical** | true | unverified | `auth_revocable`, `auth_clawback_enabled`, `domain_unverified`, `blocklisted` |
| doge-noflags-scam | `DOGE` | clear | **critical** | true | unverified | `domain_unverified`, `blocklisted` |
| velo-no-home-domain | `VELO` | clear | **clear** | false | unknown | `domain_unverified` |

## What each result proves

### USDC — the false-positive test

`medium`, not escalated, not discounted.

This is the result the whole model is built to get right. USDC carries
`auth_revocable`: Circle **can** freeze a holder's balance. Assay says so
plainly, because it is true and a holder should know it.

What Assay does *not* do is either of the two easy mistakes:

- It does not call it dangerous. `auth_revocable` alone is level 2 of 4, and the
  reasoning explains that freezing is not confiscation. There is no clawback
  here — verified live, `auth_clawback_enabled: false`. The assumption that
  regulated stablecoins carry clawback is simply wrong for the biggest one on
  the network.
- It does not wave it through because Circle issues it. The severity comes from
  the flag. An anonymous issuer with the same flag gets the same `medium`.

`accountability: unverified` is a genuine finding, not a bug:
`circle.com/.well-known/stellar.toml` returns 404 (fixture captured 2026-08-10;
still 404, via a redirect to `www.circle.com`, on 2026-09-17), so reciprocal SEP-1
verification fails by the letter of the spec. It is left uncorrected because it
is the strongest available argument that accountability must never have been a
severity discount — had it been one, USDC would score worse than a scam asset
with a working toml.

### DOGE — why capability-only severity does not miss scams

`base: clear` → `final: critical`, escalated.

A known scam asset with **zero** authorization flags. Its issuer holds no
special power, so the honest capability answer is `clear` — and Assay says
`clear` for the base, without flinching.

The trap here is not a trap mechanic at all; it is impersonation. Capability
analysis cannot see that, and pretending otherwise would mean inventing a
heuristic that fires on innocent assets too. The curated malicious listing
catches it, escalation raises it to `critical`, and `base_severity: clear`
remains visible in the report so a reader can see exactly which axis did the
work.

This subject is the reason reputation is kept as a separate upward-only axis
rather than being dropped for purity.

### DOGE (contradictory sources) — handling disagreeing reputation sources

`base: clear` → `final: critical`, escalated.

A regression fixture where consumed reputation sources disagree: StellarExpert's
`blocked-domains` returns `blocked=false` for `darkpool.digital`, while the
`directory` tags the issuer as `malicious` and `unsafe`.

Assay consumes both sources and escalates if *either* source flags evidence of
abuse. Requiring agreement between sources would silently drop known scams when
one source is incomplete or delayed. This fixture proves that escalation fires
despite the disagreement.

### BERKSHIRE — both axes firing

`base: high` → `final: critical`, escalated.

Impersonates Berkshire Hathaway, carries `auth_revocable` + `auth_clawback_enabled`.
Capability alone puts it at `high` — Assay would flag this asset as
confiscation-capable **even with no reputation data at all**, which is the case
for any brand-new trap. Reputation then escalates it.

### AQUA and SHX — no manufactured risk

Both `clear`. A scanner that only ever finds problems is as useless as one that
never does. SHX additionally carries `auth_immutable`, and the reasoning
correctly frames that as a safety property: the issuer can never add clawback
later.

### XRP — the unlocked counterpart to SHX

`clear`, not escalated, and `auth_immutable` unset.

SHX and XRP are the two halves of the `mutability` check. Both have no
authorization flags, so `capability` is `clear` for each. The difference is that
SHX's flag set is locked — clawback can never be added — while XRP's is not, so
the issuer may add freeze or confiscation later. That difference never enters
severity: `base: clear` and `severity: clear` for both, because `auth_immutable`
is not a power over holders. It is reported as its own finding instead, and this
subject is here so the unlocked branch is pinned by the eval rather than only by
a unit test.

### VELO — no claim, not a failed claim

`clear`, not escalated, `accountability: unknown`.

The issuer account carries no `home_domain` — Horizon omits the field
entirely — so there is no published identity and no stellar.toml to read.
That is a third state, distinct from both verification (`AQUA`) and a failed
verification (`USDC`): nobody has made a claim, so nobody has failed one.
Accountability records it as `unknown`, never `unverified`, because
`unverified` would assert an attempt that never happened.

It is also the proof that the distinction does not buy a severity discount in
disguise: identical flags to `aqua-clear-verified`, identical `clear` result.
The `domain_unverified` bit still appears, because no identity was published
to verify against. This subject is the fixture for issue #3.

## Per-check evaluation

An aggregate verdict can be right for the wrong reason: if the capability check
says `clear` and reputation escalates the asset to `critical`, the report is
correct while the capability error stays invisible. `TestEvalPerCheck` therefore
compares every finding against its own label, not only the total.

A check that could not conclude is compared against an **undetermined** label,
not against a severity, because an undetermined finding makes no severity claim.
A subject whose findings and labels do not line up — including one with no
per-check labels at all — is reported as **partially evaluated**, never silently
passed. `TestEvalPerCheckReportsPartialLabels` and
`TestEvalPerCheckDetectsWrongExpectation` pin those two failure modes.

Measured per-check output (same fixtures as the table above):

| Subject | capability | mutability | sep1-domain | reputation |
| --- | --- | --- | --- | --- |
| aqua-clear-verified | clear | clear | verified | clear (escalation axis) |
| shx-clear-flagslocked | clear | clear, `auth_immutable` | verified | clear (escalation axis) |
| xrp-clear-unlocked | clear | clear | verified | clear (escalation axis) |
| usdc-revocable-regulated | medium, `auth_revocable` | clear | unverified, `domain_unverified` | clear (escalation axis) |
| usdz-clawback-regulated | high, `auth_revocable`, `auth_clawback_enabled` | clear | verified | clear (escalation axis) |
| berkshire-clawback-scam | high, `auth_revocable`, `auth_clawback_enabled` | clear | unverified, `domain_unverified` | critical, `blocklisted` |
| doge-noflags-scam | clear | clear | unverified, `domain_unverified` | critical, `blocklisted` |
| velo-no-home-domain | clear | clear | unknown, `domain_unverified` | clear (escalation axis) |

The `reputation` column carries the escalation axis: its finding is `clear` with
`escalation: true` when nothing is flagged, and `critical` with `blocklisted`
when it is. That is the one check permitted to escalate, and per-check labels
keep it from hiding a capability error. For `synthetic-reputation-outage` the
reputation cell is **undetermined**: the blocklist was consulted and failed, so
the finding makes no severity claim at all — it is compared against its
`Undetermined` label, not against a level.

### synthetic-reputation-outage — the degraded scan

`base: clear` → `final: clear`, `undetermined: true`, not attestable.

The issue behind #23 was a subject whose reputation source was unreachable
scanning as a clean answer. `TestOutageDoesNotRenderAsNotListed` and its
companions pin the behaviour over hand-built subjects, because the fixture
loader used to render an outage as a clean absence: a missing `blocked.json`
was indistinguishable from a source that was never asked. With the error-marker
convention below, the labelled set can state the difference itself, and
`TestEvalDegradedSubjectIsUndeterminedNotClear` pins it end to end:

- the reputation finding is **undetermined**, not clear — `not listed` was
  never observed;
- the report carries `undetermined: true` and names `reputation` in
  `undetermined_checks`, so a JSON consumer sees a partial answer;
- severity stays at the measured capability — the outage must not be answered
  by inventing a level either;
- `attest.FromReport` refuses the report (`ErrUndetermined`), because a partial
  scan must never reach the chain.

This subject is also why the corpus's undetermined handling is not hypothetical:
`make eval-compare` reports it as undetermined and excludes it from movement
counts, exactly as it would a live degraded run.

## Fixture conventions

Each subject directory holds the captured answer of every consumed source. A
source is expressed in one of three states, and the loader
([`internal/eval/load.go`](../internal/eval/load.go)) maps them to the Subject
fields the checks read:

| State | Fixture | Loader sets |
| --- | --- | --- |
| **valid** — the source answered | payload file present: `stellar.toml`, `directory.json`, `blocked.json` | the parsed payload and the source's `FetchedAt` |
| **unavailable** — the source was consulted and failed | error marker present: `stellar.toml.status`, `directory.err`, `blocked.err` | the matching `*Err` field, verbatim marker text, and `*AttemptedAt` |
| **missing** — the source was not consulted | neither file | neither the payload nor an `Err` |

The error marker convention extends the existing `stellar.toml.status` pattern:
the file's trimmed text is what the live fetcher would have recorded — an HTTP
status number for a status failure (`429`), or any error text for a transport
failure. A blank marker is treated as absent, never as an empty error.

The distinction is the point. A missing `blocked.json` and a `blocked.err`
holding `429` used to produce the same Subject, which made the degraded state
inexpressible in the labelled set. The three states are pinned by
`TestEvalLoaderStates`, and the unavailable state by the degraded subject in
the corpus. `synthetic-`-prefixed directories mark fixtures assembled for a
property under test rather than captured from a live asset; their provenance
is recorded in the directory's README and in
[`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).

## Cross-version comparison

Any change to a check can move verdicts, and pass/fail against fixed
expectations cannot show *what* moved. `make eval-record` writes the full
classifier output for the corpus — per subject, per check, with the bound check
set — to [`docs/eval-baseline.json`](eval-baseline.json), tagged with the scanner
version. `make eval-compare` records the current run and diffs it against that
baseline, reporting severity, mechanic and evidence movements separately.

Three rules keep the diff honest:

- A subject **undetermined** in either run is reported as undetermined and
excluded from the movement counts: an answer that was never reached cannot have
moved.
- A subject present in only one run is reported as **added** or **removed**, not
dropped.
- Evidence movements are reported as digests of the sorted claims, excluding
retrieval times, so a re-run of unchanged evidence does not show as a change.

Run `make eval-record` when the output is intended to change; the baseline is
what a reviewer diffs against. Run `make eval-compare STRICT=1` to make any
movement fail the command.

## Running the evaluation

The eval is a Go program that classifies every subject in the labelled
corpus and compares the result against the known labels. It uses
captured fixtures only — no network access is required.

```sh
make eval          # print the confusion matrix with precision/recall caveat
make test          # run TestEval and TestEvalPerCheck (asserts every row)
```

`make eval` prints a confusion matrix showing agreements, disagreements,
and undetermined counts per severity level and per check. Sample size is
printed with every row so the contributor can judge whether the corpus is
large enough to trust the figures.

### Reading the output

The matrix has two tables:

- **severity level agreement** — for each base severity in the corpus,
  how many subjects the classifier agreed with the label, disagreed,
  or left undetermined.
- **check agreement** — for each check (capability, mutability,
  sep1-domain, reputation), how many findings matched their label,
  disagreed, or were undetermined.

Every row includes `sample_size`: the number of subjects at that
severity level (or the number of subjects whose label includes that
check). If `sample_size` is small, the counts are illustrative and must
not be cited as evidence of classifier accuracy.

**Undetermined is its own outcome.** An undetermined scan is never
folded into agreement or disagreement. It means a source the check
depends on was unreachable, so the classifier could not produce a
conclusion. An undetermined result is not a failure — it means the
run was incomplete and should be retried or the missing source
investigated.

### A disagreement may indicate a wrong label

When a subject disagrees with its label, that does not automatically
mean the code is wrong. The label itself may be incorrect:

- The provenance may be stale because the issuer changed its flags
  after the fixture was captured.
- The label may rest on an assumption that has since been disproven
  (for example, a domain that was once malicious may now be clean).

Before assuming the classifier is wrong, check the fixture against the
live source and review the provenance in
[`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).
If the label needs correction, see the label change process in the
dataset labeling section below.

### Cross-version comparison

Any change to a check can move verdicts, and pass/fail against fixed
expectations cannot show *what* moved. `make eval-record` writes the full
classifier output for the corpus — per subject, per check, with the bound check
set — to [`docs/eval-baseline.json`](eval-baseline.json), tagged with the scanner
version. `make eval-compare` records the current run and diffs it against that
baseline, reporting severity, mechanic and evidence movements separately.

Three rules keep the diff honest:

- A subject **undetermined** in either run is reported as undetermined and
excluded from the movement counts: an answer that was never reached cannot have
moved.
- A subject present in only one run is reported as **added** or **removed**, not
dropped.
- Evidence movements are reported as digests of the sorted claims, excluding
retrieval times, so a re-run of unchanged evidence does not show as a change.

Run `make eval-record` when the output is intended to change; the baseline is
what a reviewer diffs against. Run `make eval-compare STRICT=1` to make any
movement fail the command.

## Coverage gaps

Stated plainly, because an eval that hides its gaps is marketing.

- **Eight subjects.** Enough to pin the judgment boundaries, not enough for a
  statistical claim. No precision/recall numbers are quoted, because eight
  subjects cannot support them.
- **~~No legitimately-clawback-enabled asset~~ Closed 2026-09-27.**
  `USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR` (Zeam Money)
  is now in the set as `usdz-clawback-regulated`: clawback-capable, reciprocal
  SEP-1 verification passes, StellarExpert directory tag is `issuer` (not
  malicious), and the issuer is FSCA-licensed. Base severity is `high` from
  the flag alone, and — critically — it is **not escalated**. That is the
  measurement the model's central claim rests on. Fixture provenance and the
  independent-verification evidence are in
  [`internal/mechanics/testdata/PROVENANCE.md`](../internal/mechanics/testdata/PROVENANCE.md).
- **Trap coverage still narrow.** The set has no subject exercising
  `auth_required` as a gating mechanism, and no subject with all four
  authorization flags set. Adding those needs live traps that actually
  exhibit those shapes; the two current traps (`BERKSHIRE`, `DOGE`) do not.
- **No frozen-trustline case.** Nothing exercises assets with unauthorized
  trustlines, where a freeze has actually been used rather than merely enabled.
- **Fixtures are a snapshot.** Issuers can change flags. Fixtures pin the
  judgment, so a live asset's real classification can drift from the fixture's;
  re-capture before citing a specific asset's current state.

## Adding a subject

1. Capture fixtures for the asset and record provenance, following
   [Capturing a fixture](adding-a-check.md#capturing-a-fixture).
2. Add a case to `TestEval` with the expected base, final, escalation, and
   accountability — and a `why` string stating what the case proves. The `why`
   is printed on failure, so a future maintainer learns what they broke.
3. Every new check must add at least one subject that trips it **and** one with
   the same mechanics legitimately that must not be over-flagged.

Point 3 is the discipline. Any check can find `auth_revocable: true`. The reason
to have a check is that it knows when that is fine.

## Dataset labeling and refresh

The machine-readable record for this set is
[`internal/mechanics/testdata/manifest.json`](../internal/mechanics/testdata/manifest.json).
The fixture metadata is CC-BY-4.0 under the dataset directory's
[`LICENSE`](../internal/mechanics/testdata/LICENSE); Assay source code remains
Apache-2.0 and upstream payloads remain subject to their providers' terms.

### Label criteria

- **Legitimate** is a control-group label for an asset with a documented issuer
  identity or a known regulated/compliance use case, supported by the captured
  source records. It does not mean risk-free: USDC is legitimate while its
  `auth_revocable` capability still produces `medium` severity.
- **Trap** requires affirmative captured reputation evidence identifying the
  issuer or domain as malicious or unsafe, or a documented impersonation case
  with corroborating source records. Capability alone is never enough for this
  label.
- Severity and accountability are measured independently from the label. The
  expected base severity comes from issuer capability; final severity may only
  rise through reputation escalation; accountability records reciprocal SEP-1
  verification and is never a legitimacy discount.

### Point-in-time refresh pipeline

1. Re-fetch the URLs recorded for a subject and record one UTC capture date for
  the refresh. `make refresh-fixture SUBJECT=<dir>` does this from the URLs in
  `PROVENANCE.md`, prints the diff for review, and updates the capture date in
  both `PROVENANCE.md` and the manifest. A source that fails aborts before
  anything is written, so a fixture is never left partial.
2. Store only payloads whose current provider terms permit redistribution. For
  uncertain StellarExpert or issuer material, retain the URL and derived
  annotation rather than adding a new raw copy.
3. Rebuild the expected labels and metrics from the captured files, update the
  manifest atomically, and run `make test`.
4. Review the diff for source attribution, update `PROVENANCE.md`, and publish a
  new manifest version. Never overwrite an old capture without preserving its
  date and provenance.

### Disputed labels and corrections

A disputed label is not silently edited. Open a correction with the fixture
name, disputed field, evidence URL, observed date, and proposed replacement.
After review, preserve the original annotation in the change history, update
the manifest and provenance together, add or adjust the evaluation assertion,
and record the reason for the correction. A disagreement without sufficient
evidence remains `unresolved` in the correction record and is excluded from
claims about model accuracy.
