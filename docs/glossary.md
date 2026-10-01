# Glossary: the states, and the words they must not blur

Every bug this project has fixed was one state collapsing into another: `clear`
standing in for "not evaluated", an outage rendering as a clean result, stale
reading as current, absent reading as safe. The distinctions *are* the product.
This page is the one place where each state is defined, with what produces it,
what a consumer should do with it, and which other state it is most often
mistaken for.

Read it before the other documents. The rules and reasoning live in
[the severity model](severity-model.md), [checks](checks.md), and
[the contract interface](contract-interface.md); this page is only the
vocabulary those documents assume.

## The one rule

**One state, one axis, one spelling.** A bare word is only used here if it
names exactly one state. Where two axes reuse a word — and one does (`unknown`)
— the axis is always named with it. `clear` is not `safe`; absent is not
`clear`; `undetermined` is not absent; `stale` is not `undetermined`.

| These are not synonyms | |
| --- | --- |
| `clear` ≠ `safe` | The issuer holds no power; the asset can still be worthless or a scam. |
| absent ≠ `clear` | No attestation exists; an attestation of `clear` exists and says no power. |
| `undetermined` ≠ absent | A source failed; "not listed" is a source answering that there is no entry. |
| `stale` ≠ `undetermined` | A verdict was complete when made and aged; a partial verdict never completed. |
| not evaluated ≠ not listed | Flags were never read; a source was read and had no entry. |
| not listed ≠ could not check | The list was read; the list could not be read. |

## The four words people reach for first

### SAFE

**Not a state Assay produces.** There is no `safe` severity, no `safe` field,
and no `safe` on-chain value. A consumer's `is_safe(asset, max_severity,
max_age_secs) == true` is a *gate's verdict*, computed from four facts: an
attestation exists, it is fresh enough for that caller, its severity is at or
below the caller's ceiling, and its bitset clears the caller's forbidden mask.
The verdict belongs to the consumer's policy, not to Assay.

**Most confused with:** `clear`. A `clear` asset means the *issuer* holds no
special power over the holder's balance. It does not mean the asset is genuine,
solvent, or not a rug by another mechanism. `DOGE-GA22IDJN…` carries no
capability bits at all and is a known scam
([attestation run](attestation-run.md)).

**Consumer action:** never translate `clear`, a matched `evidence_hash`, or an
admitted `is_safe` into the English word "safe" in a UI or an API field. The
closest honest phrasing is the one the model uses: "the issuer holds no power
over holders" ([severity model](severity-model.md#what-severity-does-not-tell-you)).

### UNSAFE

**Not a state Assay produces either.** The nearest states are `high` (the
issuer can confiscate) and `critical` (a curated source affirmatively identified
the issuer or its domain as malicious). Neither is a prediction that the issuer
*will* act, and a `clear` asset can still be unsafe through a mechanism Assay
does not scan.

**Most confused with:** `critical`. `critical` means a curator made an adverse
determination; it is not "maximally dangerous capability". `DOGE` is `critical`
with a `clear` capability base, because the escalation axis and the capability
axis are separate ([severity model](severity-model.md)).

**Consumer action:** gate on the axis your policy is about — the severity
ceiling, the forbidden mechanics mask, or both. Both are needed: a mask over
capability bits cannot see a reputation escalation, and a severity ceiling
cannot see which power is held
([integrating](integrating.md#2-decide-what-you-are-refusing)). The example gate
that shipped without the ceiling admitted a known scam on testnet; that is
[#26](https://github.com/use-assay/Assay/issues/26).

### UNKNOWN

**Overloaded, and therefore always qualified.** `unknown` is a value on two
different axes, and a bare "unknown" is ambiguous:

- **`Report.State = "unknown"`** — the verdict is not usable: either a check
  could not conclude (`undetermined`) or the capability axis was never read
  (`unevaluated`). See [verdict state](#verdict-state--is-the-answer-complete).
- **`Accountability = "unknown"`** — the issuer advertises no `home_domain`, so
  no published identity exists to verify. This is a definite finding, not an
  incompleteness. See [accountability](#accountability--who-stands-behind-the-power).

The word also names states on two other surfaces that are *not* the report:
history and transition completeness (`valid`/`unknown`/`missing`) and the
evidence check-set comparison (`unknown`/`complete`/`incomplete`). Those are
listed under [the word "unknown" elsewhere](#the-word-unknown-elsewhere).

**The three things informal language calls "unknown"** are defined separately
below, because collapsing them is the exact error this page exists to prevent:
[not evaluated](#not-evaluated), [not listed](#not-listed), and
[could not check](#could-not-check).

### UNDETERMINED

**A completeness flag, not a severity.** `Report.Undetermined` (JSON
`"undetermined"`, with `"undetermined_checks"` naming the checks) is true when
at least one check could not complete because a source it depends on did not
answer. It is produced by a check that records an unreachable source — a 429, a
5xx, or a timeout — and returns `Finding.Undetermined = true`.

**Most confused with:** `clear` / a clean result. An undetermined report still
carries whatever the checks that *did* complete established (often `clear`), but
it is a floor, never an answer: a source that failed could have hidden exactly
the danger being asked about. "We could not check" and "this is fine" must never
render the same.

**Consumer action:** treat the severity as a floor, read
`undetermined_checks` to see which axis is missing, and never rely on the
absence of an escalation. `attest.FromReport` refuses it outright
(`ErrUndetermined`), because `get_safety` has nowhere to carry the caveat; the
resulting absence on-chain is `None`, and every gate fails closed on it. This
collapse was fixed in [#23](https://github.com/use-assay/Assay/issues/23).
The related case where the flags themselves were never read is
[not evaluated](#not-evaluated), refused with the distinct `ErrUnevaluated`.

## The axes at a glance

| Axis | Field | Values | Question it answers |
| --- | --- | --- | --- |
| Severity | `Report.Severity`, `Report.Base` | `clear`, `low`, `medium`, `high`, `critical` (+ Go-only `unevaluated`) | What can the issuer do to a holder's balance? |
| Accountability | `Report.Accountability` | `unknown`, `unverified`, `verified` | Who, if anyone, publicly claims this asset? |
| Verdict state | `Report.State` | `valid`, `unknown`, `stale` | Is this answer complete and current? |
| Completeness | `Report.Undetermined`, `undetermined_checks` | `true`/`false`, list of check IDs | Did every source answer? |
| On-chain storage | `get_safety` | `None`, `Some(Safety)`, (archived restores) | Does a claim stand? |
| Curated source | check output + evidence | `listed`, `not listed`, `could not check` | What did the curator say, or fail to say? |

Each axis is independent. `Accountability = "verified"` does not lower
`Severity`; `State = "stale"` does not change the capability the flags
describe; an unknown `accountability` does not make the verdict `unknown`.

## Severity — what the issuer can do

Severity is **capability-only** and derived from the issuer's authorization
flags. It is the highest single capability present, never a sum
([severity model](severity-model.md#rule-4-do-not-double-count-what-the-protocol-requires)).
The values are ABI: do not renumber them.

| Value | Number | Produced by | Consumer action | Most confused with |
| --- | --- | --- | --- | --- |
| `clear` | 0 | `capability` check: no auth flags set | The issuer holds no power over holders. Not a safety verdict. | `unevaluated` |
| `low` | 1 | `capability` check: `auth_required` | The issuer controls entry, not existing holders. | `clear` (both "not dangerous to a current holder") |
| `medium` | 2 | `capability` check: `auth_revocable` | The issuer can freeze an existing balance in place. | `high` |
| `high` | 3 | `capability` check: `auth_clawback_enabled` | The issuer can confiscate and burn a balance without a signature. | `critical` |
| `critical` | 4 | `reputation` check: a curator tags the issuer `malicious`/`unsafe`, or blocks its domain | A named third party has affirmatively identified abuse. Capability is unchanged. | `high` |
| `unevaluated` | 5 (Go only) | `capability` check when the flags were never read (`Subject.Stat == nil`) | No capability statement exists. Never attested. | `clear` |

- **`critical` is escalation, not capability.** It is the only value never
  produced by reading flags. `base_severity` and `severity` are reported side by
  side, with `escalated`, so the capability contribution is always visible. A
  `critical` asset with no flags masks to an empty capability set.
- **`unevaluated` is deliberately outside the on-chain ABI.** `attest.FromReport`
  refuses it (`ErrUnevaluated`) and the contract's range check would reject it as
  `InvalidSeverity`; value 5 exists only so an unread flag cannot serialize as
  the safest value in the table. This collapse was fixed in
  [#32](https://github.com/use-assay/Assay/issues/32), the dependency of the
  issue that produced this page.

## Accountability — who stands behind the power

Accountability is reported beside severity and never folded into it
([severity model](severity-model.md#rule-3-accountability-is-reported-never-discounted)).

| Value | Produced by | Consumer action | Most confused with |
| --- | --- | --- | --- |
| `unknown` | `sep1-domain`: the issuer advertises no `home_domain` | Nobody has publicly claimed the asset. This is a definite answer. | `unverified` |
| `unverified` | `sep1-domain`: a `home_domain` exists but the reciprocal claim failed or the toml did not resolve | A claim was attempted and not reciprocated, or not readable. | `unknown` |
| `verified` | `sep1-domain`: the domain's `stellar.toml` lists this exact code and issuer | A named party has published a claim. It says nothing about the issuer's power or honesty. | `safe` |

`unverified` deliberately covers two different facts — "the toml did not
resolve" and "it resolved and did not name this asset" — because SEP-1 does not
let a consumer distinguish them from the field alone; the distinction survives
in the attributed evidence and reasoning
([attestation run](attestation-run.md#sep1-domain)). It does **not** cover
"nobody claimed it": that is `unknown`.

## Verdict state — is the answer complete

`Report.State` separates a usable answer from an incomplete or expired one. The
same three words are reused by the history and transition views for the same
reason, on their own inputs.

| Value | Produced by | Consumer action | Most confused with |
| --- | --- | --- | --- |
| `valid` | `Engine.Run` on a complete scan; freshness evaluator within the window | A fresh, complete verdict. Apply your own severity/mechanism policy. | `stale` |
| `unknown` | `Engine.Run` or the freshness evaluator when `Undetermined` is set, `Base == unevaluated`, or `Severity == unevaluated` | Not usable. Read `undetermined_checks`; do not act. | `stale` and `valid` |
| `stale` | `FreshnessEvaluator` when the report age exceeds the policy window | Complete when made, but too old to act on. Check `stale_reason`. | `unknown` and `valid` |

**`stale` and `unknown` are different failures.** A stale report was complete
when made and is now old; an unknown report never completed. An unknown report
can never become stale: staleness applies only to verdicts that were complete.
This distinction is [#57](https://github.com/use-assay/Assay/issues/57). A
stale report cannot be attested (`ErrStale`), so an expired verdict cannot be
written as fresh. On-chain the example gate returns `AttestationStale` (error
code 2) for the same condition, distinct from `NotAttested` (error code 1).

## The three things "unknown" can mean

These are the states informal language most often merges. They are three
different facts with three different serialized forms.

### Not evaluated

**Spelling:** prose "not evaluated"; serialized as severity `unevaluated` (5,
Go only). **Produced by:** a `Subject` whose flags were never read — `Stat ==
nil`. **Means:** no question was asked, so no answer exists, including the
answer "no powers". **Consumer action:** there is nothing to attest
(`ErrUnevaluated`); treat the capability axis as absent, not as `clear`.
**Most confused with:** `clear`. Collapse fixed in
[#32](https://github.com/use-assay/Assay/issues/32).

### Not listed

**Spelling:** prose "not listed"; no serialized value — it is an *evidence
claim* from a consumed source. **Produced by:** a curated source that answered
with no entry — an HTTP 404 from StellarExpert, or a toml that resolved and did
not name the asset. **Means:** the source was read and had nothing. **Consumer
action:** for reputation this is the normal case and is **not** a positive
signal: absence from a scam list is not evidence of safety, and most legitimate
assets and every unreported scam are absent. **Most confused with:**
`undetermined` / could not check. Collapse fixed in
[#23](https://github.com/use-assay/Assay/issues/23).

### Could not check

**Spelling:** prose "could not check"; serialized as `undetermined: true` with
`undetermined_checks`. **Produced by:** a source that did not answer — a 429, a
5xx, or a timeout — recorded as attributed evidence with the failure verbatim.
**Means:** the source was never read, so its absence carries no information.
**Consumer action:** as for `undetermined` above — floor, not answer; not
attestable. **Most confused with:** not listed, and `clear`. This is the
Finding 1 collapse ([attestation run](attestation-run.md#finding-1)), tracked as
[#23](https://github.com/use-assay/Assay/issues/23).

## On-chain storage states

The registry stores attestations; `get_safety` returns `Option<Safety>`.

| State | Produced by | Consumer action | Most confused with |
| --- | --- | --- | --- |
| Never attested | no `attest` has been written for the asset | Fail closed. Unknown is not safe, and no argument makes it so. | an attestation of `clear` |
| Revoked | `revoke(asset)` removed the attestation | Same as never attested: no claim stands. The contract keeps no tombstone. | never attested (indistinguishable to `get_safety`) |
| Attested | `attest(...)` wrote a `Safety` | Apply `max_age_secs` against `attested_at`, then your severity and mask policy. | "fresh" |
| Stale (gate verdict) | a consumer's `max_age_secs`/age check | Refuse. The example gate returns `AttestationStale` (2), distinct from `NotAttested` (1). | never attested |
| Archived | the entry's TTL ran out | The first read restores it, at the reader's cost, with its original `attested_at`. It does **not** read as `None`. | never attested / "expired" |

- **`None` is not `clear`.** A never-attested asset returns `None`; an attested
  clear asset returns `Some(Safety{severity: 0, ...})`. Collapsing them would
  make every unscanned asset read as safe
  ([contract interface](contract-interface.md#option-so-unknown-is-not-safe)).
- **Revoked and never-attested look the same on-chain, deliberately.** Both mean
  "no claim stands" and both fail closed; only the `revoke` event distinguishes
  them for an off-chain observer
  ([contract interface](contract-interface.md#revoked-and-never-attested-look-the-same-on-chain-deliberately)).
- **Archival is not expiry.** An archived attestation is restored, not removed;
  what protects a gate from an old one is `max_age_secs`, not the archive
  ([deployment](deployment.md#entry-lifetime)).

## The word "unknown" elsewhere

These are real uses of the word on surfaces that are *not* `Report.State` or
accountability. They are listed so a reader does not mistake them for the report
axis.

| Surface | Values | Meaning |
| --- | --- | --- |
| History (`GET /api/v1/history`) | `valid`, `unknown`, `missing` | Completeness of the returned *history*, not of one scan. `missing` is "we have never looked" and is an explicit empty result, never a 404 or an error. |
| Transition (`internal/temporal`) | `valid`, `unknown`, `missing` | Whether a difference could be derived between two observations. `missing` is fewer than two observations; `unknown` is a partial input. |
| Check-set verification (`internal/attest`) | `unknown`, `complete`, `incomplete` | Whether a report's bound check set can be compared against what a verifier expects. No bound set is `unknown`, never `complete`. |
| End-to-end verification (`docs/verifying.md`) | `valid`, `invalid`, `unknown`, `stale` | The outcome of the verification *procedure*: hashes match, differ, could not be computed, or verify but are old. Not a `Report.State`. |

## Worked examples: the collapses that were fixed

- **`clear` as "not evaluated" — [#32](https://github.com/use-assay/Assay/issues/32).**
  There was no severity value meaning "never read", so an empty `Subject` read
  as `clear`, the safest value in the ABI. Fixed by the `unevaluated` sentinel
  (5) and `ErrUnevaluated`, which keep an unread flag out of the preimage and
  off-chain. See [severity model](severity-model.md#what-unevaluated-means).
- **An outage as a clean result — [#23](https://github.com/use-assay/Assay/issues/23).**
  A StellarExpert 429 was discarded, and `reputation` reported "that is the
  normal case" for an issuer it had never read. `DOGE` — a known scam that is
  `critical` solely by escalation — scanned `clear` and was writable on-chain.
  Fixed by recording the failure as attributed evidence, setting
  `undetermined`, naming the check on `undetermined_checks`, and refusing to
  attest. See [Finding 1](attestation-run.md#finding-1).
- **Stale as current — [#57](https://github.com/use-assay/Assay/issues/57).**
  A verdict that was complete when made but had aged out was indistinguishable
  off-chain from a fresh one. Fixed by `Report.State` (`valid`/`unknown`/`stale`)
  and `Report.Stale`, with `ErrStale` blocking attestation. See
  [freshness](freshness.md#off-chain-freshness-and-report-state).
- **A capability mask read as the whole verdict — [#26](https://github.com/use-assay/Assay/issues/26).**
  The example gate refused forbidden capability bits but never checked the
  severity ceiling, so `DOGE`, whose severity comes entirely from reputation and
  which sets no capability bit, was admitted on testnet. Fixed by checking both
  axes. This is not a collapse of two Assay states but of two consumer
  questions; it is included because it is the same error in a gate.

## Checking this glossary against the documents

The definition here is the one the other documents already assert. The audit
that produced this page confirmed:

- [severity-model.md](severity-model.md) — "a `clear` asset is not safe",
  "what unevaluated means", "what stale means": all consistent with the
  severity and verdict-state entries above.
- [checks.md](checks.md) — "'we could not check' and 'this is fine' must never
  render the same", and the 404-versus-5xx rule: consistent with
  [could not check](#could-not-check) and [not listed](#not-listed).
- [contract-interface.md](contract-interface.md) — `None` distinct from
  `SEVERITY_CLEAR`, revoked/never-attested alike, `unevaluated` never on-chain:
  consistent with [on-chain storage states](#on-chain-storage-states).
- [freshness.md](freshness.md), [history.md](history.md),
  [transitions.md](transitions.md), [verifying.md](verifying.md) — the
  reused `valid`/`unknown`/`stale`/`missing` words are the surface-specific
  enums in [the word "unknown" elsewhere](#the-word-unknown-elsewhere), not
  alternative definitions of `Report.State`.
- [attestation-run.md](attestation-run.md) — two bullets in "What the checks
  can get wrong" described gaps since closed (`clear` doubling as not
  evaluated, and the two Horizon flag copies never being compared). Both were
  corrected to match this glossary and the current code.

## Related

- [severity-model.md](severity-model.md) — the judgment layer and the
  legitimate-use carve-out.
- [checks.md](checks.md) — what each check concludes and cannot.
- [contract-interface.md](contract-interface.md) — the on-chain ABI and
  `evidence_hash` encoding.
- [freshness.md](freshness.md) — how old a verdict may be, per use class.
