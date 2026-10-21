# Fail-closed enumeration

Every place in the scan and attestation path where a failure could influence
the answer, classified as **fail-closed** (a failure yields a result no more
permissive than the truth), **fail-open** (a failure yields a more permissive
result than success would have), or **not applicable** (the path cannot make a
permissive claim). This document is the systematic counterpart to the two
fail-open bugs found by hand — #23 and #25 — and it is the defence against the
third being found the same way, by luck.

The classification rule comes from the issue: a path is fail-closed when every
failure on it yields a result **no more permissive than the truth**. "No more
permissive" is not the same as "more severe": an outage that inflated every
severity to critical would be safe for a gate but dishonest, and it is handled
separately (the engine must not inflate to compensate — that is pinned by
`TestOutageDoesNotInflateSeverity` and, from the eval set,
`TestEvalDegradedSubjectIsUndeterminedNotClear`). What a fail-closed path may
never do is turn "we could not check" into "this is fine".

Test names below are prefixed with the Go package (`mechanics.`,
`attest.`, `scan.`, `api.`, `eval.`) or the contract test (`SR:` safety-registry,
`EG:` example-gate). Every site marked **fail-closed (tested)** carries at
least one named test; the tests named `TestFailClosed*` were written for this
enumeration, and the others predate it and are listed because they are the
claim's evidence. Where a test was added for this enumeration it also proves
its claim the deliberate way: it feeds the failure and asserts the output is
no more permissive than the truth, rather than only asserting that code runs.

## Go — the fetch layer (`internal/scan`, fetchers)

| # | Site | Classification | Evidence |
| --- | --- | --- | --- |
| F1 | `horizon.Client.get` — non-200 status | **fail-closed (tested)** | Returns an error; `Scanner.Subject` aborts the scan on Horizon failures (F3). `scan.TestFailClosedHorizonNon200AbortsTheScan`, `horizon.TestNon200IsAnError`. |
| F2 | `horizon.Client.get` — malformed body, timeout, transport error | **fail-closed (tested)** | Same abort path as F1. `scan.TestFailClosedHorizonNon200AbortsTheScan` (503 case), `horizon.TestMalformedJSON`, `horizon.TestTimeoutIsAnError`. |
| F3 | `Scanner.Subject` — Horizon asset or account fetch fails | **fail-closed (tested)** | Only the ledger lookups are fatal: the scan returns an error, so no Subject — and therefore no report, no severity, no attestation — exists. Aborting is the fail-closed choice; the alternative (building a Subject without flags) was exactly bug #25's shape and now cannot arise from the live path. `scan.TestFailClosedHorizonNon200AbortsTheScan`. |
| F4 | `Scanner.Subject` — StellarExpert directory fetch fails | **fail-closed (tested)** | The error is recorded verbatim in `DirectoryErr` and the reputation check marks its finding `Undetermined`; a partial answer is refused at attest (A2). `mechanics.TestOutageDoesNotRenderAsNotListed`, `mechanics.TestEitherSourceFailingIsEnough`, `eval.TestEvalDegradedSubjectIsUndeterminedNotClear`. |
| F5 | `Scanner.Subject` — StellarExpert blocklist fetch fails | **fail-closed (tested)** | Same as F4 via `BlockedErr`. `mechanics.TestEitherSourceFailingIsEnough` (blocklist case), `eval.TestEvalDegradedSubjectIsUndeterminedNotClear` (429 marker). |
| F6 | `Scanner.Subject` — stellar.toml fetch fails | **fail-closed (tested)** | Recorded in `TomlErr`; DomainCheck reports the domain claim **unverified** (`domain_unverified`), never verified. `mechanics.TestEvalDegradedSubjectIsUndeterminedNotClear` (toml-state assertions via the loader), `TestEvalPerCheck` over `usdc-revocable-regulated` (a real 404 capture labelled unverified). |
| F7 | `Scanner.SubjectWithHolder` — trustline fetch fails | **fail-closed (tested)** | `HolderTrustlineErr` set; TrustlineCheck marks its finding `Undetermined` rather than reporting the holder safe. `mechanics.TestFailClosedTrustlineOutageIsUndetermined`. |
| F8 | `horizon.Client.Asset` — echo mismatch (record describes another asset) | **fail-closed (tested)** | Fatal error; a record that cannot be proven to describe the requested asset never reaches the engine. `horizon.TestAssetMismatchErrors`. |
| F9 | `horizon.Client.Account` — echo mismatch | **fail-closed (tested)** | Same reasoning as F8. `horizon.TestAccountMismatchErrors`. |

Not applicable here: StellarExpert and SEP-1 404s. A 404 from the directory or
blocklist is a **normal "not listed" answer** from these endpoints, and the
 StellarExpert client maps it to `nil, nil` deliberately; the blocklist lookup
of a domain with no entry genuinely is "not blocked". This is the one place
"absence" is treated as an answer, and it is justified because the endpoints
themselves define 404 as the not-listed response — unlike a transport failure,
which says nothing about the listing. (The directory's `200 {}` empty-object
answer is additionally distinguished from a real listing by the address-echo
check — see G1.)

## Go — the engine (`internal/mechanics`)

| # | Site | Classification | Evidence |
| --- | --- | --- | --- |
| G1 | `stellarexpert.Directory` — `200 {}` with no address echo | **fail-closed (tested)** | An empty object is an unlisted answer, not a listing; the address echo is the discriminator, so an outage that returned an empty 200 cannot fabricate a claim — and a listing cannot be fabricated from nothing. `stellarexpert` client tests; downstream rendering pinned by `TestEvalPerCheck` (an unlisted issuer carries no directory evidence). |
| G2 | `ReputationCheck.Run` — `DirectoryErr`/`BlockedErr` set | **fail-closed (tested)** | Unreachable sources make the finding `Undetermined`; they never render as "not listed". The old wording that asserted absence was normal must not survive an outage. `mechanics.TestOutageDoesNotRenderAsNotListed`, `mechanics.TestUnreachableSourceIsRecordedAsEvidence`, `mechanics.TestFailureEvidenceCarriesAttemptTime`. |
| G3 | `ReputationCheck.Run` — positive listing plus an outage | **fail-closed (tested)** | A confirmed malicious listing still escalates: evidence of abuse does not become less true when a second source is down, and Critical is the ceiling, so nothing missing could raise the level further. `mechanics.TestPositiveListingStillEscalatesWhenTheOtherSourceIsDown`. |
| G4 | `CapabilityCheck.Run` — `Stat == nil` (flags never read) | **fail-closed (tested)** | The finding carries `Unevaluated` — deliberately not zero, because Clear is the ABI's safest value — and marks the report undetermined, making it non-attestable. `mechanics.TestNilStatIsUnevaluatedNotClear`, `mechanics.TestNilStatEngineRunIsUndeterminedNotClear`, `attest.TestUnevaluatedReportIsRefused`. |
| G5 | `Engine.Run` — a check returns an error | **fail-closed (tested)** | Run aborts and returns no report; a check that cannot decide cannot hand back a half-answer dressed as a full one. `mechanics.TestFailClosedEngineCheckErrorProducesNoReport` (added for this enumeration). |
| G6 | `Engine.Run` — escalation finding carries capability bits | **fail-closed (tested)** | Run fails loudly rather than masking bits and continuing: a report must never assert a power the issuer does not hold. `mechanics.TestEngineRejectsEscalationSettingCapabilityBits`, `mechanics.TestEscalationCapabilityMutationIsCaught`. |
| G7 | `DomainCheck.Run` — `Toml == nil` (toml unreachable) | **fail-closed (tested)** | Accountability is `unverified` and `domain_unverified` is set; an unreachable toml proves nothing about who issued this. Not severity-affecting by design (accountability is never severity). `TestEvalPerCheck` over `usdc-revocable-regulated`; loader states pinned by `eval.TestEvalLoaderStates`. |
| G8 | `reconcileFlags` — Horizon's two flag copies disagree | **fail-closed (tested)** | Resolves against the holder: a power is counted as held if either copy reports it, and `auth_immutable` only if both agree. Indexer lag cannot lower a severity. `mechanics.TestCapabilityFlagDisagreement*` (the disagreement suite). |
| G9 | `TrustlineCheck.Run` — holder does not hold the asset | **fail-closed (tested)** | The finding is `Undetermined`, not "no exposure": no trustline means no holder-specific answer exists. `mechanics` trustline tests. Not severity-affecting by design. |

Not applicable: `MutabilityCheck` has no failure path of its own — it reads the
same reconciled flag set as G4/G8 and carries the same `Stat == nil`
undetermined branch (tested in that suite).

## Go — attestation and API (`internal/attest`, `internal/api`)

| # | Site | Classification | Evidence |
| --- | --- | --- | --- |
| A1 | `attest.FromReport` — `severity`/`base` is `Unevaluated` | **fail-closed (tested)** | Refused with `ErrUnevaluated` before anything else; an unread-flag report can never be serialized. `attest.TestUnevaluatedReportIsRefused`. |
| A2 | `attest.FromReport` — `rep.Undetermined` | **fail-closed (tested)** | Refused with `ErrUndetermined`, naming the incomplete checks: a level derived from half the evidence is indistinguishable on-chain from one derived from all of it, so the honest options are attest-complete or attest-nothing. `attest.TestUndeterminedReportIsRefused`, `attest.TestCapabilityClearWithReputationDownIsNotAttestable` (the #23 regression), `eval.TestEvalDegradedSubjectIsUndeterminedNotClear`. |
| A3 | `attest.FromReport` — confiscation invariant (clawback bit below High) | **fail-closed (tested)** | Refused with `ErrInconsistent` before a fee is spent; the contract re-checks it at write time (C3). `attest.TestConfiscationInvariantIsRefusedBeforeSubmission`. |
| A4 | `attest.Preimage` escaping — issuer-controlled claims | **fail-closed (tested)** | Tab/newline/CR/backslash in third-party text are escaped, so a crafted directory name cannot forge another report's preimage. `attest.TestSeparatorsInClaimsCannotForgeALine`. |
| A5 | `attest.VerifyCheckSet` / `VerifyParams` — no bound check set | **fail-closed (tested)** | Reported as `unknown`, **never** as complete: a report from before check-set binding cannot pass as one that ran everything. The attest `unevaluated`/suppression tests pin the reporting; the check-set comparison itself is exercised by the suppression suite (`attest.TestFailClosedMissingCheckSetIsReportedUnknown`). |
| A6 | `api.handleScan` — scan error (after validation) | **fail-closed (tested)** | Surfaced as 502 with the upstream error text, never as a permissive report; a caller cannot mistake "we could not check" for "safe". `api.TestFailClosedScanErrorIsSurfacedNotClean` (added for this enumeration). |
| A7 | `api.handleScan` — bad asset/holder input | **fail-closed (tested)** | Rejected with 400 before any network call. `api.TestScanRejectsBadInput`. |
| A8 | `horizon.Asset` — empty records list | **fail-closed (tested)** | `ErrNotFound`, which the scanner treats as fatal (F3) and the API as 404 — never as an asset with no flags. `horizon.TestAssetNotFound`, `api` 404 mapping. |

## Contracts (`assay-contracts`, both crates)

| # | Site | Classification | Evidence |
| --- | --- | --- | --- |
| C1 | `SafetyRegistry::is_safe` — `get_safety` returns `None` | **fail-closed (tested)** | Returns `false` for every threshold, including the most permissive. SR: `gate_fails_closed_on_unattested_asset`, `unattested_asset_returns_none`; EG: `unattested_asset_is_refused`. |
| C2 | `SafetyRegistry::is_safe_masked` — `None`, including an empty `forbidden_mask` | **fail-closed (tested)** | An empty policy must not become a blanket allow for unattested assets. SR: `masked_gate_fails_closed_on_unattested_asset`; EG: `unattested_asset_is_refused`. |
| C3 | `SafetyRegistry::attest` — severity out of range / confiscation inconsistency | **fail-closed (tested)** | Rejected at write time (`InvalidSeverity`, `InconsistentAttestation`), so a reader can rely on the invariant; nothing is stored, no event is published. SR: `attest_rejects_out_of_range_severity`, `attest_rejects_clawback_below_high`, `attest_publishes_no_event_on_rejection`. |
| C4 | `attest`/`revoke` — caller is not the admin (`require_auth`) | **fail-closed (tested)** | Unauthorized writes fail and change nothing. SR: `attest_rejects_unauthorized_caller`, `revoke_rejects_unauthorized_caller`. This is also mutation M6 in the catalogue. |
| C5 | `is_safe` — stale attestation / attestation from the future | **fail-closed (tested)** | Saturating age check refuses beyond `max_age_secs`; a future timestamp cannot underflow into "fresh". SR: `stale_attestation_fails_closed`, `attestation_from_the_future_does_not_underflow`; EG: `stale_attestation_is_refused`. |
| C6 | `is_safe` — defence-in-depth confiscation re-check at read time | **fail-closed (tested)** | A gate below High refuses a confiscation-capable asset even if a bad attestation somehow existed. SR: `gate_blocks_confiscation_below_high_threshold`. |
| C7 | `ExampleGate::assert_safe` — `None`, stale, above ceiling, or refused bits | **fail-closed (tested)** | Every non-affirmative path is a distinct error; `None` is handled first and explicitly. EG: `unattested_asset_is_refused`, `stale_attestation_is_refused`, `severity_above_ceiling_is_refused`, `critical_by_reputation_without_capability_bits_is_refused`, `freeze_capable_asset_is_refused_even_though_severity_is_medium`, `confiscation_capable_asset_is_refused`. |
| C8 | `SafetyRegistry::revoke` — revoking an unattested asset | **fail-closed (tested)** | `NotAttested`, not a silent success: a revoke aimed at the wrong address must not report that it worked. SR: `revoke_nonexistent_returns_not_attested`. |
| C9 | Event publication on rejected writes | **fail-closed (tested)** | Nothing is emitted for writes that did not happen, so indexers never observe phantom attestations or revocations. SR: `attest_publishes_no_event_on_rejection`, `revoke_publishes_no_event_on_rejection`. |
| C10 | Archived (TTL-expired) entry read | **fail-closed (tested)** | The host restores the entry with its original `attested_at`, so `max_age_secs` still sees the true age; archival cannot make an old attestation look fresh. SR: `read_after_archival_returns_original_attestation`. |

## Legitimately fail-open sites

Two shapes recur across the paths above and are worth stating rather than
hiding, because a future reader will meet them and wonder:

1. **"Not listed" from a source that answered.** StellarExpert's directory and
   blocklist define 404 (and the directory's `200 {}`) as the not-listed
   response. Treating that as "no curated claim" is not a failure path at all —
   it is the source's own normal answer, and the check treats absence from a
   scam list as evidence of nothing (it never lowers severity). The failure
   paths — transport errors, non-200 statuses, timeouts — are all classified
   above, and none of them render as "not listed".
2. **Best-effort continuation of the scan.** `Scanner.Subject` deliberately
   does not abort on StellarExpert or toml failures, because aborting would
   deny the holder the ledger facts (capability flags) that remain fully
   readable. That is not fail-open: the degraded axes are marked undetermined
   in the report, and the report is non-attestable, so nothing permissive
   escapes to a consumer that acts automatically. The one consumer that could
   act on a partial report by hand sees `undetermined: true` and the verbatim
   failure evidence.

## Method

This enumeration was produced by walking each error-handling site in
`internal/scan/scan.go`, the fetchers (`internal/horizon`, `internal/sep1`,
`internal/stellarexpert`), `internal/mechanics/*.go`, `internal/attest/attest.go`,
`internal/api/api.go`, and both contracts' entry points, and asking one
question at each: *if this call fails, does the caller downstream see anything
more permissive than the truth?* The Go side was walked from `cmd/assay/main.go`
downward; the contract side from each `pub fn` that crosses the ABI.

New tests written for this enumeration (the `TestFailClosed*` family) cover the
claims that had no test naming them before: the Horizon abort (F1–F3), the
trustline outage (F7), a check error aborting the engine (G5), the missing
check-set "unknown, never complete" status (A5), the API surfacing a scan
failure (A6), and the Go-side statement of the registry's unattested-is-never-
safe and refuse-invalid-writes invariants (C1–C5, in `internal/attest`'s
contract-invariant suite). When a new error-handling site is added, add a row
here and a test for its claim in the same change.
