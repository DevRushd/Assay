# Threat model

What Assay claims, who can make those claims wrong, and which of those the
project defends against, accepts as a risk, or puts out of scope on purpose.

This file exists because several design decisions — one admin key, capability-only
severity, consuming rather than re-deriving reputation, a gate that fails closed —
are only defensible against a stated attacker. Without the statement, a reviewer
cannot tell an oversight from an accepted risk. [SECURITY.md](../SECURITY.md)
says what is reportable; this says what was already known when the code was
written.

The scope is the deployment described in [deployment.md](deployment.md): the
**testnet** registry, the scanner that writes to it, and the gate pattern in
[integrating.md](integrating.md). Where a statement is about something not built
yet, it says so.

## The one thing that must not go wrong

Assay's output is a claim about whether someone's money can be taken. A claim
that is **too permissive** — an asset admitted that a consumer should have
refused — is the only failure that puts funds at risk. A claim that is **too
severe** refuses a good asset: bad, but it fails closed, and the holder keeps
their money.

Almost every verdict below follows from that asymmetry. Denial of service is
accepted throughout, as long as it is visible. The two things this document
will not accept are an admission and a silent wrong-in-the-dangerous-direction.

| Asset | Why it matters | Failure direction |
| --- | --- | --- |
| The consumer's funds | The gate admitted an asset whose issuer can seize the balance | Unsafe |
| Registry availability | Stale or revoked attestations block good assets | Safe: fails closed |
| Evidence attribution | A claim that cannot be traced to the evidence it cites | Detective |
| Attester integrity | Who is allowed to write, and what a compromise costs | Unsafe (admission) |

## Trust boundaries

```
 issuer ──controls their flags, home_domain, stellar.toml ─┐
                                                           │
 Horizon ──┐                                               │
 SEP-1 toml ├── consumed, attributed, untrusted ───────────┤
 StellarExpert ┘                                           │
                                                           ▼
                                                    ┌─────────────┐
        attester key ──── require_auth ────────────▶│  registry   │
                                                    │  (testnet)  │
                                                    └──────┬──────┘
                                                           │ same-transaction read
                                                           ▼
                                                   consuming contract / gate
```

Every arrow into the scanner is untrusted input. The only privileged arrow is
the attester key, and the only arrow a consumer can trust is the read — which is
why the read is fail-closed.

## Actors

| Actor | What they control | What they can do to Assay |
| --- | --- | --- |
| **Asset issuer** | The authorization flags on their own account, their `home_domain`, the `stellar.toml` at that domain | Change the facts an attestation describes after it is written; publish a `home_domain` pointing anywhere; put hostile strings in `stellar.toml` and directory fields |
| **Attester key holder** | The admin key, and therefore every write | Attest anything for any asset, overwrite, revoke, or stop writing. A compromise is indistinguishable from honest use on-chain |
| **StellarExpert** (and the SEP-0037 directory) | The curated directory entries and the blocked-domain list | Escalate an asset to `critical`; withdraw a listing that previously escalated one; go dark |
| **Domain operator** | Whatever the issuer's `home_domain` resolves to — **including one an attacker controls** | Serve a hostile or oversized `stellar.toml`; stall a fetch; lie about which asset it issues |
| **Consuming contract** (the gate) | Its own call: which SAC address, which threshold or mask, which `max_age_secs` | Read the wrong asset, pass the wrong policy, or mishandle `None` |
| **Network observer / indexer** | Nothing. Read-only over public ledger state and events | Nothing. No confidentiality is claimed, and none is needed: an attestation is a public claim |
| **Assay maintainers / CI** | Which code runs at build time | Ship a scanner that reports what it should not. Covered by review, not by the contract |

## Attack classes

Format: **verdict**, then the reason. "Accepted" means the exposure is known,
bounded, and the reason it is not fixed is stated — not that nobody thought
about it.

### Admission-risk classes

#### 1. Attester writes `clear` for a dangerous asset

**Verdict: accepted risk (the central one).**

Nothing on-chain can prevent this. The contract cannot evaluate an
`evidence_hash`, only store it, and it cannot see issuer flags because a Soroban
contract cannot call Horizon. Today one key can write anything, so a compromised
or malicious attester can cause an admission directly.

Two things bound the damage rather than prevent the write:

- `evidence_hash` makes the lie **checkable**. A consumer that re-scans can
  prove an attestation does not reproduce from the evidence it implies, which
  turns "trust the attester" into "verify the attester". That is a detective
  control: a consumer gating without verification is fully exposed.
- The escalation path is monotone and auditable. A `clear` write for an asset
  whose issuer holds clawback is rejected at write time
  (`InconsistentAttestation`), so the lie has to be a *capability* lie, which a
  re-scan of the ledger catches without any source being reachable.

The fix is threshold attestation, designed with a recommendation in
[multi-attestor.md](multi-attestor.md): the property required is narrow — no
single compromised attestor can cause an admission.

#### 2. Issuer changes flags after the attestation

**Verdict: accepted risk, mitigated by consumer policy.**

An attestation is point-in-time. An issuer can enable `auth_clawback_enabled`
after a scan, and nothing on-chain notices until someone re-attests. The
contract exposes `attested_at` precisely so this is the consumer's decision, and
`is_safe`/`is_safe_masked` take `max_age_secs` rather than using a contract
constant. [freshness.md](freshness.md) measures how often flags actually change
and recommends a window per use class; `max_age_secs = 0` opts out explicitly
and is documented as such.

Residual risk: a consumer that passes `0`, or a window far longer than the
measured flag-change rate, has no protection. That is a documented misuse, not
an outage Assay can fix.

#### 3. Fabricated or replayed attestation

**Verdict: defended.**

There is no path by which an outside party can write storage:

- Every write path (`attest`, `attest_many`, `revoke`) requires the admin's
  `require_auth`, and the gate never depends on a writer having been correct:
  `is_safe` re-checks the confiscation invariant even though `attest` already
  rejects it.
- There is no import entrypoint, so an attestation cannot be copied in from
  elsewhere, and `evidence_hash` is stored rather than verified against a
  caller-supplied value.
- Storage is keyed by SAC address, not by a code+issuer string, so a replay
  aimed at a different asset does not land. SAC addresses are network-derived,
  so a testnet attestation is not addressable on pubnet either.
- Batch writes are not a bypass: `attest_many` validates every element through
  the same function the single-write path uses, before writing anything
  (see [contract-interface.md](contract-interface.md#attest_many-many-attestations-in-one-transaction)).
  `batch_with_one_invalid_entry_writes_nothing` holds that with the bad element
  in the middle of the batch.

The deployed contract has **no upgrade entrypoint**, which cuts both ways: there
is no admin-takeover-by-upgrade, and there is also no way to fix the deployed
instance in place — a change means a new contract ID and re-attestation
([deployment.md](deployment.md#migrating-to-a-registry-with-revoke)).

#### 4. Reputation, attribution, age, or popularity lowers a severity

**Verdict: defended within a report; accepted across reports, with visibility.**

Inside one report this cannot happen, structurally: base severity is the maximum
over non-escalation findings, final severity is the maximum over all findings,
and `Engine.Run` raises the final severity to the base at the end. A finding
marked `Escalation` that sets a capability bit is a hard error rather than a
masked one. The property test
[`TestSeverityNeverBelowMaximumCapabilityFinding`](../internal/mechanics/monotonicity_test.go)
asserts it over generated finding sets, including the combinations no fixture
covers.

Across reports it is **not** prevented, and saying so is the point of this
entry. If a source withdraws a listing, the next scan recomputes a lower final
severity — reputation moved an asset *down*, which
[severity-model.md](severity-model.md) otherwise forbids. The justification:

- The new attestation is a new claim with a new `attested_at`. It asserts "as of
  now, no consumed source flags this", which is exactly what the scanner can
  honestly say. Refusing to ever lower an escalation would mean the registry
  could never correct, and a wrong escalation is itself a denial of service that
  consumers would learn to ignore.
- `revoke` exists so an honest operator can **withdraw** rather than lower. That
  is the documented way to retract a wrong claim.
- The transition is observable rather than silent: observations are retained and
  served by the history API ([history.md](history.md)), and `internal/temporal`
  reports capability and evidence changes between consecutive scans. A consumer
  that needs to know an asset *was* escalated can see that it was.

Residual risk accepted: a consumer reading only the current attestation sees the
lower level with no indication that it was ever higher.

#### 5. Downgrade by removing a check from the engine

**Verdict: defended.**

`Engine.Run` iterates whatever checks the engine holds, so a report from a
smaller engine used to be indistinguishable from one where the removed check ran
and found nothing — `DOGE` is critical solely through the reputation check, so
removing that check turns it clear. The `assay-evidence-v2` preimage binds the
sorted check IDs that ran, and `attest.VerifyCheckSet` compares a report's bound
set against the set a verifier expects, naming the absent checks rather than
returning a generic mismatch. A report with no bound set is read as *unknown*,
never as complete. See
[contract-interface.md](contract-interface.md#the-preimage-binds-the-check-set).

Not eliminated: whoever controls which code runs controls which checks are in
the engine. Version and check-set binding narrow the window; they do not close
it. Only threshold attestation does.

#### 6. Injection through issuer-controlled strings

**Verdict: defended.**

Every string an issuer controls — asset code, `home_domain`, `stellar.toml`
fields, directory names — is untrusted input, and it reaches the API and the UI.
The evidence preimage escapes `\`, tab, LF and CR inside every field, because
without that an issuer could publish a directory name containing a tab and forge
the preimage of a report that was never produced. The escaping is
security-relevant rather than cosmetic
([contract-interface.md](contract-interface.md#evidence_hash-commits-to-the-claims-not-to-the-clock)).

The scanner's own parsing of `stellar.toml` is covered by
[checks.md](checks.md#sep1-domain); a claim in a `stellar.toml` about an asset
it does not issue cannot pass as reciprocal verification.

#### 7. Hostile or broken source: unbounded body, stalled fetch

**Verdict: defended, with tests.**

A domain the issuer names can serve a multi-gigabyte `stellar.toml`, stream
forever, or never answer. Both HTTP clients cap the read at 1 MiB
(`sep1.MaxBody`, `stellarexpert.MaxBody`) and time out at 15 s, and the caps are
asserted against hostile fixtures rather than assumed
(`internal/sep1/exhaustion_test.go`, `internal/stellarexpert/exhaustion_test.go`).
An oversized body is truncated and then fails to decode rather than allocating
without bound.

#### 8. Unreachable source rendered as a clean result

**Verdict: defended.**

"We could not check" and "this is fine" must never look the same, so they are
programmatically distinct: a finding that could not conclude sets
`Undetermined`, the report carries `UndeterminedChecks` and `State: unknown`,
and failure evidence carries `Attempted: true` with the attempt time rather than
a completion time. A positive signal that arrived is still reported — evidence
of abuse does not become less true because a second source is down — and a
missing listing is never smoothed into "clear". The scanner also treats a nil
directory entry as "not listed" **only** when the source actually answered.

#### 9. Third-party reputation data is wrong

**Verdict: partially defended; accuracy is out of scope.**

Assay consumes StellarExpert's directory and blocklist and does not re-derive or
second-guess them, so a wrong listing produces a wrong severity. Attribution is
the control: the claim is rendered as StellarExpert's, with its URL and
retrieval time, never as an Assay conclusion — and a consumer can see that the
escalation came from a consumed source rather than from the ledger. The failure
direction is asymmetric in Assay's favour: an erroneous listing escalates (a
refusal), and an erroneous *absence* moves nothing, because absence of bad
reputation is never evidence of good. Report data errors upstream; see
[SECURITY.md](../SECURITY.md).

### Availability classes (all fail closed)

#### 10. The attester stops writing

**Verdict: accepted risk; the mitigation is visibility, not prevention.**

The fail-open-by-neglect attack: a pipeline that silently stops turns the
registry into stale attestations, which a consumer's `max_age_secs` converts
into a refusal. It cannot cause an admission, because staleness never reads as
freshness. The designed mitigations are off-chain and **not built yet**: a
per-run record, a non-zero exit on an all-error run, and a staleness check
against `attested_at` read from the chain rather than from the pipeline's own
memory ([attestation-writer.md](attestation-writer.md#5-failure-visibility)).

#### 11. One attestor revokes a correct attestation

**Verdict: accepted risk.**

A revocation is a denial of service, and it fails closed: `get_safety` returns
`None` and every gate refuses. It is indistinguishable from never-attested
on-chain on purpose, because both mean "no claim stands"
([contract-interface.md](contract-interface.md#revoked-and-never-attested-look-the-same-on-chain-deliberately)).
The `revoke` event is what lets an indexer notice.

#### 12. Batch writes used to exhaust a transaction

**Verdict: defended.**

`attest_many` is bounded by `MAX_BATCH_SIZE` (50), derived from the live
transaction resource limits and measured rather than guessed; a longer vector
returns `BatchTooLarge` and writes nothing rather than truncating. The binding
limit is the transaction's contract-event budget, not its fee
([contract-interface.md](contract-interface.md#the-cap-and-why-it-is-50)).
A caller cannot make one call cost unbounded work, and cannot half-apply a batch
to leave an inconsistent view.

#### 13. Archival treated as expiry

**Verdict: defended by documentation and by the contract's own behaviour.**

The obvious guess — that an archived attestation reads as `None` and gates fail
closed — is wrong, and was checked against testnet rather than assumed. Since
protocol 23 an archived persistent entry is restored on access and reads with
its original `attested_at`. So archival is not an expiry control and must not be
used as one; `revoke` is how an attestation is taken back. The behaviour is
pinned by `read_after_archival_returns_original_attestation` and recorded in
[deployment.md](deployment.md#entry-lifetime).

### Out of scope

| Attack | Why it is out of scope |
| --- | --- |
| A `clear` asset is a scam, worthless, or an impersonation | Severity measures **issuer power over holders**, not fraud in general. An asset with no authorization flags genuinely gives its issuer no special power, and Assay says so. See [severity-model.md](severity-model.md#what-severity-does-not-tell-you) |
| Exposure of an *existing* holder's trustline | Attestations describe a prospective holder: what happens if you open a trustline now. Clawback enabled later does not reach trustlines that already exist (CAP-0035) |
| The scanner host or the attester key being compromised | If the machine running the scanner is owned, everything downstream of it is attacker-controlled: the binary, the key and the output. Defending that is OS and key-management work, not scanner work; the on-chain consequence is attack class 1 |
| Consumer-side mishandling: wrong SAC, wrong `max_age_secs`, misusing `None` | The contract's shape makes the safe answer the default — unattested is `None`, every non-happy path returns `false`, a wrong address is unattested rather than someone else's attestation. A consumer that unwraps `None` into a default, or resolves a SAC other than the asset it intends, has left the model; [integrating.md](integrating.md) is the guidance |
| Stellar consensus, Horizon correctness, ledger reversion | Assay reads the ledger; it does not secure it. A reorg or a false Horizon answer is upstream of every claim here |
| Testnet resets | Testnet is periodically reset and removes all state. Recorded in [deployment.md](deployment.md) |
| MEV, front-running, or order flow around a gated action | The gate answers "is this asset safe to hold"; it says nothing about the terms of the trade that follows |
| Reputation data accuracy | Consumed and attributed, not curated. Report it upstream |
| Denial of service against Assay's own HTTP API | Pre-1.0 and not deployed as a service. Missing timeouts or unbounded reads in the fetch layer *are* in scope ([SECURITY.md](../SECURITY.md)) |

## Trust assumptions a reader should check

1. The `Address` a consumer passes is the SAC of the asset it actually means.
   Everything else follows from this: a wrong address is simply unattested and
   fails closed, but a *right* address for the wrong asset is the consumer's
   error, not the registry's.
2. The consumer picks a `max_age_secs` it would accept, not `0` by default.
3. The attester key is honest, or its lies are detected by re-scanning.
4. The scanner's own sources are correct to the extent Assay relies on them —
   and where they are not, the claim is attributed to them rather than to Assay.
5. The attested set is curated deliberately. Attesting by crawling would be
   coverage theatre, and coverage is not a safety property
   ([attestation-writer.md](attestation-writer.md#4-which-assets-and-who-pays)).

## What this document does not authorize

The deployment is **testnet only** and is not a candidate for mainnet. The
single-admin admission risk (class 1) is the blocking gap, and it is not closed
by anything in this document. The testnet pipeline demonstrates and exercises
the machinery; it does not make the registry trustworthy.

## Maintaining this document

- A **new attack class** gets an entry with a verdict, and if the verdict is
  "defended" it gets a test. The contract's `batch_with_one_invalid_entry_writes_nothing`
  and `batch_size_bound_is_measured_and_holds_headroom`, the mechanics
  property test, and the two exhaustion suites exist because of entries here.
- A verdict that changes from "accepted" to "defended" is a code change, not a
  documentation change: update the entry and cite the test that now holds it.
- A verdict that changes from "defended" to "accepted" is a regression to be
  argued explicitly, in the diff, with the reason.
