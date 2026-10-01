# The attestation writer pipeline

**Status: design. Not implemented, deliberately.** This document answers the
open questions in [#8](https://github.com/use-assay/Assay/issues/8) so that the
trust model can be agreed before any code lands. No `cmd/assay-attester`
exists yet; nothing here is on the critical path of the scanner or the
contract.

The contract half exists and is tested:
[`assay-contracts/contracts/safety-registry`](../assay-contracts/contracts/safety-registry/src/lib.rs)
defines `attest` and its write-time invariants, and is live on testnet
([deployment.md](deployment.md)). Today nothing drives it: `get_safety`
returns `None` for every asset in the world except the ten recorded in
[attestation-run.md](attestation-run.md), written by hand through
`make attest`, and every gate correctly fails closed on the rest. This
document is the design for the thing that changes that.

Read [freshness.md](freshness.md) alongside this one: it defines *how often*
attestations must be refreshed and *why those numbers*, which this document
consumes but does not re-derive.

## The pipeline in one paragraph

A scheduled process scans assets exactly as `assay scan` does, derives
attestation arguments exactly as `assay attestation` does — via
[`attest.FromReport`](../internal/attest/attest.go), with no path that lets a
hand-written severity reach the chain — and submits them to the registry. A
watcher re-scans the issuers of already-attested assets on a short interval
and triggers re-attestation the moment a capability changes, per the policy in
[freshness.md](freshness.md). Every run leaves an observable record of what it
attested, what it refused, and what failed, so the pipeline cannot silently
stop writing.

## The five questions

### 1. Who attests

**Decision for the first implementation: the single admin key the contract
already assumes.** The registry's `attest` requires the admin's authorization,
and there is no threshold mechanism to use — building one is
[#88](https://github.com/use-assay/Assay/issues/88) and needs a stated threat
model ([#52](https://github.com/use-assay/Assay/issues/52)) before a scheme
can be chosen. This is a limitation, stated as such in
[contract-interface.md](contract-interface.md#not-done-yet), and it caps what
the first pipeline is *for*: it can make the testnet registry useful and
exercise the writer machinery, and it must not be read as production trust
infrastructure.

What the single key buys that is not nothing: the writer path, the refusal
path, the dry-run mode, and the run records are all identical to what a
threshold deployment would drive. Swapping the signer later does not redesign
the pipeline; it redesigns the contract.

The key lives in the `assay-attester` stellar CLI identity
([deployment.md](deployment.md) records its address). Key custody and rotation
procedure are operational concerns documented in
[attester-key.md](attester-key.md) and tracked as
[#150](https://github.com/use-assay/Assay/issues/150); this design only
requires that the pipeline never accepts a seed file path from a report or a
scan — the key is configuration, and the pipeline fails to start without it
rather than falling back to an unsigned simulation that *looks* like success.

### 2. What is signed

**Decision: exactly what `attest` already takes — `severity`, `flags`,
`evidence_hash` — with `evidence_hash` computed by
[`attest.FromReport`](../internal/attest/attest.go) over the canonical
preimage specified in [contract-interface.md](contract-interface.md).** The
encoding is line-oriented, escaped, version-tagged (`assay-evidence-v1`), and
was verified byte-for-byte against an independent re-implementation on
2026-09-17 ([attestation-run.md](attestation-run.md#reproducibility-audit-2026-09-17)).
No new signature surface is introduced and none is needed: the admin's
transaction signature authorizes the write, and the hash is what makes the
write *checkable* afterwards.

What the hash binds: every claim the report consumed, attributed by source and
URL, plus the severity, base severity, escalation state, mechanic bitset and
accountability they produced. A verifier can re-scan and reproduce it exactly —
with one known, documented exception: reports whose evidence embeds
machine-dependent transport text ([#24](https://github.com/use-assay/Assay/issues/24),
three of the ten on-chain hashes). The
[evidence-only detector](transitions.md#evidence-only-changes) exists to
classify exactly that case when a verifier hits it.

What the hash does **not** bind: the scanner version
([#40](https://github.com/use-assay/Assay/issues/40)), the network
([#41](https://github.com/use-assay/Assay/issues/41)), or the check-set
identity ([#42](https://github.com/use-assay/Assay/issues/42)). Until those
land, `evidence_hash` proves *that* evidence produced this attestation, not
*which code* turned the evidence into the verdict. See the threat model below.

The asset is keyed on its **Stellar Asset Contract address**, derived from the
network passphrase (`stellar contract id asset`). The derivation is
network-scoped, so a pubnet scan attested to a testnet registry keys a
different address than the same asset would on pubnet — the scans-read-pubnet,
attests-to-testnet split in [deployment.md](deployment.md#the-assets-are-mainnet-the-attestations-are-testnet)
rests on this and the pipeline must derive the address with the *registry's*
network, not the scan's.

### 3. Partial-evidence policy

**The rule, normatively: a partial scan is never attested. Not at its
measured severity, not at a lower one, not with a marker. It is refused.**

A scan is partial when any check reports `undetermined` — a source it depends
on did not answer. `attest.FromReport` already refuses such reports
(`ErrUndetermined`), and that behaviour is the policy; the pipeline adds
nothing and strips nothing.

The alternatives were considered and rejected:

- *Attest with an explicit incompleteness marker.* The contract's `Safety`
  struct has nowhere to put one, and its callers have no way to read it:
  `get_safety` returns a severity and a timestamp, and the example gate reads
  a severity and a bitset. Adding a field is an ABI change every consumer
  would have to honour, and the one thing a gate demonstrably does with a
  severity is compare it — so a partial attestation marked in a field nobody
  reads is indistinguishable, to every downstream gate, from a complete one.
  Writing it would be indistinguishable from lying.
- *Attest the part that completed.* `is_safe` compares one number. "The
  capability half is fully readable" is true and irrelevant: a gate refusing
  on `severity <= max` cannot know whether the missing reputation axis would
  have raised it. This is exactly the failure
  [Finding 1](attestation-run.md#finding-1) fixed off-chain; the on-chain
  half of the same rule is refusing to write.

The already-decided asymmetry stands and the pipeline inherits it: a positive
listing that *did* arrive still escalates even if the other source is down,
and a report that reached `critical` with every flag checked is complete —
`critical` is the ceiling, so nothing still missing could raise the level
further. `FromReport` accepts it. The one refusal the pipeline can surface
that the contract cannot: a re-scan whose evidence changed such that the new
severity is *lower* is still a valid attestation write (the severity is what
the evidence says now), but a re-scan that comes back **undetermined** must
never delete or soften the previous attestation — there is no unset path, and
deliberately so; staleness is handled by `attested_at`, not by erasure.

### 4. Which assets, and who pays

**Decision: the attested set is a maintained list, scoped to assets with
plausible consumer exposure, and the attester key pays.** The pipeline does
not discover what to attest by crawling the network: an attestation is a
claim somebody is expected to rely on, and unattended coverage would be
coverage theatre at best. The list starts as the ten assets in
[attestation-run.md](attestation-run.md) and grows deliberately, the way the
scan corpus grew — each addition chosen, scanned, and recorded before it is
attested.

Costs, verified 2026-09-25: testnet inclusion fees sit at the 100-stroop
network minimum (p95 200 stroops) via `getFeeStats`; the resource fee for a
one-persistent-entry write adds a fraction of an XLM at most. Ten assets
re-attested daily is on the order of a few XLM **per year** — fees do not
constrain the design, which is why [freshness.md](freshness.md) can recommend
a daily schedule plus event-driven re-attestation without a budget argument.
That fee argument means batching is not required for the list above. It is
available anyway, because the ceiling it lifts is not the fee one. `attest_many`
(see [contract-interface.md](contract-interface.md#attest_many-many-attestations-in-one-transaction))
writes up to `MAX_BATCH_SIZE` assets in one contract invocation, all-or-nothing,
so the per-ledger limit on coverage moves from one asset to one batch. What
bounds a batch is the transaction's event budget rather than its cost: every
element publishes its own per-asset event, and 50 of them consume 61% of the
16 384-byte budget.

The fee floor is not zero: a run whose submissions fail on an unfunded key
must be visible as a failure (see question 5), not as an empty success.

### 5. Failure visibility

**The failure mode this section exists for: a pipeline that silently stops
writing.** Stale-but-valid attestations would then be gated on indefinitely —
[freshness.md](freshness.md)'s whole analysis assumes someone is actually
re-attesting. Three mechanisms, in increasing order of honesty:

1. **Every run writes a run record** — machine-readable, one entry per asset:
   attested (with tx hash), refused (with the refusal reason verbatim:
   undetermined, invariant violation), or errored (with the error). A run
   record with zero entries is itself an error. The record is the pipeline's
   observable output; it is written even when every submission fails.
2. **A run that is all errors exits non-zero.** An orchestrator (cron, CI
   timer) can therefore alert on a dead pipeline without parsing anything.
3. **Staleness is checked against the chain, not against the pipeline's
   memory.** A monitoring step reads `attested_at` from the registry for every
   listed asset and compares against the schedule in
   [freshness.md](freshness.md). This is deliberately a check of the *output*
   rather than the *process*: it also catches a pipeline that runs green but
   writes to the wrong contract ID.

The runbook for these alerts is [#115](https://github.com/use-assay/Assay/issues/115);
this design specifies what is observable, not who gets paged.

## Dry-run mode

**Specified: `assay-attester --dry-run`.** With the flag set, the pipeline
performs the full path — scan, derive `Params` via `FromReport`, including the
confiscation-invariant and undetermined re-checks, derive the SAC address for
the target network — and then **stops before signing**. It prints, per asset,
the same triple `assay attestation -raw` produces plus the derived SAC
address, and exits:

- `0` — every asset produced a submission-ready `Params` (would-attest);
- `1` — at least one asset was refused (undetermined or inconsistent), with
  the reason printed verbatim per asset;
- `2` — operational failure (scan transport, config), distinct from a refusal.

Dry-run requires no key material at all: refusing a run for a missing seed in
dry-run mode would make the mode useless as a config check. This is the
artifact a reviewer inspects before a real write, and the artifact CI can
produce for the attested set on every change to the scanner — a diff in
dry-run output is the earliest possible signal that an attestation on-chain is
about to diverge from what the code now produces.

## Shape of the command

```
cmd/assay-attester
  --config PATH        asset list + network + contract ID + cadence
  --dry-run            scan, derive, print; never sign
  --once               one pass, then exit (the unit schedulers invoke)
  --watch              issuer watcher for event-driven re-attestation
```

Per asset, one pass is: `scan` → `mechanics` report → `attest.FromReport` →
(if unchanged evidence-hash **and** still fresh per
[freshness.md](freshness.md), skip — re-attestation with identical evidence
moves only the timestamp, and doing it pointlessly doubles the write load) →
submit → record. The watcher pass is the same loop keyed on capability
transitions detected by
[`temporal`](../internal/temporal) between consecutive scans.

## Threat model

Stated for the single-admin deployment this design ships against. "The
attester" below means whoever holds the admin key — including an attacker who
compromised it.

**What a malicious or compromised attester can do:**

- Attest **any severity for any asset**, including `clear` for a known scam
  and `high` for an asset it does not like. Nothing on-chain prevents this;
  the contract cannot check an `evidence_hash`, it only stores it.
- **Overwrite** an existing attestation. `attest` keeps no history
  ([#92](https://github.com/use-assay/Assay/issues/92)), so the overwritten
  values are gone. `revoke`
  ([#86](https://github.com/use-assay/Assay/issues/86)) lets an honest admin
  withdraw a bad write rather than overwrite it, but the same key can also
  revoke a *correct* attestation. That is a denial of service, and it fails
  closed. `revoke` is in the contract source but not yet on the live testnet
  deployment ([deployment.md](deployment.md#migrating-to-a-registry-with-revoke)).
- Attest assets **never scanned**, with an `evidence_hash` of all zeroes.
- Refuse to write, or stop writing — the fail-open-by-neglect attack. It
  degrades the registry to staleness, which `is_safe`'s `max_age_secs`
  converts to fail-closed at the consumer, at a rate the consumer chooses.

**What `evidence_hash` protects against — and what it does not:**

- *It makes a malicious write **detectable**, not preventable.* Any attestation
  whose hash does not reproduce from a re-scan is provably not backed by the
  evidence it implies. That converts "trust the attester" into "verify the
  attester", after the fact, by anyone. This is worth having — it is the
  difference between a lie and a checkable lie — but it is a detective
  control. A consumer that gates *without* verifying hashes is still fully
  exposed to a malicious writer.
- *It does not survive a scanner downgrade*
  ([#54](https://github.com/use-assay/Assay/issues/54)). If the attacker
  controls which code runs, the hash is internally consistent with whatever
  the compromised scanner concluded. Version binding
  ([#40](https://github.com/use-assay/Assay/issues/40)) and check-set binding
  ([#42](https://github.com/use-assay/Assay/issues/42)) narrow this; nothing
  eliminates it except threshold attestation.
- *It does not bind the network* — closed. The preimage binds the network
  passphrase under `assay-evidence-v3`
  ([#41](https://github.com/use-assay/Assay/issues/41)), so a testnet scan and
  a pubnet scan of the same code+issuer no longer hash identically, and the
  scanner refuses to run when its network cannot be determined before any
  fetch. See [contract-interface.md](contract-interface.md), "The preimage
  binds the network".

**Consequence for the deployment claim this design is allowed to make:** the
testnet pipeline demonstrates and exercises the machinery. It does not make
the registry trustworthy; that requires the multi-attestor work
([#88](https://github.com/use-assay/Assay/issues/88)) behind a signed threat
model ([#52](https://github.com/use-assay/Assay/issues/52)). This document
asks for maintainer sign-off on exactly that scope boundary.

## Verified against live surfaces, 2026-09-25

- `stellar` CLI 27.1.0 installed locally; `stellar contract invoke` supports
  `--send=no` (simulate, do not sign or submit — the mechanism dry-run and the
  read path use), `--fee` (override the simulated resource fee), and `--cost`.
  Default behaviour submits when simulation indicates writes or required auth,
  which is the correct default for `attest` (it always writes) and the reason
  reads use `--send=no` explicitly.
- Testnet RPC `getFeeStats`: inclusion fee mode 100 stroops, p95 200 stroops.
  Fee posture for the daily schedule is therefore negligible; no batching or
  fee-auction machinery is designed in.
- CAP-0035 re-read from `stellar/stellar-protocol@master`: clawback
  authorization is fixed at trustline creation
  (`AUTH_CLAWBACK_ENABLED_FLAG` "must be set when a trustline is created";
  `SetTrustLineFlagsOp` can unset `TRUSTLINE_CLAWBACK_ENABLED_FLAG` but cannot
  add it retroactively), so a *newly-set* issuer clawback flag does not reach
  existing trustlines. This is the fact
  [freshness.md](freshness.md#the-exposure-window-stated-honestly) is built
  on. Confirmed against both the live pubnet and testnet ledgers (~5 s close
  cadence, 2026-09-25) that Horizon serves ledger state in real time.

## What this document does not decide

- Revocation ([#86](https://github.com/use-assay/Assay/issues/86)),
  TTL extension ([#87](https://github.com/use-assay/Assay/issues/87)),
  multi-attestor ([#88](https://github.com/use-assay/Assay/issues/88)),
  admin rotation ([#89](https://github.com/use-assay/Assay/issues/89)),
  key custody ([#150](https://github.com/use-assay/Assay/issues/150), see
  [attester-key.md](attester-key.md)),
  the re-attestation runbook
  ([#115](https://github.com/use-assay/Assay/issues/115)).
- Whether `undetermined` belongs in the preimage
  ([#43](https://github.com/use-assay/Assay/issues/43)) — irrelevant here,
  because undetermined reports are refused before a preimage would be hashed
  into an attestation.
