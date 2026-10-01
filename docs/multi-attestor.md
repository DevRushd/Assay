# Multi-attestor writes

**Status: design, for review. Nothing here is implemented.** This document
answers [#88](https://github.com/use-assay/Assay/issues/88). It compares ways
to remove the single-admin trust root, says what each costs, and recommends
one. Implementation is filed separately once a scheme is agreed. The contract
is not changed by this document.

## The problem

Today `init` sets one admin, and `attest` and `revoke` accept only that admin.
A consumer calling `is_safe` is trusting one ed25519 key on one machine
([deployment.md](deployment.md#what-this-deployment-is-not)). That is the
largest single trust assumption in Assay, and it is what has to change before
anyone should rely on the registry for value.

## What a compromised attestor can do today

The actors, their capabilities and the admitted gaps are set out in
[threat-model.md](threat-model.md) (#30; the writer design refers to the same
work as [#52](https://github.com/use-assay/Assay/issues/52)). The relevant part
— and the whole reason a threshold is on the roadmap — is attack class 1 there:
a compromised attester can cause an **admission**, which is the only failure
direction that puts funds at risk. The pipeline-document version of the same
analysis is [attestation-writer.md](attestation-writer.md#threat-model). The
part a threshold has to answer is restated here so the schemes can be compared
against it.

A holder of the admin key, honest or not, can:

| Action | Effect on a consumer | Direction |
| --- | --- | --- |
| Attest `clear` for a dangerous asset | The gate **admits** an asset it should refuse | Unsafe: funds at risk |
| Attest a high severity for a harmless asset | The gate refuses a good asset | Safe: denial of service |
| `revoke` a correct attestation | The gate refuses (reads `None`) | Safe: denial of service |
| Stop writing | Attestations go stale and `max_age_secs` refuses them | Safe: denial of service |
| Attest with a fabricated `evidence_hash` | Detectable after the fact by re-scanning; not preventable on-chain | Detective only |

Only the first row puts funds at risk. The property any scheme must have is
therefore narrow: **no single compromised attestor can cause an admission.**
Denial of service by one attestor is acceptable, as long as it is visible,
because it fails closed. Every scheme below is judged on that first.

## Terms

- **N**: the number of attestors in a set. **M**: the threshold.
- **Responding**: an attestor with a *fresh* attestation for the asset, fresh
  meaning within the consumer's `max_age_secs`. A stale attestation counts as
  not responding. Archived entries are restored on read and carry their
  original `attested_at` ([deployment.md](deployment.md#entry-lifetime)), so
  they are judged the same way.
- **Agree**: two attestations agree when their `severity` and `flags` are
  equal. `evidence_hash` is deliberately excluded. Independent scanners should
  reproduce the same hash, but three of the ten live attestations embed
  machine-dependent transport text
  ([#24](https://github.com/use-assay/Assay/issues/24)). Requiring equal hashes
  would turn a known reproducibility defect into disagreement. Hashes are
  still stored per attestor, so a verifier can check each one.

## The three states a threshold must keep apart

The issue asks for disagreement and non-response to be distinct. They are, and
they mean different things:

| State | Condition | Gate result | What it means operationally |
| --- | --- | --- | --- |
| **Met** | At least M responding attestors, and the aggregation rule produces a result | Admit or refuse on that result | Normal |
| **Unavailable** | Fewer than M responding | Refuse | A liveness problem: attestors are down, slow, or have stopped. Nothing is wrong with the claims. |
| **Contested** | At least M responding, but they do not agree as the rule requires | Refuse | Something is wrong with a claim. An attestor is buggy, compromised, or running a different check set, or the issuer changed flags between two scans. It needs a human. |

Both non-Met states fail closed. They must be distinguishable to an observer,
because one needs waiting and the other needs investigation. A registry that
reports only `false` for both hides an attack behind what looks like an outage.

## Scheme A: the admin becomes a threshold account

Keep the contract as it is. Make the `admin` address a Stellar account with
M-of-N signers (native multisig), or a Soroban custom-account contract that
checks M signatures. `require_auth` then needs M signatures.

- **Registry changes:** none. The contract already calls `admin.require_auth()`,
  and that works unchanged with a multisig account or a custom account. It can
  be adopted on the next deploy, or on the current one by rotating the admin
  account's signers.
- **Trust assumption:** that M signers each *independently re-scan* before
  signing. The scheme cannot check this. A coordinator builds one transaction
  with one set of values, and signers approve those values. If they
  rubber-stamp, the threshold protects the key but not the claim.
- **What one compromised attestor can do:** alone, nothing. It cannot sign an
  admission by itself. It can refuse to sign, which is Unavailable. With a
  compromised *coordinator*, it can propose a bad value that careless signers
  approve.
- **Disagreement vs non-response:** not representable. A signer who disagrees
  just does not sign, which looks the same as one who is offline. The registry
  only ever sees Met.
- **Failure modes:** rubber-stamping; signer-set changes are account
  operations outside the contract's view; a consumer cannot see who signed or
  how many signers there are without reading the account.
- **Cost:** one entry per asset, one read per gate call. Unchanged.

## Scheme B: an on-chain quorum inside the registry

The registry holds an attestor set and a threshold, configured by a governance
key. Each attestor submits its own proposal for an asset. An attestation
stands when M proposals agree. Consumers keep calling `get_safety` and
`is_safe` unchanged.

- **Registry changes:** new storage for the attestor set, the threshold and
  per-attestor proposals (`Proposal(attestor, asset)`); an `attest` that records
  a proposal and recomputes the standing attestation; governance entrypoints to
  add and remove attestors and change M; a `quorum_status(asset)` read that
  returns Met, Unavailable or Contested; events for each. `get_safety` returns
  the standing attestation, or `None` when not Met.
- **Trust assumption:** that the attestors are independent, **and** that the
  governance key that manages the set is honest. That key can add M attestors
  it controls, or lower M to 1, and reach an admission without compromising
  anyone. The single root moves from "who attests" to "who picks the
  attestors". It needs its own threshold, and then the question repeats.
- **What one compromised attestor can do:** alone, it cannot make an attestation
  stand. It can submit a divergent proposal to push an asset into Contested,
  which is a visible denial of service. It can stay silent to push towards
  Unavailable.
- **Disagreement vs non-response:** fully representable on-chain, since the
  registry sees every proposal.
- **Failure modes:** governance capture, as above. Proposals submitted at
  different times can "agree" across an issuer's flag change unless the
  registry requires the M agreeing proposals to fall within a window, which is
  a registry-wide freshness policy the current design deliberately leaves to
  callers ([freshness.md](freshness.md#who-decides)). Every change to the set is
  a change under every consumer at once.
- **Cost:** N proposal entries per asset, each with its own TTL. A write
  recomputes the quorum over up to N entries. Reads stay one entry.

## Scheme C: independent attestors, quorum chosen by the consumer

The registry stops having an admin for attestations. Any address can attest,
but only under its own name: storage is keyed by `(attestor, asset)`, and
`attest` requires the attestor's own authorization. The consumer names the
attestors it trusts and the threshold it wants, per call.

```rust
// Sketch, not an ABI commitment.
pub fn attest(env: Env, attestor: Address, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn revoke(env: Env, attestor: Address, asset: Address) -> Result<(), Error>;
pub fn get_attestation(env: Env, attestor: Address, asset: Address) -> Option<Safety>;
pub fn quorum(env: Env, asset: Address, attestors: Vec<Address>, threshold: u32, max_age_secs: u64) -> Quorum;
pub fn is_safe_quorum(env: Env, asset: Address, attestors: Vec<Address>, threshold: u32, max_severity: u32, max_age_secs: u64) -> bool;

pub enum Quorum {
    Met(Safety),                             // aggregated, see below
    Unavailable(u32),                        // responding count, < threshold
    Contested(u32),                          // responding count, >= threshold
}
```

**The aggregation rule is the important part.** Recommended: *conservative
aggregation*. Require at least M responding attestors. If they do, the result
takes the **highest** severity and the **union** of flags among all responding
attestors, not only M of them. Report Contested when responding attestors
differ, and still return the conservative result alongside for observers. A
stricter alternative is to require M exactly-agreeing attestors and treat any
difference as Contested with no result. Conservative aggregation is preferred
because it follows the rule that already holds for severity: danger can be
raised, never lowered.

- **Registry changes:** re-key storage from `Safety(asset)` to
  `Attestation(attestor, asset)`; `attest` and `revoke` take the attestor and
  require its auth; remove the admin from the write path; add `quorum` and
  `is_safe_quorum`, bounding `attestors.len()` (say 16) so the read budget is
  predictable; **deduplicate** `attestors` before counting, since otherwise a
  consumer listing one attestor M times gets a quorum of one; reject
  `threshold == 0` and `threshold > attestors.len()`. Events gain the attestor
  as a topic. The existing single-attestor calls can remain as
  `get_attestation` with one named attestor, for a migration period.
- **Trust assumption:** that the attestors a consumer names are operated
  independently: different operators, different machines and keys, and ideally
  different scanner builds, since a shared scanner bug is a common-mode failure
  a threshold cannot catch ([#54](https://github.com/use-assay/Assay/issues/54)).
  There is no governance key. Nobody can change a consumer's attestor set but
  the consumer.
- **What one compromised attestor can do:** under conservative aggregation it
  **cannot cause an admission** as long as at least one honest attestor in the
  set is responding, because the maximum wins. It can raise severity or add
  flags, which refuses, and which is visible as Contested with its address
  attached. It can stay silent, which counts towards Unavailable. To force an
  admission, an attacker needs M compromised attestors **and** every honest
  attestor in the set to be non-responding within the window. That is a
  stronger bound than M-of-N agreement gives.
- **Disagreement vs non-response:** representable, and computed from exactly
  the attestors this consumer trusts, not from a global set.
- **Failure modes:** a consumer picks a poor set, for example one where every
  attestor is run by the same party. The registry cannot prevent that, and
  docs must say so. A single honest-but-buggy attestor that over-reports
  causes denial of service for every consumer that names it, visibly. Anyone
  can write, so storage grows with writers, but rent is paid by the writer and
  consumers read only the entries they name.
- **Cost:** a quorum read touches up to N entries instead of one. At N ≤ 5 this
  is small next to the call it protects, but it must be measured against the
  Soroban read budget before an ABI is fixed. Each attestor pays its own rent
  and TTL extension ([deployment.md](deployment.md#entry-lifetime)).

## Comparison

| | A: threshold admin | B: registry quorum | C: consumer quorum |
| --- | --- | --- | --- |
| One compromised attestor can admit | No (unless signers rubber-stamp) | No | No, and not with up to M−1 others, while one honest attestor responds |
| Remaining single root | The coordinator building the transaction | The governance key managing the set | None in the registry; the consumer's own choice of set |
| Disagreement visible on-chain | No | Yes | Yes, per consumer's set |
| Disagreement vs non-response distinct | No | Yes | Yes |
| Registry changes | None | Large: set, threshold, proposals, governance | Moderate: re-key storage, quorum read, drop admin |
| Consumer changes | None | None | Must name attestors and threshold |
| Read cost per gate call | 1 entry | 1 entry | Up to N entries |
| Fits "freshness is the caller's policy" | Yes | Strains it: needs a registry-wide agreement window | Yes: the window is the caller's `max_age_secs` |

## Recommendation

**Adopt C, with conservative aggregation. Use A as an interim step now.**

Criteria, in priority order:

1. **No single compromised party can cause an admission.** A and B meet this
   for attestors but each keeps a single root elsewhere: the coordinator in A,
   the governance key in B. Only C removes the root from the registry.
2. **Disagreement is observable and distinct from outage.** A cannot express
   it. B and C can. C reports it against the set the consumer actually trusts.
3. **Consistency with existing design.** The registry already makes freshness
   the caller's decision ([freshness.md](freshness.md#who-decides)). C makes
   trust the caller's decision in the same way. B would need a registry-wide
   freshness policy to define agreement.
4. **Cost and complexity.** A is free and C is moderate. B is the most code and
   the most governance surface.

A is worth doing first because it needs no contract change: moving the admin
to a 2-of-3 account with signers on separate machines, each re-scanning before
signing, removes the one-key-on-one-machine exposure immediately. It is not
the end state, because it cannot show disagreement and still trusts whoever
builds the transaction.

## What an implementation issue for C must decide

These are left open on purpose. They need maintainer answers before code:

- The attestor cap and the measured read budget at that cap.
- Whether the strict exact-agreement rule is offered alongside the
  conservative one, or conservative only.
- The migration path from `Safety(asset)` storage, and how long single-attestor
  reads remain.
- Whether Assay publishes a recommended default attestor set, and who the
  independent operators would be. A threshold of attestors all run by one
  team is Scheme A with extra steps.
- How the revoke event and the `Contested` state reach the attestation writer's
  alerting ([attestation-writer.md](attestation-writer.md#5-failure-visibility)).
