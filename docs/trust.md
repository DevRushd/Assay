# Trust Boundaries

What a reader or consuming contract is trusting when they act on an Assay
verdict.

The trust model of Assay is intentionally separated across multiple layers:
on-chain ledger facts, off-chain scanner code, curated third-party reputation,
and the attester key that bridges them. This document collects every trust
assumption into one place so integrators can evaluate what must hold true for an
Assay verdict to be sound, what happens if any party is wrong or dishonest, and
the exact boundary between verifiable facts and relayed claims.

For the threat analysis across attackers, defended vectors, and accepted risks,
see [the threat model](threat-model.md). For how to call the on-chain gate
safely, see [integrating.md](integrating.md).

---

## Verifiable Facts vs. Relayed Claims

Assay handles two fundamentally different categories of data:

| Category | Source | Nature | Verification |
| --- | --- | --- | --- |
| **Verifiable facts** | Stellar ledger (Horizon / RPC) | Consensus-enforced facts about issuer capabilities (`auth_required`, `auth_revocable`, `auth_clawback_enabled`, `auth_immutable`). | Independent verification: anyone running an archive node or querying Horizon can independently verify these bits at any ledger sequence. |
| **Relayed claims** | Third parties (StellarExpert directory, blocked domains, SEP-1 `stellar.toml`, SEP-0042 asset lists) | Published statements by external operators. | Attributed only: Assay attributes each claim to its upstream source URL and fetch time, but does not independently re-derive or endorse reputation. |

Assay never combines these categories into a single blended score.
`severity` is capability-only, derived strictly from consensus-enforced flags
(see [docs/severity-model.md](severity-model.md)). Third-party curation can
escalate severity to `Critical` upon a malicious listing, but can never lower
it, and never sets capability bits.

---

## Trust Matrix: Who Must Be Trusted and The Consequences

When acting on an Assay verdict (either off-chain via CLI/API or on-chain via
`get_safety` / `is_safe`), a consumer relies on the following parties:

| Party | What you are trusting them for | How it is bounded / audited | Consequence if dishonest or wrong |
| --- | --- | --- | --- |
| **Asset Issuer** | Not changing authorization flags after an attestation is computed. | Bounded by the consumer's `max_age_secs` policy and measured change rates ([docs/freshness.md](freshness.md)). Flags locked with `auth_immutable` can never change. | **Unsafe admission:** If an issuer enables `auth_clawback_enabled` after `attested_at`, a gate accepting stale attestations will admit a confiscation-capable asset. |
| **Attester Key Holder** | Signing attestations that faithfully reflect scanner output without tampering. | `evidence_hash` commits to the full canonical evidence bundle (preimage). Any observer can independently re-scan and detect discrepancies. | **Unsafe admission or DoS:** A compromised key can write `Clear` (0) for a dangerous asset (unsafe admission) or write false high severities/revoke legitimate assets (denial of service). |
| **Scanner Code / Evaluator** | Correctly interpreting raw flags and encoding the evidence preimage according to the documented specification. | Open source code that anyone can inspect, build, and run locally. Offline deterministic unit and regression suites. | **Unsafe admission:** Buggy evaluation could under-report capability severity, admitting an unsafe asset. |
| **Ledger Ingestion (Horizon / RPC nodes)** | Serving truthful account and asset flag states without omissions or indexer drift. | Differential reading: Assay reads authorization flags across two independent ingestion endpoints (`/assets` and `/accounts`) and takes the most dangerous reading on disagreement ([docs/checks.md](checks.md)). | **Unsafe admission:** If both Horizon copies simultaneously omit an active flag, capability could be scored lower than consensus rules enforce. |
| **Curated Reputation Providers (e.g. StellarExpert)** | Accurately identifying scam domains and malicious issuers. | Reputation is strictly monotonic upward: absence from a list never lowers severity or grants a clean bill of health. Inclusion in curated lists is never a safety endorsement. | **Delayed escalation or false refusal:** If a provider fails to list a scam, Assay cannot escalate on reputation alone (falls back to capability severity). If a provider falsely lists an honest asset as malicious, Assay escalates to `Critical` (fails closed, funds remain safe). |
| **Domain Operators (SEP-1 `stellar.toml`)** | Serving valid TOML files that match the asset code and issuer account reciprocally. | Reciprocal matching: issuer account must point to domain, and domain's TOML must list code and issuer. Content never affects severity. | **Spoofed accountability (no capability impact):** A compromised domain can only affect whether accountability reads `verified` or `unverified`. It cannot move severity or bypass capability checks. |
| **Consuming Contract / Caller** | Enforcing the gate correctly: passing a strict `max_age_secs`, checking the severity ceiling, and checking the capability bitmask. | Reference implementations provided in [docs/integrating.md](docs/integrating.md) and [`contracts/example-gate`](../assay-contracts/contracts/example-gate). | **Self-inflicted admission:** If the consumer ignores `None` (unattested), omits `max_age_secs`, or checks only severity without checking capability bits, the contract will admit unsafe assets. |

---

## The Core Trust Boundaries

### 1. The On-Chain Gate Is an Attestation Store, Not an On-Chain Scanner
A Soroban smart contract cannot make HTTP calls or query external ledger indexers
mid-transaction. Therefore, the on-chain contract (`get_safety`) does not scan;
it stores attestations signed by the off-chain attester key.
- **Why this exists:** It allows atomic gating in the same transaction as a swap
  or deposit, preventing front-running between check and action.
- **The limit:** The caller is trusting the attester key.

### 2. `evidence_hash` Makes Trust Verifiable Rather Than Blind
The registry stores `evidence_hash`, a SHA-256 digest of the canonical
evidence preimage containing the exact asset, severity, flags, accountability,
check-set, and raw source claims.
- Anyone can run `assay attestation CODE-ISSUER` to recompute the preimage and
  hash from scratch.
- If an attester writes a fraudulent attestation, the fraud is permanently
  recorded on-chain with cryptographic evidence of the discrepancy.

### 3. Attestations Age: Freshness Is Gated by the Caller
The registry records `attested_at` as the ledger timestamp when the write
occurred.
- Issuer flags can change in a single ledger close (~5 seconds) unless
  `auth_immutable` is set.
- Assay contracts do not guarantee eternal freshness; consuming contracts must
  supply `max_age_secs` to reject stale records according to their own risk
  tolerance.

### 4. Severity Is Capability, Not Intent
Assay answers **what an issuer can do**, never **what they will do**.
- A regulated stablecoin with clawback and a malicious honeypot with clawback
  receive the same severity (`High` / 3).
- Consumers who require immunity from confiscation must gate on the bitset
  (`is_safe_masked` with `MECH_CLAWBACK_ENABLED`) rather than assuming a low
  severity means an issuer is trustworthy.


