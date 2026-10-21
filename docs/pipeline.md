# The Scan-to-Gate Pipeline

This document traces a single asset from raw ledger facts through every check, aggregation, encoding, and on-chain decision. It names the file and function responsible for each stage, and states exactly what information is preserved and what is intentionally discarded at the boundaries.

The asset is `DOGE-GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P`. It is the most instructive example because its pure-mechanics severity is 0 (Clear) but its final severity is 4 (Critical), demonstrating the escalation path.

## 1. Retrieval
**Where:** `internal/scan/scan.go` (`Scanner.Scan`)

The scanner fetches raw data from external sources and assembles a `mechanics.Subject`.

- **Horizon:** Fetches the issuer account and asset stats. For DOGE, the issuer has no authorization flags set (no `auth_required`, `auth_revocable`, etc.).
- **StellarExpert:** Fetches directory and blocklist. DOGE is flagged as "DOGE Scam" on a malicious domain.
- **SEP-001:** Fetches `stellar.toml`.

**Discarded here:** Nothing. The `Subject` holds the raw responses, HTTP errors, and exact retrieval timestamps.

## 2. Checks and Classification
**Where:** `internal/mechanics/` (`Check.Run`)

The engine runs a suite of pure functions (checks) over the `Subject`. Each produces a `Finding`.

- **CapabilityCheck:** Sees no authorization flags. Returns severity `0` (Clear) and no capability mechanics.
- **ReputationCheck:** Sees the malicious listing. Returns severity `4` (Critical), the `MECH_BLOCKLISTED` bit, and `Escalation: true`.
- **DomainCheck:** Checks SEP-001 linkage. Fails, returns `MECH_DOMAIN_UNVERIFIED` and `Accountability: unverified`.

**Discarded here:** The raw HTTP responses. The findings extract only the specific capability bits, severity levels, and plain-language reasoning (the claims).

## 3. Aggregation
**Where:** `internal/mechanics/mechanics.go` (`Engine.Run`)

The findings are aggregated into a `mechanics.Report`.

- `Base` (capability-only severity) is the maximum of all non-escalation findings. For DOGE, `Base` is `0`.
- `Severity` (final severity) is the maximum of all findings. The `ReputationCheck` raises this to `4`.
- `Mechanics` is the bitwise OR of all finding bits: `MECH_BLOCKLISTED | MECH_DOMAIN_UNVERIFIED`.
- `Checks` (the list of check IDs) is recorded.
- `Evidence` is concatenated and sorted.

**Discarded here:** Finding-level distinctions. The report only carries the aggregate severity and combined mechanics.

## 4. Attestation Encoding and Hashing
**Where:** `internal/attest/attest.go` (`FromReport` and `Preimage`)

The report is encoded into a canonical bytes buffer to produce the `evidence_hash`.

- The fields (asset, severity 4, base 0, escalated true, mechanics, accountability, checks) and all evidence claims are serialized into a tab-separated, LF-terminated format.
- The `SHA-256` of these bytes becomes the `evidence_hash`.

**Discarded here:** 
- Retrieval timestamps (`RetrievedAt`) are completely excluded so the hash commits to the *claims*, not the *clock*.
- Per-finding plain-language reasoning. The preimage only retains the structured evidence claims.

## 5. The On-Chain Registry
**Where:** `assay-contracts/contracts/safety-registry` (`attest` and `get_safety`)

The `assay attestation` command passes the parameters to the registry contract on-chain.

- The contract verifies the consistency invariant (e.g. `MECH_CLAWBACK_ENABLED` must be at least severity `3`).
- It stores `severity`, `flags`, `evidence_hash`, and records the ledger time as `attested_at`.

**Discarded here:** `Base` severity, accountability, and the actual evidence claims. The contract only holds the summary bits, relying on `evidence_hash` to prove them.

## 6. The Gate Decision
**Where:** `assay-contracts/contracts/safety-registry` (`is_safe`)

A consumer contract calls `is_safe(asset, max_severity, max_age_secs)`.

- If a DEX only accepts `max_severity = 2` (Medium), DOGE fails because its severity is `4`.
- The consumer may also bitwise-check the flags for specific powers (e.g. `flags & MECH_BLOCKLISTED`).

**Discarded here:** The gate returns a boolean. The reason for failure (stale, too severe, missing) is dropped.
