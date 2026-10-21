# Observation Timestamp Semantics

Assay evaluates and stores temporal facts about Stellar assets. Every downstream
temporal capability — on-chain freshness gating, off-chain cache TTLs, historical
observation tracking, and transition detection — depends on an unambiguous answer
to the question: **as of when is this fact true?**

Three distinct time values exist in Assay. None is interchangeable with another,
and each serves a specific layer of the system.

| Time Value | Struct & Field | Clock Source | Precision | Authority | Scope |
| --- | --- | --- | --- | --- | --- |
| **Observation / Retrieval** | `Evidence.RetrievedAt`<br>`Subject.*FetchedAt` | Scanner host wall clock (`time.Now().UTC()`) | Nanoseconds (`time.Time`), RFC 3339 in JSON | Authoritative for individual evidence claims | Per-source fetch completion (or attempt) |
| **Scan / Report** | `Report.ScannedAt`<br>`Subject.ScannedAt` | Scanner host wall clock (`time.Now().UTC()`) | Nanoseconds (`time.Time`), RFC 3339 in JSON | Authoritative for full scan run off-chain | Approximation over up-to-30s sequential fetch window |
| **Attestation** | `Safety.attested_at`<br>`Attested.attested_at` | Stellar consensus ledger (`env.ledger().timestamp()`) | Seconds (`u64`) | **Authoritative for on-chain freshness decisions** | Entire attestation written on-chain |

---

## 1. The Three Time Values

### Observation Time (`Evidence.RetrievedAt`, `Subject.*FetchedAt`)

**What it means:** When a specific external source answered an inquiry about an
asset (or when that inquiry failed).

Every signal consumed by Assay originates from an upstream source:
- Horizon `/assets` (`Subject.StatFetchedAt`)
- Horizon `/accounts` for issuer flags (`Subject.IssuerFetchedAt`)
- SEP-0001 `stellar.toml` (`Subject.Toml.FetchedAt`)
- StellarExpert directory API (`Subject.DirectoryFetchedAt`)
- StellarExpert blocked-domains API (`Subject.BlockedFetchedAt`)
- Horizon `/accounts` for holder trustline balance (`Subject.HolderFetchedAt`)

Because each HTTP request resolves independently, each source has its own
observation timestamp. `Evidence.RetrievedAt` records the exact instant that
specific source responded.

- **Clock Source:** The local system clock of the scanner process (`time.Now().UTC()`).
- **Precision:** Nanosecond resolution in memory (`time.Time`), serialized as
  UTC ISO 8601 / RFC 3339 strings (`"2006-01-02T15:04:05Z"` or with fractional
  seconds) in JSON APIs.
- **Use:** Used in [`internal/temporal`](transitions.md) to detect evidence-only
  transitions, and in audit trails to prove when an upstream authority made a
  specific statement.

### Scan Time (`Report.ScannedAt`, `Subject.ScannedAt`)

**What it means:** When a complete scan was initiated off-chain.

`Subject.ScannedAt` is stamped at the very beginning of `scan.Scanner.Subject()`
before any network calls are dispatched. It is subsequently copied to
`Report.ScannedAt` when the mechanics engine aggregates all findings.

- **Clock Source:** The local system clock of the scanner process (`time.Now().UTC()`).
- **Precision:** Nanosecond resolution in memory (`time.Time`), serialized in
  RFC 3339 format in JSON reports.
- **Sequential Fetch Approximation:**
  The scanner fetches upstream sources **sequentially** over a bounded context
  timeout of up to 30 seconds (`context.WithTimeout(..., 30*time.Second)`):
  1. Horizon `/assets` lookup
  2. Horizon `/accounts` issuer lookup
  3. SEP-1 `stellar.toml` discovery and fetch
  4. StellarExpert directory and blocked-domain queries
  5. (Optional) Holder trustline lookup

  Because these operations run in sequence rather than atomically, `ScannedAt` is
  an **approximation across the fetch window**. A claim retrieved near the end
  of the scan (such as a blocked-domain check or a slow `stellar.toml`) may have
  an observation time up to **30 seconds later** than `ScannedAt`. `ScannedAt`
  is therefore the lower bound of the scan window, not an exact instant for all
  contained facts.
- **Use:** Report-level grouping, API response metadata, and off-chain indexing.

### Attestation Time (`Safety.attested_at`)

**What it means:** When the attestation was written into Soroban persistent storage
on the Stellar ledger.

When an attester calls `attest(env, asset, severity, flags, evidence_hash)`, the
contract reads the current ledger close time:
```rust
let now = env.ledger().timestamp();
let safety = Safety {
    severity,
    flags,
    evidence_hash,
    attested_at: now,
};
```

- **Clock Source:** **Stellar ledger consensus timestamp** (`env.ledger().timestamp()`),
  agreed upon by validating nodes during ledger close (~5 seconds per close). It is
  independent of off-chain machine clocks, timezone configurations, or local clock
  drift.
- **Precision:** Unix epoch timestamp in seconds (`u64`).
- **Use:** On-chain gating, staleness detection, and indexer event tracking.

---

## 2. Which Timestamp is Authoritative for Freshness?

**`Safety.attested_at` is the authoritative timestamp for all on-chain freshness decisions.**

A Soroban smart contract executing on-chain has no network stack, cannot verify
off-chain wall clocks, and cannot inspect when individual HTTP calls completed.
The only trustworthy time primitive accessible to smart contracts is the consensus
ledger close timestamp.

When consumer contracts gate on freshness using `is_safe` or `is_safe_masked`:
```rust
if max_age_secs > 0 {
    let now = env.ledger().timestamp();
    if now.saturating_sub(safety.attested_at) > max_age_secs {
        return false; // Stale attestation: fail closed
    }
}
```
The comparison is strictly between the current ledger timestamp and
`safety.attested_at`.

### Off-Chain vs. On-Chain Authority

| Context | Authoritative Timestamp | Decision / Action |
| --- | --- | --- |
| **On-chain contract gates** | `Safety.attested_at` | Enforcing `max_age_secs` during atomic execution (`is_safe`, `is_safe_masked`). |
| **Attester re-scan scheduling** | `Safety.attested_at` | Determining when an asset is due for a scheduled or event-driven re-scan (see [freshness.md](freshness.md)). |
| **Scanner cache invalidation** | `Report.ScannedAt` | Deciding whether a cached scan report is fresh enough to serve via API. |
| **Temporal transition detection** | `Evidence.RetrievedAt` | Comparing observations between scans to determine if upstream evidence changed. |

---

## 3. Representation of Absent Retrieval Times

Assay follows a strict fail-closed discipline: **"we could not check" and "clean"
must never render the same.**

If a third-party source is unreachable, down, or returns an error, there is no
successful observation. Assay handles this absence explicitly:

1. **Never Represented as Zero:** An absent retrieval time is **never** represented
   as `time.Time{}` (the Go zero value), `0`, or Unix epoch `1970-01-01T00:00:00Z`.
   A zero timestamp could silently underflow age calculations, appear as an ancient
   observation, or fail JSON round-trip validations.
2. **Explicit Failure Attribution in `Evidence`:**
   When a fetch fails, `Evidence.RetrievedAt` records the timestamp when the
   fetch was **attempted** (`*AttemptedAt`), and the evidence explicitly marks:
   ```go
   Evidence{
       Source:      sourceName,
       URL:         sourceURL,
       Claim:       "not retrievable: " + err.Error(),
       RetrievedAt: attemptedAt,
       Attempted:   true,
   }
   ```
   The `Attempted: true` boolean allows programs to distinguish an attempt from a
   successful claim without string parsing.
3. **Explicit Absence in `Subject`:**
   In `Subject`, an unreached source leaves its data pointer `nil` and its
   `*FetchedAt` unset (zero value), while populating the attempt timestamp
   `*AttemptedAt` and error description `*Err` (e.g. `TomlErr`, `DirectoryErr`,
   `BlockedErr`, `HolderTrustlineErr`).
4. **Undetermined Status:**
   A finding relying on a failed source sets `Finding.Undetermined = true` and
   records the failed check in `Report.UndeterminedChecks`. An undetermined report
   is refused by `attest.FromReport` (`ErrUndetermined`) and cannot be written
   on-chain.

---

## 4. Why Retrieval Timestamps are Excluded from `evidence_hash`

`evidence_hash` commits to **what the sources claimed**, not **when they were asked**.

If fetch timestamps were included in the canonical preimage:
- Every re-scan of an asset whose flags and evidence are completely unchanged
  would produce a different SHA-256 hash.
- An independent verifier re-running the scanner against the ledger would never
  be able to reproduce the on-chain hash.

By hashing only the canonical claims and storing `attested_at` separately on the
ledger, Assay achieves both properties:
1. **Reproducibility:** A verifier can re-scan and prove that the stored
   `evidence_hash` matches the current claims byte-for-byte.
2. **Freshness:** A consumer gate enforces maximum tolerable age using
   `attested_at` against the consensus clock.

---

## 5. Evaluation & Decision: Storing Scan Time On-Chain (`observed_at`)

### Context & Problem Statement

Issue #334 raised whether `Safety` should store the scanner's observation time
(`Report.ScannedAt` / `observed_at: u64`) on-chain alongside `attested_at`.

`attested_at` records the ledger consensus timestamp (`env.ledger().timestamp()`)
when the attestation is written to persistent storage. If attestation writes are
delayed or batched into transactions submitted later, `attested_at` reflects the
time of the write rather than when the external facts were observed by the scanner.
Downstream consumer gates evaluating freshness via `max_age_secs` compute staleness
against `attested_at`, which can overstate how fresh the underlying observation is
by the duration of the write lag.

### Options Evaluated

1. **Adopt `observed_at: u64` in `Safety`:**
   - **Mechanism:** The writer supplies `observed_at: u64` (derived from the
     scanner's whole-second UTC timestamp, `Params.ScannedAt`) in `attest` and
     `Attestation` (for `attest_many`).
   - **Validation:** Enforce invariant `observed_at <= env.ledger().timestamp()`
     at write time (refusing future observation times).
   - **Impact & Trade-offs:**
     - Modifying `Safety` alters the on-chain storage layout and observable ABI
       of `SafetyRegistry` and `assay-gate`.
     - It forces a bump of `INTERFACE_VERSION` from 1 to 2, affecting downstream
       integrators and ABI drift checks.
     - `observed_at` is inherently an off-chain, untrusted claim provided by the
       writer (admin). Unlike `attested_at`, which is consensus-verified by validating
       ledger nodes, `observed_at` cannot be independently checked on-chain beyond
       asserting that it does not lie in the future.
     - A malicious or misconfigured writer could pass `observed_at = env.ledger().timestamp()`
       anyway, meaning on-chain contracts cannot truly rely on `observed_at` for
       adversarial protection.

2. **Document the Gap & Maintain `attested_at` as Sole Freshness Authority:**
   - **Mechanism:** Retain the current `Safety` struct layout (`severity`, `flags`,
     `evidence_hash`, `attested_at`).
   - **Freshness Discipline:** Preserve `attested_at` as the single authoritative
     time primitive for on-chain gates.
   - **Auditability via `evidence_hash`:** The off-chain report already contains
     exact whole-second UTC `ScannedAt` and per-source `RetrievedAt` timestamps.
     Anyone can verify the attestation and inspect the lag between `ScannedAt` and
     `attested_at` via `assay verify` or off-chain indexers.
   - **Operational Bound:** Mitigate write lag operationally: the attestation
     pipeline runs scans and submits transactions immediately rather than holding
     stale observations in deep queues.

### Decision

**Assay declines adding `observed_at` to the on-chain `Safety` struct and documents
the gap.**

**Rationale:**
1. **Trust Boundary:** On-chain Soroban contracts cannot independently verify wall-clock
   observation times; `env.ledger().timestamp()` is the only consensus-backed time
   source. Adding an unverified writer-supplied timestamp on-chain increases storage
   footprint and contract complexity without providing trust-minimized security guarantees.
2. **ABI & Schema Stability:** Preserving the existing `Safety { severity, flags, evidence_hash, attested_at }`
   struct avoids breaking changes across the deployed registry, the `assay-gate` crate,
   and third-party protocol integrators.
3. **Auditability:** Reproducibility and audit trails are preserved off-chain:
   `evidence_hash` commits strictly to the canonical claims, `attested_at` binds the
   ledger write, and the full temporal record (`ScannedAt`, `RetrievedAt`) remains
   verifiable against the original signed scan report.

