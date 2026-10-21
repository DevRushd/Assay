# SEP: Asset Safety Attestation Interface

## Preamble

```
SEP: To Be Assigned
Title: Asset Safety Attestation Interface
Author: Promise Olubudo (@Bidex-cmyk)
Status: Draft
Created: 2026-10-20
Updated: 2026-10-20
Version: 0.0.1
Discussion: https://github.com/use-assay/Assay/issues/366
```

This draft is maintained in Assay's repository pending a maintainer decision
on whether to submit it to
[stellar/stellar-protocol](https://github.com/stellar/stellar-protocol)
([#366](https://github.com/use-assay/Assay/issues/366)). Per the SEP process,
no SEP number has been self-assigned; on submission the file would be renamed
`sep_asset_safety_attestation.md`, placed in `ecosystem/`, and a maintainer
would assign the number. Sections follow the official
[SEP template](https://github.com/stellar/stellar-protocol/blob/master/sep-template.md).

The key words MUST, SHOULD, and MAY are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## Simple Summary

Wallets, gates, and protocols on Stellar need to know whether an asset's
issuer can freeze or confiscate a holder's balance, and whether the asset has
been flagged as malicious — before they admit it. This proposal standardises
the interface that answers that question on-chain: a `Safety` record
(severity, a mechanic bitset, an evidence hash, and a timestamp), a
`get_safety` read that returns `None` when no claim stands, fail-closed gate
helpers, and a canonical encoding of the evidence behind an attestation so
that anyone can re-derive and verify the hash independently of who wrote it.
Any attester can produce attestations in this format, and any consumer can
verify them without adopting Assay's scanner.

## Dependencies

No required SEP or CAP dependency to implement the interface. Related
proposals, informative:

- [SEP-0001](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)
  (Stellar Info File) and
  [SEP-0042](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md)
  (Stellar Asset Lists): common evidence sources attesters fetch while
  scanning; they constrain what claims can be made, not the interface.
- [CAP-0035](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md)
  (Clawback): defines the confiscation power one of the bitset's bits and the
  severity floor both describe.
- The interface targets Soroban contracts (the registry is a contract, the
  read is a contract call).

## Motivation

A safety attestation is only worth as many eyes as it can survive. Assay's
registry — `get_safety`, the severity/mechanic bitset, and the
`evidence_hash` preimage — exists today only in Assay's own documentation and
implementation ([contract-interface.md](contract-interface.md)). That makes
three ecosystem problems unsolved:

1. **Independent attesters cannot interoperate.** The multi-attestor design
   ([multi-attestor.md](multi-attestor.md), Scheme C) requires several
   independently operated scanners writing attestations that one consumer
   aggregates. A threshold of attestors is meaningless if each attester
   invents its own record shape, its own bit meanings, and its own hash
   encoding: a consumer could not compare two attestations, and a verifier
   could not check either one against evidence.
2. **Consumers cannot verify what they did not build.** `evidence_hash`
   exists so that trust in an attester is checkable rather than absolute —
   anyone can re-scan the same evidence and reproduce the digest. That
   property is currently defined by a document inside the producing project;
   without a standalone specification and a language-neutral conformance
   suite, only an Assay reader can follow it.
3. **Assay-specific choices and interoperable choices are entangled.** The
   `assay-evidence-vN` tag names, Assay's check IDs, and Assay's contract
   entrypoint batch sizes sit next to choices any implementation needs —
   the bit positions, the `Option` semantics, the versioned preimage layout.
   A standards-track document is where that separation can be stated once and
   reviewed as a contract with non-adopters.

A SEP is how Stellar standardises exactly this kind of ecosystem interface.

## Abstract

This proposal specifies an asset-safety attestation interface for the Stellar
ecosystem: an on-chain registry record (`Safety`) holding a bounded severity
level, a mechanic bitset describing what an issuer can do to a holder's
balance, a 32-byte `evidence_hash` committing to the evidence behind the
record, and the ledger timestamp of the write. The interface defines the
read side (`get_safety` returning `Option<Safety>`, so unknown is never
mistaken for safe), fail-closed gate helpers (`is_safe`, `is_safe_masked`)
whose freshness window is the caller's policy, and the write side
(`attest`, `revoke`). `evidence_hash` is SHA-256 over a canonical,
version-tagged, line-oriented, tab-separated preimage with an ABNF grammar,
published conformance cases, and committed vectors, so any implementation in
any language can reproduce byte-identical attestations. The specification
separates what generalises — record shape, bit positions, fail-closed
semantics, the preimage encoding — from what is Assay-specific — tag naming,
check IDs, batch endpoints, storage schema. An extension defines how
independently operated attestors write under their own address and how a
consumer aggregates their attestations with a conservative max/union rule,
leaving its undecided operational parameters to the open-questions list.

## Specification

### Roles and scope

| Role | Description |
| --- | --- |
| **Attester** | An operator that scans an asset off-chain and writes an attestation. Produces the severity, the bitset, and the evidence hash. |
| **Registry** | A Soroban contract that stores attestations and serves reads. It stores; it does not scan — a contract cannot fetch mid-transaction. |
| **Consumer** | A contract or application that reads attestations and decides whether to admit an asset. Chooses its own freshness window and policy. |
| **Verifier** | Anyone who re-derives an `evidence_hash` from evidence and compares it with the stored value, without trusting the attester. |

The scope is the record, the bitset, the read/write interface, the gate
helpers, and the evidence encoding. How an attester derives a severity from
its own observations is attester-side judgment and is deliberately not
standardised: two honest attesters may classify an asset differently, and
the aggregation rule below (not agreement on method) is what consumers rely
on.

### The `Safety` record

```rust
pub struct Safety {
    pub severity: u32,             // 0..=4
    pub flags: u32,                // mechanic bitset
    pub evidence_hash: BytesN<32>, // sha256 of the evidence preimage
    pub attested_at: u64,          // ledger timestamp of the write
}
```

- `severity` MUST be in `0..=4` (table below). The value `5` (used by Assay
  internally for "flags never read") is not a level; a registry MUST reject
  it at write time rather than store it as an answer.
- `flags` is an unsigned 32-bit bitset whose defined positions are `0..=5`
  (table below).
- `evidence_hash` is exactly 32 bytes: the SHA-256 of the canonical preimage
  defined in [Evidence encoding](#evidence-encoding).
- `attested_at` is the ledger timestamp of the write, not of the scan. The
  scan time is deliberately absent from the record (see
  [Design Rationale](#design-rationale)).

### Severity

Severity is a total order answering *how bad* — what the issuer can do to a
holder, and whether curated sources have flagged it. Values are ABI: they
MUST NOT be renumbered.

| Value | Name | Meaning |
| --- | --- | --- |
| 0 | `clear` | No capability known: the issuer cannot act on a holder's balance, and no escalation applies. |
| 1 | `low` | Gate entry: the issuer decides who may hold the asset (`auth_required`). |
| 2 | `medium` | Freeze: the issuer can make a holder's balance unusable (`auth_revocable`). |
| 3 | `high` | Confiscate: the issuer can take a holder's balance without their signature (`auth_clawback_enabled`). |
| 4 | `critical` | Confirmed malicious: a curated source affirmatively identified the issuer or its domain. Never derived from flags. |

Two invariants are normative for any attester and are enforced a second time
by the registry at write time and by the gate helpers at read time:

1. **Confiscation floor:** if `flags & (1 << 2)` (clawback) is set,
   `severity` MUST be `>= 3`.
2. **Escalation is not a power:** a record raised to `critical` by
   reputation carries **no** capability bits (`bits 0..=2`). Severity is the
   axis that carries escalation; the bitset carries powers.

### The flags bitset

Bits are ABI: they MUST NOT be renumbered or moved. Positions `0..=5` are
defined by this specification; positions `6..=31` are undefined here and
have no interoperable meaning (see
[generalising vs Assay-specific](#what-generalises-what-is-assay-specific)).

| Bit | Constant | Class | Meaning |
| --- | --- | --- | --- |
| `1 << 0` | `MECH_AUTH_REQUIRED` | power | The issuer decides who may hold the asset. |
| `1 << 1` | `MECH_AUTH_REVOCABLE` | power | The issuer can freeze a holder's balance. |
| `1 << 2` | `MECH_CLAWBACK_ENABLED` | power | The issuer can confiscate a holder's balance. |
| `1 << 3` | `MECH_FLAGS_LOCKED` | report | The flag set can never change again (`auth_immutable`). |
| `1 << 4` | `MECH_DOMAIN_UNVERIFIED` | report | Reciprocal SEP-1 verification of the issuer's home domain failed. |
| `1 << 5` | `MECH_BLOCKLISTED` | report | A curated source flagged the issuer. |

- **Powers (bits 0–2)** describe what the issuer *can do* to a balance.
  `CAPABILITY_MASK = (1<<0) | (1<<1) | (1<<2)`.
- **Reports (bits 3–5)** describe observed or stated facts, not powers.
  Reputation escalation lives entirely on this side.
- `CONFISCATION_MASK = (1<<2)`; a record carrying it MUST have
  `severity >= 3`.

The two classes are not redundant, and consumers MUST check both axes: a
mask over capability bits cannot see an escalation (the `48 & 6 == 0` case —
a known-bad asset with no capabilities), and a severity ceiling cannot tell
a freeze from a confiscation.

### Registry reads

```rust
pub fn get_safety(env: Env, asset: Address) -> Option<Safety>;
pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
pub fn is_safe_masked(env: Env, asset: Address, forbidden_mask: u32, max_age_secs: u64) -> bool;
pub fn version(env: Env) -> u32;
```

- An asset is identified by its **Stellar Asset Contract address**
  (`Address`), not a code+issuer pair.
- `get_safety` MUST return `None` whenever no attestation stands — never
  attested and revoked MUST be indistinguishable, and MUST be distinct from
  an attestation of `clear`. Collapsing `None` into `clear` would make every
  asset nobody has scanned read as safe: the single worst failure this
  interface permits. An archived (TTL-expired) entry is restored on read with
  its original `attested_at`, not treated as absent.
- `is_safe` returns `true` only when an attestation exists, is within
  `max_age_secs` of `attested_at`, has `severity <= max_severity`, and
  satisfies the confiscation-floor invariant; every other path returns
  `false`. `max_age_secs = 0` explicitly opts out of the freshness check.
- `is_safe_masked` is the same test against `forbidden_mask & flags == 0`
  instead of a severity ceiling. An empty forbidden mask (`0`) MUST still
  require a fresh attestation to exist.
- Both helpers fail closed: the safe answer is the default, so a caller that
  gets its arguments wrong blocks rather than admits.
- Freshness is the **caller's** policy: `attested_at` is exposed and
  `max_age_secs` is a parameter, not a contract constant. A DEX listing gate
  and a large settlement window legitimately differ.
- `version()` returns an interface version, bumped by exactly one on every
  breaking change to this specification's shapes or signatures; purely
  additive read-only entrypoints do not bump it. (Assay's reference
  implementation is currently at version `1`.)

### Registry writes

```rust
pub fn attest(env: Env, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn revoke(env: Env, asset: Address) -> Result<(), Error>;
```

- `attest` stores the record and MUST validate `severity <= 4` and the
  confiscation-floor invariant, returning typed errors rather than storing a
  record the read side would have to disbelieve.
- `revoke` removes the entry, restoring the never-attested state exactly
  (`None`, all gates fail closed). Revoking an entry that does not exist
  MUST fail loudly rather than report success: a revoke sent to the wrong
  address must not leave a standing claim behind. Overwriting is not
  retraction — a corrected claim is a new `attest`; a withdrawn one is a
  `revoke`.
- **Who may write is not fixed by this specification.** The current Assay
  deployment uses a single admin address; the recommended design
  (multi-attestor Scheme C) keys storage by `(attestor, asset)` and
  authorizes each attestor's own write. See
  [Open Questions](#open-questions).

### Independent attestors (proposed extension)

Standardising independent attestors is this SEP's motivation, so the
extension shape is recorded here even though its operational parameters are
undecided. In this model the registry has no admin for attestations; storage
is keyed by `(attestor, asset)`; each attestor writes only under its own
address; the **consumer** names the attestors it trusts and the threshold it
requires, per call.

```rust
// Sketch: the interface, not a frozen ABI.
pub fn attest(env: Env, attestor: Address, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn revoke(env: Env, attestor: Address, asset: Address) -> Result<(), Error>;
pub fn get_attestation(env: Env, attestor: Address, asset: Address) -> Option<Safety>;
pub fn quorum(env: Env, asset: Address, attestors: Vec<Address>, threshold: u32, max_age_secs: u64) -> Quorum;
pub fn is_safe_quorum(env: Env, asset: Address, attestors: Vec<Address>, threshold: u32, max_severity: u32, max_age_secs: u64) -> bool;

pub enum Quorum {
    Met(Safety),        // at least `threshold` responding; conservative result
    Unavailable(u32),   // fewer than `threshold` responding: an outage
    Contested(u32),     // `threshold` or more responding, but they differ
}
```

Normative rules for this extension:

- **Aggregation is conservative max/union.** Require at least `threshold`
  *responding* attestors (fresh within the caller's `max_age_secs`). The
  result takes the **highest** severity and the **union** of flags among all
  responding attestors. `Contested` is reported when responders differ,
  alongside the conservative result. Strict M-exactly-agree aggregation MUST
  NOT be offered: it lets a coordinated minority of `threshold` attesters
  lower the effective answer below what honest responders said, which
  violates the property the whole scheme exists for.
- **Three states stay distinguishable:** `Met`, `Unavailable` (a liveness
  problem — wait), `Contested` (a claim problem — investigate). Both
  non-`Met` states fail closed; collapsing them into one `false` hides an
  attack behind what looks like an outage.
- **Agreement** is equality of `severity` and `flags`. `evidence_hash` is
  excluded from agreement: independent scanners should reproduce it, but
  hashes are still stored per attestor so a verifier can check each one.
- The attestor list MUST be deduplicated before counting (a consumer listing
  one attestor `threshold` times would otherwise quorate on one), MUST be
  bounded for a predictable read budget, and `threshold == 0` or
  `threshold > attestors.len()` MUST be rejected.
- **Security property:** no single compromised attestor can cause an
  admission while any honest attestor in the set is responding — the maximum
  wins. Forcing an admission requires `threshold` compromised attestors
  *and* every honest attestor non-responding in the window.

### Evidence encoding

`evidence_hash` is what makes an attestation checkable rather than trusted:
SHA-256 over a canonical rendering of the report the attester produced. The
encoding is line-oriented, tab-separated, LF-terminated UTF-8. The first
line is a version tag, and **each tag names exactly one layout**: the tag
alone says which lines follow and in what order.

```
assay-evidence-v1
asset	CODE-ISSUER
severity	N
base_severity	N
escalated	true|false
mechanics	N
accountability	unknown|unverified|verified
evidence	SOURCE	URL	CLAIM
```

That is the complete v1 layout: **no `checks` line, not even an empty one**.
The bindings are cumulative:

| Tag | Lines after the version line, before the evidence lines | Report bindings |
| --- | --- | --- |
| `assay-evidence-v1` | `asset` … `accountability` | none |
| `assay-evidence-v2` | `asset` … `accountability`, `checks` | check set |
| `assay-evidence-v3` | `asset` … `accountability`, `checks`, `network` | check set, network |
| `assay-evidence-v4` | `scanner`, `asset` … `accountability`, `checks`, `network` | check set, network, scanner |

```
checks	ID,ID,...        (v2+: the checks the engine ran, sorted, never empty)
network	PASSPHRASE      (v3+: the ledger the facts were read from)
scanner	VERSION         (v4: immediately after the version line)
```

Rules:

- **One tag, one layout.** A report whose bindings match no tag MUST be
  refused, never rendered under the nearest tag. A report with a network but
  no check set has no encoding; a `scanner` line under any tag but `v4` is
  invalid.
- `PASSPHRASE` is the full network passphrase (e.g.
  `Public Global Stellar Network ; September 2015`), not a short name. An
  undeterminable network MUST be an error, never a default.
- `checks` is the sorted set of check IDs the scan ran, never empty under
  v2+. The set is attester-defined; the *binding* is what is standardised:
  a scan run with a check removed must not hash like one where it ran.
- `scanner` is the identity of the producing scanner, escaped like every
  other field.
- **Escaping** (load-bearing, not tidy): inside any field, `\` becomes
  `\\`, tab becomes `\t`, newline becomes `\n`, carriage return becomes
  `\r`. Without it, a third-party string (a directory name, a domain claim)
  could contain a tab and forge the preimage of a report that was never
  produced.
- **Evidence lines are sorted bytewise** across the rendered lines (including
  the `evidence` key and separators), so reordering claims does not move the
  hash.
- **Retrieval timestamps are excluded.** Hashing them would give unchanged
  evidence a different hash on every scan and make the digest unverifiable
  by anyone who was not present for the fetch. Freshness is carried by
  `attested_at` instead, under the caller's `max_age_secs`.
- **Undetermined reports are excluded.** A report whose sources were
  unreachable makes no capability statement and MUST NOT be attested; an
  implementation MUST refuse to produce an `evidence_hash` for one, and a
  verifier MUST never compare the hash of a report carrying
  `undetermined: true`. Degraded fetches remain visible through
  `not retrievable: …` evidence claims, which are hashed like any other.
- Severity and mechanics render as **decimal integers of their bit values**,
  not as names.
- The version line is inside the hash, so a future encoding change cannot
  produce bytes a verifier would silently compare against an old tag.

#### Formal grammar (ABNF)

The grammar below is normative, written per
[RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) over bytes (LF-terminated
UTF-8 lines, HTAB-separated fields), and describes exactly what the
reference encoder emits.

```abnf
; Canonical evidence preimage. Byte-oriented: the ranges below are bytes,
; so a multi-byte UTF-8 sequence passes through as its constituent bytes.
; Literal strings are case-sensitive.

preimage        = v1-preimage / v2-preimage / v3-preimage / v4-preimage

; One layout per tag. The bindings are cumulative: checks, then
; network, then scanner. No other combination has a tag.
v1-preimage     = "assay-evidence-v1" LF field-lines *evidence-line
v2-preimage     = "assay-evidence-v2" LF field-lines checks-line *evidence-line
v3-preimage     = "assay-evidence-v3" LF field-lines checks-line network-line
                  *evidence-line
v4-preimage     = "assay-evidence-v4" LF scanner-line field-lines checks-line
                  network-line *evidence-line

; The scanner's identity, escaped like every other field.
scanner-line    = "scanner" HTAB escaped-value LF

; v1 is exactly these lines: no checks line, not even an empty one.
field-lines     = asset-line
                  severity-line
                  base-severity-line
                  escalated-line
                  mechanics-line
                  accountability-line

asset-line      = "asset" HTAB escaped-value LF
severity-line   = "severity" HTAB 1*DIGIT LF
base-severity-line = "base_severity" HTAB 1*DIGIT LF
escalated-line  = "escalated" HTAB ("true" / "false") LF
mechanics-line  = "mechanics" HTAB 1*DIGIT LF
accountability-line = "accountability" HTAB accountability LF
accountability  = "unknown" / "unverified" / "verified"

; The bound check set, sorted. Never empty: a report with no check set is v1.
checks-line     = "checks" HTAB check-list LF
check-list      = check-id *("," check-id)
check-id        = 1*(ALPHA / DIGIT / "-" / "_")

network-line    = "network" HTAB escaped-value LF

; One line per attributed claim. Constraint outside the grammar: the
; evidence lines are sorted bytewise across the RENDERED lines (including
; the "evidence" key and separators), so reordering checks or claims does
; not move the hash.
evidence-line   = "evidence" HTAB escaped-value HTAB escaped-value HTAB escaped-value LF

escaped-value   = *(safe-char / escaped)
escaped         = %x5C.5C          ; \\ — a literal backslash
                / %x5C.74          ; \t — HTAB
                / %x5C.6E          ; \n — LF
                / %x5C.72          ; \r — CR
safe-char       = %x00-09 / %x0B-0C / %x0E-5B / %x5D-FF
                  ; every byte except HTAB (09), LF (0A), CR (0D),
                  ; and backslash (5C) — the four escaping covers
```

#### Conformance

An implementation MUST be able to validate itself without reading any other
implementation's source. The reference material shipped with Assay is
language-neutral for exactly this purpose:

- [`conformance/cases.json`](../conformance/cases.json) — one JSON object per
  case: the grammar rules it covers, an input report, the expected preimage
  bytes (JSON-escaped), and the expected digest. Any language can replay the
  cases and compare byte-for-byte, then check `SHA-256(preimage) == digest`.
- [`internal/attest/testdata/vectors/`](../internal/attest/testdata/vectors)
  — committed `.preimage`/`.digest` pairs per version tag, three of which
  equal live on-chain `evidence_hash` values. Vectors are the reference an
  encoder is checked against; they MUST NOT be regenerated from an encoder
  that disagrees.
- The suite's coverage rule: every grammar rule above has a case that
  declares it in `covers`, so a rule cannot exist only in prose.

## What generalises, what is Assay-specific

The issue this draft answers is precisely this separation. Normative for the
interface (generalises): everything in [Specification](#specification)
except where this table says otherwise.

| Element | Status | Notes |
| --- | --- | --- |
| `Safety` record shape; `Option`/`None` semantics | **Generalises** | Any registry serving attestations needs unknown-distinguishable-from-clear. |
| Severity domain 0–4 and its ordinal meaning | **Generalises** | How a level is *derived* from observations is attester-side judgment, not standardised. |
| Mechanic bits 0–5, `CAPABILITY_MASK`, `CONFISCATION_MASK` | **Generalises** | Frozen ABI; the power/report split is what makes masks and ceilings each checkable. |
| Confiscation floor; escalation-carries-no-power | **Generalises** | Enforced at write and read; the security argument for severity gating rests on both. |
| Fail-closed `is_safe` / `is_safe_masked`; caller-owned `max_age_secs` | **Generalises** | Freshness tolerance is a property of the consumer, not the network. |
| `evidence_hash` construction: SHA-256, version tag, one-tag-one-layout, escaping, sorted evidence lines, timestamp/undetermined exclusions | **Generalises** | The ABNF and conformance suite are the contract. |
| Version-selection rule (refuse unencodable, never nearest-tag) | **Generalises** | |
| Conservative max/union aggregation; Met/Unavailable/Contested | **Generalises** (extension) | Its operational parameters remain open (below). |
| `attested_at` = ledger write time; scan time excluded from record | **Generalises** | |
| `assay-evidence-vN` tag strings | **Assay-specific** | The *mechanism* generalises; the prefix carries Assay's name. See Open Questions. |
| Check IDs bound in `checks` (v2+) | **Assay-specific per attester** | Each attester binds its own set; a verifier compares against the set it expects. |
| Input report JSON shape used by conformance cases | **Assay-specific** | The hashed *bytes* are the interface; the report JSON is one producer's intermediate form. |
| `scanner` = Go module version of the Assay module (`devel` sentinel) | **Assay-specific** | Binding scanner identity generalises; this identity scheme is Assay's. |
| Batch entrypoints (`attest_many`, `get_safety_many`), `MAX_BATCH_SIZE`, admin transfer handshake, error-code numbering, event schema, storage keys | **Assay-specific** | Current reference implementation's plumbing; nothing interoperable depends on them yet. |
| Single-admin write authorization | **Assay-specific, transitional** | Superseded in direction by the independent-attestors extension; the write-authorization model for the standard is open. |
| Per-holder trustline bits (Go report bits 6–7) | **Assay-specific** | Used only in per-holder scans; they are not part of the registry ABI and are never attested by the reference pipeline. Positions 6+ are undefined by this specification. |
| Reference deployment, `assay-gate` crate, `assay` CLI, severity model document | **Assay-specific** | Implementations MAY adopt them; they are not required to interoperate. |

## Design Rationale

- **Store, don't scan.** A contract cannot fetch mid-transaction; the
  half that needs to be on-chain is the atomic read the action is gated on,
  taken against the same ledger state the action lands on. The attestation
  store shape follows from that split, and `evidence_hash` is how the
  off-chain half stays checkable.
- **`Option`, so unknown is not safe.** `None` for never-attested and
  revoked, distinct from an attestation of `clear`. The alternative — a
  `Severity::Unknown = 0` variant — silently makes every unscanned asset
  read as the safest value in the table.
- **Two axes, never merged.** Severity is a total order; policies are not.
  A protocol that can tolerate a freeze but never a confiscation needs the
  bitset, and a gate that trusts only the bitset admits escalation-only
  assets (the `48 & 6 == 0` counter-example, fixed in
  [#26](https://github.com/use-assay/Assay/issues/26)). Both checks exist
  because each one's blind spot is the other's strength.
- **Why timestamps are outside the hash.** Including them would make the
  digest unverifiable after the fact and reward a re-fetch with a different
  answer. The record stores `attested_at` for freshness instead, and the
  caller decides how old is too old — a listing gate and a settlement
  network have very different tolerances.
- **Why undetermined is outside the hash** ([#43](https://github.com/use-assay/Assay/issues/43)):
  an undetermined report is refused before it could be hashed, so the field
  would commit nothing on any preimage a verifier will ever compare; the
  refusal — not the encoding — carries the guarantee.
- **One tag, one layout** ([#270](https://github.com/use-assay/Assay/issues/270)):
  when two independent changes both claimed `v3`, a reimplementer could not
  know which lines to expect. Giving each layout its own tag makes the tag
  self-describing instead of a version number with an amendment history.
  The corollary — v1 must never gain a `checks` line
  ([#269](https://github.com/use-assay/Assay/issues/269)) — is why layouts
  are cumulative rather than edited.
- **Why conservative aggregation for independent attestors.** Danger may be
  raised, never lowered; the max/union rule means `threshold` compromised
  attestors still cannot cause an admission while one honest attestor
  responds. Strict agreement was considered and rejected in
  [multi-attestor.md](multi-attestor.md): a coordinated minority could then
  set the answer, and any single buggy attestor would refuse assets for
  every consumer that names it.
- **Alternative shapes considered.** A consumer-agreed quorum held inside
  the registry (Scheme B) would need a registry-wide freshness policy to
  define agreement, and moves the single trust root to whoever manages the
  attestor set. A threshold-signature admin (Scheme A) needs no interface
  change but cannot express disagreement at all. The interface specified
  here supports the consumer-chosen-set design (Scheme C) because it keeps
  both freshness and trust the caller's decision — the same rule the read
  side already follows.

## Open Questions

Listed for reviewers and for the maintainer decision this draft awaits
(#366). Nothing below is implemented; all of it needs answers before code.

**For this draft:**

1. **Whether to submit this draft to stellar/stellar-protocol, and when.**
   This is the issue's third acceptance criterion and is a maintainer
   decision: adopting the SEP track moves the specification's source of
   truth out of Assay's docs, with the usual review and adoption burden.
2. **Evidence tag namespace.** The `assay-evidence-vN` prefix is Assay's
   name. Should a standard keep these tags (Assay is the existing producer
   of every on-chain attestation), define a neutral prefix, or give other
   attesters their own tag space under a registry of prefixes? All current
   vectors and on-chain hashes are `assay-evidence-v1`.
3. **Write-authorization model for the standard.** The current model is a
   single admin; the recommended direction is attestor-address-keyed writes.
   Does this SEP specify only the record, the read side, and the encoding as
   normative (with writes per implementation), or does it standardise one
   write model?

**Carried from the multi-attestor design (Scheme C), all still open:**

4. The attestor cap, and the measured Soroban read budget at that cap
   (a quorum read touches up to N entries).
5. The migration path from single-attestor `Safety(asset)` storage, and how
   long single-attestor reads remain available.
6. Whether a recommended default attestor set is published at all, and who
   the independent operators would be — a threshold of attestors run by one
   team is a single-admin registry with extra steps.
7. How the revoke event and the `Contested` state reach the attestation
   writer's alerting.

**Ecosystem-level:**

8. Whether the attestation event schema should be standardised so indexers
   can subscribe across registries (today's schema is Assay-specific).
9. What a verifier should do when two attesters' `evidence_hash` values for
   the same asset differ — reproduce both and compare evidence, or treat the
   divergence itself as the signal (agreement already excludes hash equality
   from quorum counting).

## Security Concerns

- **Admission is the only direction that puts funds at risk.** A
  compromised attester (or, under the extension, `threshold` of them) tries
  to cause an admission. The conservative aggregation rule and the
  single-admin interim both aim at one property: no single compromised party
  causes an admission. Denial of service by one party is visible and fails
  closed, which is acceptable; silent admission is not.
- **`None` collapse would be catastrophic, not cosmetic.** Any
  implementation that reads "no attestation" as "not flagged" reintroduces
  the failure this interface exists to prevent. The distinction is
  normative, and the gate helpers' default (`false`) exists so argument
  errors block instead of admit.
- **Common-mode scanner failures.** A threshold of attestors does not catch
  a shared scanner bug; attestors SHOULD operate different machines, keys,
  and ideally different scanner builds. The interface can record this
  requirement only as guidance — a consumer that names ten attestors run by
  one operator has chosen Scheme A with extra steps, and no registry can
  prevent that.
- **Preimage forgery via unescaped fields.** Evidence claims embed
  third-party text. The escaping rules are load-bearing: without them an
  issuer could publish a tab-containing name and forge the preimage of a
  report that was never produced. Implementations MUST apply escaping to
  every field, not only to URLs.
- **Version downgrade.** Before scanner identity was hashed (v4), two
  scanner versions that classified an asset differently produced equally
  valid hashes, so a downgrade to a buggy version was undetectable. The
  version line inside the hash and the `scanner` binding close this;
  implementations MUST NOT treat a missing binding as equivalent to a
  present one when the tag says otherwise.
- **Freshness is not in the hash.** An attestation can verify perfectly and
  be a year stale. This is deliberate (see rationale), which means every
  consumer MUST apply `max_age_secs` itself; a consumer that ignores
  freshness inherits none of this specification's freshness guarantees.
- **Quorum set selection is the consumer's trust root.** Under the
  extension, the registry cannot audit the set a consumer names. The
  consumer's choice of attestors, not the contract, is what a quorum
  inherits its security from.
- **`Contested` vs `Unavailable` must stay distinguishable to observers.**
  Reporting only `false` for both lets an attack present as an outage and
  delay investigation that only the first state warrants.

## Changelog

- `v0.0.1`: Initial draft. Extracts the registry interface, bitset, and
  evidence encoding from Assay's docs, separates what generalises from what
  is Assay-specific, records the independent-attestors extension, and lists
  the open questions. [#366](https://github.com/use-assay/Assay/issues/366)
