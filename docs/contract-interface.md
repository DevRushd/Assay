# `get_safety(asset)`

## API Contract for Scans

The HTTP scan endpoint (`GET /api/v1/scan?asset=CODE-ISSUER`) returns HTTP `200 OK` on successful or degraded scans, accompanied by the `X-Assay-Undetermined` response header (`true` if any source was unreachable, `false` otherwise). API consumers must check this header or the report's `undetermined` field.

The on-chain half of Assay: a Soroban contract another contract can call
atomically, in the same transaction as the action it protects.

Source: [`assay-contracts/contracts/safety-registry`](../assay-contracts/contracts/safety-registry).Deployed to testnet at `CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73`
— see [deployment.md](deployment.md) for addresses, transaction hashes, and the
superseded/old-address record, and [integrating.md](integrating.md) for how to
call it.   

## What it is, honestly

**It is an attestation store, not a scanner.**

A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
issuer's authorization flags mid-transaction. So the contract does not scan. It
stores attestations produced by the off-chain scanner and serves them for atomic
reads.

This is stated plainly rather than hidden behind a reassuring function name,
because a caller is trusting the attester and needs to know that. `evidence_hash`
is what makes that trust checkable: a SHA-256 over the canonical evidence bundle
the scanner fetched, so anyone can verify an attestation corresponds to specific
evidence rather than to a number someone typed.

Attestations are written by `assay attestation`, which derives severity, the
mechanic bitset, and the evidence hash from a live scan, and `make attest`,
which submits them. No path through either lets a hand-written severity reach
the contract. The pipeline that would keep the registry continuously current
is designed (not yet built) in [attestation-writer.md](attestation-writer.md).

## ABI

```rust
// What storage holds, returned by get_safety.
pub struct Safety {
    pub severity: u32,             // 0..=4, capability-only
    pub flags: u32,                // mechanic bitset
    pub evidence_hash: BytesN<32>, // sha256 of the evidence bundle
    pub attested_at: u64,          // ledger timestamp
}

// One element of an attest_many batch: the arguments of attest(), grouped.
pub struct Attestation {
    pub asset: Address,
    pub severity: u32,
    pub flags: u32,
    pub evidence_hash: BytesN<32>,
}

/// The largest batch attest_many and get_safety_many accept. The cap is
/// derived from the live transaction resource limits; see "attest_many" below.
pub const MAX_BATCH_SIZE: u32 = 50;

/// The contract's interface version, bumped on every ABI change. See
/// "Interface versioning" below for the bump rule.
pub const INTERFACE_VERSION: u32 = 2;

pub fn get_safety(env: Env, asset: Address) -> Option<Safety>;
pub fn version(env: Env) -> u32;
pub fn get_safety_many(env: Env, assets: Vec<Address>) -> Result<Vec<Option<Safety>>, Error>;
pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
pub fn is_safe_masked(env: Env, asset: Address, forbidden_mask: u32, max_age_secs: u64) -> bool;
pub fn attest(env: Env, asset: Address, severity: u32, flags: u32, evidence_hash: BytesN<32>) -> Result<(), Error>;
pub fn attest_many(env: Env, attestations: Vec<Attestation>) -> Result<(), Error>;
pub fn revoke(env: Env, asset: Address) -> Result<(), Error>;
pub fn init(env: Env, admin: Address) -> Result<(), Error>;
pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error>;
pub fn accept_admin(env: Env) -> Result<(), Error>;
pub fn cancel_admin_transfer(env: Env) -> Result<(), Error>;
```

The `Vec<Attestation>` argument is confirmed against the built artifact rather
than assumed: `stellar contract info interface` on the compiled wasm publishes
`fn attest_many(env: soroban_sdk::Env, attestations: soroban_sdk::Vec<Attestation>)`
with `Attestation` as a contracttype UDT, so a `Vec` of a `#[contracttype]`
struct is a supported argument type in soroban-sdk 27.

## Interface versioning

`version()` is a read-only entrypoint that returns the contract's interface
version (`INTERFACE_VERSION`), currently `2`. A consumer or a drift script can
call it to ask "what is this contract?" instead of inferring the interface from
a wasm hash.

### The bump rule

`INTERFACE_VERSION` is bumped by exactly one on every ABI change:

- **Bump:** adding, removing, or renaming an entrypoint; changing an
  entrypoint's signature; changing the [`Safety`] or [`Attestation`] shapes;
  changing an error code; changing the event schema.
- **No bump:** purely additive read-only entrypoints that old consumers can
  safely ignore (a new `get_safety_many` does not break an existing
  `get_safety` caller), and documentation-only changes.

Adding `version()` itself establishes version 1: the interface as of that
build is version 1. Version 2 adds `cancel_admin_transfer` and the
`cancel_admin` event. The constant is an ABI value and is parsed by the Go ABI
drift test, so it cannot drift from the deployed interface without a red build.

| Error | Code | Returned by |
| --- | --- | --- |
| `AlreadyInitialized` | 1 | `init` on an initialized contract |
| `NotInitialized` | 2 | `attest`, `attest_many`, `revoke`, `transfer_admin`, `cancel_admin_transfer` before `init` |
| `InvalidSeverity` | 3 | `attest`, `attest_many` with severity above 4 |
| `InconsistentAttestation` | 4 | `attest`, `attest_many` with the clawback bit below `SEVERITY_HIGH` |
| `NotAttested` | 5 | `revoke` for an asset with no attestation |
| `NoPendingAdmin` | 6 | `accept_admin` or `cancel_admin_transfer` with no pending transfer |
| `BatchTooLarge` | 7 | `attest_many` with more than `MAX_BATCH_SIZE` elements |

### `attest_many`: many attestations in one transaction

`attest_many(attestations)` is `attest`, repeated. One transaction writes up to
`MAX_BATCH_SIZE` attestations, which is what lets a re-attestation run cover a
useful set of assets instead of one asset per ledger and per fee.

Every element is written exactly as `attest` writes it — the same
`DataKey::Safety(asset)` key, the same stored `Safety`, the same `Attested`
event — and both entrypoints call the same validation function. A batch is
**not** a lower bar:

- `InvalidSeverity` and `InconsistentAttestation` are the same checks, on every
  element. There is no batch path around the confiscation invariant.
- `require_auth` on the admin is required, as for `attest`. An empty batch is
  authorized too: who may call an entrypoint is a property of the entrypoint,
  not of what it was handed.
- Per-asset reads after a batch are identical to per-asset reads after the
  equivalent single writes. The contract test
  `batch_reads_match_single_write_path` asserts the stored value is equal, not
  merely equivalent.

#### All-or-nothing, not partial

**A batch is applied whole or not at all.** Every element is validated before
the first write, so a batch containing one bad element stores nothing, publishes
nothing, and returns the same typed error the single-write path returns for that
element. There is no state in which some assets of a batch were re-attested and
others silently were not, and the tail is never truncated to make a partly-bad
batch fit.

This is stronger than the host gives for free, and the extra is worth stating
precisely rather than overclaiming. Soroban already rolls the whole transaction
back on failure, so a batch could not half-commit even with a write-as-you-go
loop. What validating up front adds is (a) a failure that is *typed and
deterministic* — an error a caller can branch on, rather than a resource failure
from whichever write happened to be in flight — and (b) a failure that is cheap,
because a batch whose last element is bad does not first pay to write every
element before it.

#### The cap, and why it is 50

The bound is a network limit, not a round number. Read live on 2026-09-27 with
`stellar network settings --network testnet` (protocol 28), and measured against
the same enforcement the SDK applies in the tests:

| Limit | Live network | A full 50-element batch | Used |
| --- | --- | --- | --- |
| **contract event bytes** | **16 384** | **10 000** | **61% — the binding limit** |
| ledger entries written | 200 | 51 | 26% |
| transaction footprint entries | 400 | 105 | 26% |
| bytes written | 132 096 | 14 072 | 11% |
| instructions | 400 000 000 | 3 275 513 | 0.8% |
| memory | 41 943 040 | 514 609 | 1.2% |

Each element publishes its own `Attested` event and one such event is exactly
200 bytes, so the event budget admits **at most 81 elements** however frugal the
writes are. That is the hard ceiling: a 100-element batch was measured failing
with `contract events size bytes: 20000 > 16384`. 50 sits at 61% of that
budget — room for the event schema to grow before the cap becomes wrong — and
costs about a quarter of every other limit, including the write budget one would
naturally have guessed was binding.

Per-asset events are kept rather than collapsed into one batch-sized event for
precisely this reason. A single event would raise the ceiling, but it would
take away the property that an indexer subscribed to `("attest", asset)` sees
every write to that asset without decoding batch bodies. A higher cap is worth
less than that.

`batch_size_bound_is_measured_and_holds_headroom` in the contract tests runs a
full batch with the SDK's mainnet resource enforcement switched on (which
`Env::default` enables), asserts it fits every limit, and pins the 200-byte
per-event cost so the cap is re-derived rather than silently wrong if the event
or the write path changes.

#### Empty batches, and one timestamp per batch

An empty batch succeeds and does nothing: no storage write, no event, and no
instance TTL extension. That is the honest reading of all-or-nothing over zero
elements, and it lets a pipeline pass whatever a scan produced without
special-casing "nothing changed this round".

Every element of one batch carries the same `attested_at`: the timestamp of the
ledger the batch landed in. `attested_at` records when the write happened, not
when each scan ran, and the elements of one call were written at the same
instant. If the same asset appears twice in a batch, both are applied in order
and both events are published, with the second write winning — exactly what two
calls to `attest` would have done.

### `get_safety_many`: bounded batch read

`get_safety_many(assets)` returns one `Option<Safety>` per asset, in the same
order the assets were given, for up to [`MAX_BATCH_SIZE`] assets in one call.
An asset that was never attested, or whose attestation was revoked, reads as
`None`; a missing asset never fails the whole call.

#### Bound

At most [`MAX_BATCH_SIZE`] assets are accepted; a longer vector returns
[`Error::BatchTooLarge`] and reads nothing. A batch read larger than the cap is
an error rather than a truncation on purpose: a caller that asked for N answers
and got fewer would not know which assets went unread.

The bound mirrors `attest_many`'s so one number governs both directions of the
batch, and the read cost at the bound is pinned by
`get_safety_many_cost_at_the_bound`.

#### Never error the whole call because one asset is missing

Within the bound, `get_safety_many` never returns an error: unattested and
revoked assets read as `None`, and the caller learns per-asset which assets have
no standing claim. This keeps a consumer that gates several collateral assets
from failing entirely because one of them was never scanned.

### `revoke`: withdrawing an attestation

`revoke(asset)` removes the stored attestation, which restores the
never-attested state exactly: `get_safety` returns `None`, and `is_safe` and
`is_safe_masked` return `false` whatever arguments they get. It requires the
admin's authorization, as `attest` does.

It exists because overwriting is not a retraction. If an attestation turns out
to be wrong (a scanner bug, a compromised key, evidence that does not support
it), writing a higher severity over it makes a *new* claim the scanner never
reached. Revoking says only that the old claim no longer stands, and it leaves
every gate failing closed until a correct attestation is written.

- **Admin, existing attestation:** removed; a `revoke` event is published.
- **Non-admin caller:** rejected by `require_auth`, as `attest` is. Nothing
  changes.
- **No attestation for the asset:** returns `NotAttested`, changes nothing, and
  publishes nothing. This is an error rather than a no-op on purpose: a revoke
  sent to the wrong SAC address (easy to do, since addresses are
  network-derived) must fail loudly rather than report success while the
  attestation it was meant to withdraw is still there. A retried revoke also
  gets `NotAttested`, which an operator can read as "already gone".
- **Re-attesting afterwards** works normally. The new attestation carries its
  own `attested_at`.

#### Revoked and never-attested look the same on-chain, deliberately

**A consumer calling `get_safety` cannot tell a revoked asset from one that was
never attested.** Both return `None`. The contract keeps no tombstone.

That is a choice, not something left out:

- Both states mean the same thing to a gate: no claim stands, so fail closed.
  Every correctly written gate already handles `None`, so revocation needs no
  consumer changes.
- A tombstone would be a new stored type and a new read path that every
  integrator would have to understand. It would also be one more persistent
  entry with its own TTL (see [deployment.md](deployment.md#entry-lifetime)),
  and it would archive like any other entry.
- The one party that needs the difference is an off-chain observer, for
  example an indexer that saw the `attest` event and would otherwise go on
  believing it. That party gets the `revoke` event below.

If a future consumer needs to prove on-chain that an asset *was* revoked,
that is a new feature with its own ABI. It is not implied by this one.

#### Migration

The deployed registry (`CBK4FBIH…`) has no upgrade entrypoint, so `revoke` and
the TTL handling cannot be added to it in place. Using them needs a **new
deployment**: a new contract ID, `init`, re-attesting the assets from live
scans, and redeploying the example gate against the new address. The steps are
in [deployment.md](deployment.md#migrating-to-a-registry-with-revoke).
Until that is done, the live testnet registry still has no revoke path.

### Admin transfer: two-step rotation

On any instance built from current source, the admin role can be moved to a new
key **without redeploying**. It is a two-step handshake, so a transfer to an
unowned address or a mistyped key cannot silently hand the registry to a
stranger:

- **`transfer_admin(new_admin)`** — authorized by the **current admin**
  (`require_auth` on the stored admin). It records `new_admin` as the pending
  admin and changes nothing else: the current admin still attests and revokes,
  and a second `transfer_admin` replaces the pending address. It is not a
  transfer until the second step.
- **`accept_admin()`** — authorized by the **pending admin** (`require_auth` on
  the address recorded by `transfer_admin`). It promotes that address to admin,
  clears the pending entry, and completes the transfer. After this the old
  admin can no longer `attest`, `revoke`, or start another transfer.
- **`cancel_admin_transfer()`** — authorized by the **current admin**
  (`require_auth` on the stored admin). It clears the pending entry, leaves the
  current admin in place, and publishes an `AdminTransferCancelled` event. This
  is how a proposal to a wrong or compromised address is withdrawn instead of
  merely overwritten: after cancelling, the old pending address cannot accept,
  because there is no longer a pending admin.

The errors specific to this path are typed rather than silent:

| Call | Condition | Result |
| --- | --- | --- |
| `transfer_admin` | before `init` | `NotInitialized` (2) |
| `transfer_admin` | caller is not the current admin | `require_auth` failure; nothing changes |
| `accept_admin` | no pending transfer | `NoPendingAdmin` (6) |
| `accept_admin` | caller is not the pending admin | `require_auth` failure; nothing changes |
| `cancel_admin_transfer` | before `init` | `NotInitialized` (2) |
| `cancel_admin_transfer` | caller is not the current admin | `require_auth` failure; nothing changes |
| `cancel_admin_transfer` | no pending transfer | `NoPendingAdmin` (6) |

`transfer_admin` and `accept_admin` do not publish events, so those steps are
not visible in the `attest`/`revoke` event stream; the new admin's first write
is the first on-chain trace. `cancel_admin_transfer` publishes one
`AdminTransferCancelled` event (see "Attestation events" below) so a withdrawn
handover is observable. A transfer or cancellation moves the admin role only —
the stored attestations are untouched and `get_safety` keeps serving them.

**The live testnet deployment predates all three entrypoints.**
`CBK4FBIH…` was deployed on 2026-08-15, before `transfer_admin`,
`accept_admin`, and `cancel_admin_transfer` existed, and it has no upgrade
entrypoint to receive them. Calling any of them against the live contract fails
as an unknown entrypoint, and rotating the live admin still means a new deployment
and re-attestation — see
[deployment.md](deployment.md#admin-transfer-and-rotation) and
[attester-key.md](attester-key.md#rotation).

### Named policy masks for `is_safe_masked`

`is_safe_masked` gates on **which mechanics** are unacceptable rather than on a
severity ceiling. Severity is a total order; real policies are not — a
protocol that can tolerate a freeze but never a confiscation would otherwise
have to gate on `severity <= MEDIUM`, which also excludes `auth_required`
assets it may be perfectly happy with.

Two named masks are published as the two common policies; a caller may pass
any `u32`.

| Mask | Bits | When to use |
| --- | --- | --- |
| `POLICY_MASK_CONFISCATION_ONLY` | `MECH_CLAWBACK_ENABLED` | You accept freeze-capable assets but never confiscation-capable ones. |
| `POLICY_MASK_FREEZE_INCLUSIVE` | `MECH_AUTH_REVOCABLE \| MECH_CLAWBACK_ENABLED` | A custody product refusing anything the issuer can act on. |

`is_safe_masked` fails closed on every non-happy path, exactly like `is_safe`:
never-attested, stale, and any forbidden bit set all return `false`. An empty
`forbidden_mask` (`0`) still requires an attestation — an unattested asset
must never read as safe, even for a policy that forbids nothing.

### Attestation events

Every successful `attest` publishes one Soroban event so indexers do not have
to poll storage. Rejected calls (`InvalidSeverity`, `InconsistentAttestation`,
unauthorized) publish nothing: observers must never see a write that did not
happen.

| Topic 0 | Topic 1 | Data |
| --- | --- | --- |
| `symbol_short!("attest")` | asset `Address` | `Map<Symbol, Val>` with keys `severity: u32`, `flags: u32`, `attested_at: u64` |
| `symbol_short!("revoke")` | asset `Address` | `Map<Symbol, Val>` with key `revoked_at: u64` |
| `Symbol::new(env, "cancel_admin")` | pending admin `Address` | `Map<Symbol, Val>` with key `cancelled_at: u64` |

`attest_many` publishes one such `attest` event per element, in batch order,
with no batch-specific event or decoding path. A rejected batch publishes
nothing at all.

A successful `revoke` publishes the second row. A failed revoke (`NotAttested`,
unauthorized) publishes nothing. The `revoke` event uses the same topic layout
as `attest`, so an indexer subscribed by asset sees both the write and its
withdrawal.

A successful `cancel_admin_transfer` publishes the third row. A rejected cancel
(`NoPendingAdmin`, unauthorized) publishes nothing. The pending address is a
topic so an indexer can filter for the withdrawn proposal without decoding the
data map.

The events are defined with the `#[contractevent]` macro on the `Attested`,
`Revoked`, and `AdminTransferCancelled` structs
in the contract (see `assay-contracts/contracts/safety-registry/src/lib.rs`),
so the schema is discoverable from the contract spec rather than only from
this document.

The asset address is a topic rather than a data-map field so an indexer can
subscribe by asset without decoding every event body. The topic count is two,
well within the SDK's four-topic limit, and `Symbol` is the required
topic-0 shape for a filterable label.

Severity values and mechanic bit positions are **ABI** and mirror
`internal/mechanics` exactly. Do not renumber them.

| Severity | | Mechanic bit | |
| --- | --- | --- | --- |
| 0 | `SEVERITY_CLEAR` | `1 << 0` | `MECH_AUTH_REQUIRED` |
| 1 | `SEVERITY_LOW` | `1 << 1` | `MECH_AUTH_REVOCABLE` |
| 2 | `SEVERITY_MEDIUM` | `1 << 2` | `MECH_CLAWBACK_ENABLED` |
| 3 | `SEVERITY_HIGH` | `1 << 3` | `MECH_FLAGS_LOCKED` |
| 4 | `SEVERITY_CRITICAL` | `1 << 4` | `MECH_DOMAIN_UNVERIFIED` |
| | | `1 << 5` | `MECH_BLOCKLISTED` |

`CONFISCATION_MASK = MECH_CLAWBACK_ENABLED`. Anything matching it has
`severity >= SEVERITY_HIGH`, enforced at write time and re-checked at read time.

One more value exists on the Go side and **never reaches the chain**:
`mechanics.Unevaluated` (5) marks a report whose issuer flags were never read,
so no capability statement exists at all. `attest.FromReport` refuses it with
`ErrUnevaluated`, and the contract would reject it as `InvalidSeverity` anyway.
The 0..4 table above is the complete on-chain ABI and is unchanged by this
value's existence; it is there so that an unread flag can never be serialized
as `SEVERITY_CLEAR`, the safest value in the table.

## Design decisions

### Assets are SAC addresses

An asset is identified by its Stellar Asset Contract address, not by a
code+issuer string pair. Verified live on Horizon (first recorded 2026-08-11,
re-checked 2026-09-17): Circle's USDC has a canonical
`contract_id` of `CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75`.
`Address` comparison is cheap on-chain; string handling is not.

### `Option`, so unknown is not safe

`get_safety` returns `Option<Safety>`. A never-attested asset returns `None`,
which stays distinguishable from an attestation of `SEVERITY_CLEAR`. A revoked
asset also returns `None` (see [`revoke`](#revoke-withdrawing-an-attestation)).
An **archived** attestation does not: it is restored on access and read with
its original `attested_at` (see [deployment.md](deployment.md#entry-lifetime)).

Collapsing those two would make every asset nobody has scanned read as safe —
the single worst failure this contract could have, and the default a
`Severity::Unknown = 0` variant would have quietly produced.

### `is_safe` fails closed

The gate helper returns `true` only when an attestation exists, is fresh enough,
and is at or below `max_severity`. Every other path returns `false`: never
attested, stale, too severe, or internally inconsistent.

The safe answer is the default, so a caller who gets the arguments wrong blocks
rather than admits.

### A gate reads both severity and the bitset

A gate that copies this example has to check **both** axes. They are not
redundant, and the reader who takes one for the other is looking at the bug
that shipped in the example gate.

Severity is a total order and answers *how bad*; the bitset answers *which
power*. Reputation escalation raises `severity` and sets `blocklisted` and must
never set a capability bit — capability bits describe what the issuer *can do*,
and a scam listing is not a capability. So a mask over capability bits cannot
see escalation, by construction, and a severity ceiling cannot tell a freeze
from a confiscation.

`DOGE-GA22IDJNHUMC3XKUCCBFNTQIJOUBWINC5GCXHLJ2V6KZ3OWAXCULNQ7P` (the DOGE
fixture in the eval corpus) is the concrete counter-example. It is attested at
severity `4` (`SEVERITY_CRITICAL`) with flags `48`
(`domain_unverified | blocklisted`) and **no capability bits at all**, because
its issuer genuinely cannot freeze or confiscate. A gate masking only on
`MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED` (`6`) computes `48 & 6 == 0` and
admits a known scam. Only the severity ceiling refuses it.

The numbers are spelled out because the failure is easy to describe and easy to
miss: `48 & 6 == 0` is exactly zero, and a gate reading a truthful bitset is
satisfied by it. [integrating.md](integrating.md) works the same case through
both checks, and the example gate carries the note next to `MAX_SEVERITY`. The
history of the fix is
[#26](https://github.com/use-assay/Assay/issues/26).

### Staleness is the caller's policy

`attested_at` is exposed and `max_age_secs` is a parameter rather than a
contract constant. Assay does not silently serve stale safety, and it does not
guess how fresh is fresh enough — a DEX listing gate and a large settlement
have very different tolerances. `max_age_secs = 0` opts out explicitly.
`attested_at` is the authoritative timestamp for on-chain freshness decisions
(see [timestamps.md](timestamps.md)); recommended bands with reasoning, the
re-attestation cadence, and consumer guidance are in [freshness.md](freshness.md).

[freshness.md](freshness.md) is the guidance for picking a value: what changes
under an attestation, how fast (measured, not guessed), and defensible windows
per use class.

### The invariant is enforced twice

`attest` rejects an attestation whose clawback bit is set below `SEVERITY_HIGH`.
`is_safe` re-checks it anyway. A gate should not have to assume the writer was
correct.

### Revocation removes the entry

`revoke` withdraws an attestation. It is the admin-only counterpart to `attest`:
after it, `get_safety` returns `None` and both gate helpers fail closed. Until
now the only remedy for a wrong attestation was to overwrite it, which asserts a
new claim rather than retracting one; revocation retracts.

**Revoking an asset with no live attestation returns `Error::NotAttested`.** It
is not a silent no-op: an operator who revokes twice, or revokes something that
was never attested, learns the entry was already absent rather than getting a
false success.

**Revoked and never-attested are deliberately indistinguishable.** `revoke`
deletes the key and keeps no tombstone, so both states return `None` and both
reject a further `revoke` with `NotAttested`. A consumer cannot tell a withdrawn
claim from one that was never made, and this contract does not pretend
otherwise. Distinguishing them would mean storing a marker, which is the
history/audit question ([#92](https://github.com/use-assay/Assay/issues/92)), not
revocation.

Revocation publishes a `revoke` event; see "Attestation events" above for its
topic layout and the other event schemas.

## Using it

```rust
// Refuse to list an asset whose issuer can freeze or confiscate,
// using an attestation no more than an hour old.
let registry = SafetyRegistryClient::new(&env, &registry_address);
if !registry.is_safe(&asset, &SEVERITY_LOW, &3600) {
    panic_with_error!(&env, MyError::AssetNotSafe);
}
```

Gating on `severity` is sound precisely because severity is capability-only:
the contract is relying on a statement about ledger mechanics, not on a third
party's opinion of an issuer. See [the severity model](severity-model.md).

Gating on the `flags` bitset instead is usually sharper, because a contract
tends to care about a specific power rather than about an ordering.
[integrating.md](integrating.md) works through both, against the live
deployment.

### Which bits are powers and which are reports

The `flags` bitset mixes two kinds of fact, and the boundary between them is
named and exported on both sides (issue #34) so a consumer never has to know
the table by heart:

- **Powers — bits 0–2** — describe what the issuer can do to a holder's
  balance: `MECH_AUTH_REQUIRED` (1<<0, gate entry), `MECH_AUTH_REVOCABLE`
  (1<<1, freeze), `MECH_CLAWBACK_ENABLED` (1<<2, confiscate). They are
  selectable through the exported capability mask: `CAPABILITY_MASK` in
  `assay-contracts/contracts/safety-registry/src/lib.rs`, `CapabilityMask` in
  `internal/mechanics/severity.go`. The ABI drift test fails the build if the
  two sides ever disagree.
- **Reports — bits 3–5** — describe facts someone stated or observed, not
  powers: `MECH_FLAGS_LOCKED` (1<<3, the flag set cannot change again),
  `MECH_DOMAIN_UNVERIFIED` (1<<4, reciprocal SEP-1 verification failed),
  `MECH_BLOCKLISTED` (1<<5, a curated source flagged the issuer). Reputation
  escalation lives entirely on this side of the boundary, which is why a mask
  over the capability bits alone cannot see it — the #26 failure. Severity is
  the axis that carries escalation; the bitset carries the powers.

Bit positions are ABI: the ten on-chain attestations commit to them, and
nothing in this change renumbers or moves a bit — it only names the boundary.

### `evidence_hash` commits to the claims, not to the clock

`evidence_hash` is `SHA-256` over a canonical rendering of the report, produced
by [`internal/attest`](../internal/attest) and printable with
`assay attestation -preimage CODE-ISSUER`. The encoding is line-oriented,
tab-separated, LF-terminated UTF-8. The first line is a version tag, and **each
tag names exactly one layout**: the tag alone says which lines follow and in
what order.

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

That is the complete v1 layout. **A v1 preimage has no `checks` line**, not
even an empty one. Every attestation on chain today was hashed over exactly
these bytes. An encoder that emitted `checks<TAB>` for v1 reports broke every
one of them ([#269](https://github.com/use-assay/Assay/issues/269)), and the
verifier now refuses those bytes as an invalid v1 preimage.

Later encodings add lines in fixed positions. The bindings are cumulative:

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

`PASSPHRASE` is the full Stellar network passphrase, not a short name:
`Public Global Stellar Network ; September 2015` for pubnet, `Test SDF Network
; September 2015` for testnet. The passphrase is the one network identifier the
ecosystem already agrees on, and the value is fixed by the protocol. It is not
configuration.

A report whose bindings are not one of the four rows above (a network without
a check set, or a scanner without both) has no tag. `attest.FromReport` refuses
it with `ErrUnencodable`. No production path produces one: `Engine.Run` binds
the check set, and `scan.Scanner` binds the network and the scanner.

The committed vectors in `internal/attest/testdata/vectors` cover every tag:
the v1 set (including `aqua-`, `usdc-` and `usdz-mainnet-onchain`, whose digests
are the on-chain hashes), `checkset-bound-v2`, the `network-bound-pubnet` /
`network-bound-testnet` pair for v3 (byte-identical except for the network
line, which is the property v3 exists for), and `scanner-network-bound-v4`.

#### One tag, one layout ([#270](https://github.com/use-assay/Assay/issues/270))

Before this decision, `assay-evidence-v3` covered three layouts: scanner only,
network only, and both. Two independent changes (scanner identity, #40; network,
#41) each claimed v3, and a reimplementer reading the tag could not know whether
to expect a `scanner` line. Two fixes were considered:

- *Make every v3 line mandatory.* This keeps one tag, but it forces a single
  combined layout on reports that bind only some of the fields.
- *Give each layout its own tag.* **Chosen.** v3 keeps the layout its committed
  vectors already pin (checks + network), and the scanner layout becomes v4. Any
  combination outside the cumulative chain is refused, not tagged.

The verifier enforces the same table. `assay verify` and `attest.ParsePreimage`
refuse a preimage whose lines do not match its own tag: a `checks` line under
v1, a v3 preimage without `network`, a `scanner` line under any tag but v4.
`TestPreimageVersionIsInjective` enumerates all eight combinations of the three
bindings.

**Migration impact.** None on chain: all ten attestations are v1, and v1 is
unchanged. The committed v3 vectors keep their bytes and digests. Two kinds of
off-chain bytes are no longer producible. A scanner-bound preimage tagged v3
was emitted only by tests, because nothing set the binding (#271). A
network-only v3 preimage with no checks line comes from a report with a
network and no check set, which no production path creates. A verifier
holding either is told the tag and the layout disagree.

#### The preimage binds the scanner identity

The v4 `scanner` line names the code that produced the report (issue #40):

```
scanner	VERSION
```

`VERSION` is the scanner's Go **module version**, the string recorded by
`go version -m` for the `github.com/use-assay/assay` module (e.g. `v1.2.3`), or
the literal `devel` for any build that is not a clean release tag. The value is
taken from `attest.ScannerIdentity` (`internal/attest/attest.go`) and is
escaped once, like every other field: inside any field, `\` becomes `\\`, tab
becomes `\t`, and so on.

**Why the module version and not a build-stamped commit.** A commit stamp
would make every local dev build produce a different hash for identical
evidence, destroying the cross-machine and cross-version reproducibility the
hash exists for. The module version changes exactly when the code changes,
is stable across machines for a given release, and is verifiable by anyone
who can run the module. `devel` is a deliberate sentinel: a hash produced by
an unstamped build is distinguishable from any tagged release rather than
silently pretending to be one. Since Go 1.24, `go build` in a git checkout
stamps a pseudo-version such as `v0.0.0-20261018200841-38b5825719ba`, with
`+dirty` for a modified tree. `internal/version` reports those as `devel` too,
because a pseudo-version *is* a commit stamp.

**Where the binding is switched on
([#271](https://github.com/use-assay/Assay/issues/271)).** In
`scan.Scanner.Scan` and `scan.Scanner.ScanWithHolder`, which set
`Report.ScannerBound` on every report they return. That is the entry point that
performs a live scan, and it already binds the network for the same reason.
`Engine.Run` does not set it, because tests and the eval harness drive it with
fixtures. `attest.FromReport` does not set it either, because it derives
arguments from a report it did not produce and must not add claims to it. Every
`assay scan`, `assay attestation` and API scan is therefore written under v4.
`TestScanBindsTheScanner` in `internal/scan` fails if a `scan.Scanner` report is
not scanner-bound.

This closes the downgrade hole: two scanner versions that classify an asset
differently used to produce equally valid hashes, so a downgrade to a version
with a known bug was undetectable. Under v4 the hashed bytes name their
producer, so the same evidence hashed by different scanner versions cannot
collide.

**Re-deriving an attestation written under an older encoding.** The ten
attestations on chain are v1, and a scan today is v4. To compare the two,
render the fresh scan under the attestation's own encoding:

```sh
assay attestation -raw -preimage-version v1 CODE-ISSUER
```

`-preimage-version` (`attest.PreimageAs` / `attest.FromReportAs`) withholds the
bindings the named encoding predates. It never adds one: asking for v3 from a
report with no network is `ErrUnencodable`. `scripts/reproducibility.sh` passes
each asset's `Preimage` column from [deployment.md](deployment.md) this way. A v1 attestation still reproduces
only if the evidence claims the scanner emits are unchanged, so a code change
that adds or rewords a claim breaks reproduction exactly as a change at the
source would. The ten attestations are NOT re-attested as part of this change.
Re-attestation is a maintainer decision with a signing ceremony, and nothing
here can or should do it silently. A future re-attestation would be written
under v4.

with one `evidence` line per attributed claim, sorted bytewise. Inside any
field, `\` becomes `\\`, tab becomes `\t`, newline `\n`, carriage return `\r`.
That escaping is load-bearing rather than tidy: a claim embeds third-party text
such as a directory name, so without it an issuer could publish a name
containing a tab and forge the preimage of a report that was never produced.

**Retrieval timestamps are deliberately excluded.** Hashing them would give the
same unchanged evidence a different hash on every scan, which would make the
field unverifiable by anyone who was not present for the original fetch.
Excluding them means a verifier can re-scan and reproduce the hash exactly. The
cost is that the hash cannot distinguish a fresh confirmation from a stale one
— which is precisely why `attested_at` is stored separately and `is_safe` takes
`max_age_secs` against it.

**`undetermined` is deliberately excluded, decided in
[#43](https://github.com/use-assay/Assay/issues/43).** The reasoning:

- An undetermined report can never be attested — `attest.FromReport` refuses it
  with `ErrUndetermined` — so the flag is constant (`false`) across every
  report that has a hash at all. A field that never varies commits nothing; it
  would add a line that carries no information in any preimage a verifier will
  ever compare.
- The exclusion is safe only because the refusal exists, so the guarantee rests
  on `FromReport` refusing, not on the encoding. `TestUndeterminedReportIsRefused`
  and `TestCapabilityClearWithReputationDownIsNotAttestable` (both in
  `internal/attest/attest_test.go`) pin that refusal; if it is ever weakened,
  the encoding decision must be revisited, because a hash over attestable
  reports only is sound exactly as long as undetermined reports stay
  unattestable.
- Degraded scans are already visible in the hash through a stronger channel:
  an unreachable source emits a `not retrievable: …` evidence claim, which is
  hashed like any other. Two scans of the same asset, one with a source outage
  and one without, already produce different hashes and different evidence
  sets — there is nothing the flag would add that the evidence lines do not
  already carry. `docs/attestation-run.md` records the corresponding live
  observation: an undetermined KALE report would have hashed differently, and
  the attestation was refused.
- The corollary is a verifier rule, not just an implementation note: **never
  compare the hash of a report carrying `undetermined: true`.** Such a report
  has no evidence_hash — `FromReport` produces none — and an independent
  reimplementer must refuse it the same way.

The version line is inside the hash, so a future encoding change cannot produce
bytes a verifier would silently compare against v1.

#### The preimage binds the check set

`Engine.Run` iterates whatever checks the engine holds, and a report used to
commit only to the aggregate result and the evidence lines. That made a scan run
with a check removed indistinguishable from one where the check ran and found
nothing: DOGE is critical solely through the reputation check, so removing that
check turns it clear, and a two-check engine could produce a report that hashed
like a three-check one whose removed check changed no other field.

The v2 encoding closes that: the sorted check IDs the engine ran are part of the
preimage, so a report from a smaller engine hashes differently. `Report.CheckSet`
carries them, and `attest.VerifyCheckSet` compares a report's bound set against
the set a verifier expects, returning `CheckSetIncomplete` with the absent checks
named — not a generic mismatch. A report with no bound set is
`CheckSetUnknown`, reported as such rather than failed, because there is nothing
to compare.

The check-set binding is a v2 rather than an amendment to v1 deliberately: an
attestation written under v1 omitted the check set entirely, and re-hashing it
under a changed v1 format would break every existing attestation. That is also
why the v1 layout must not carry an empty `checks` line (#269).

### The preimage binds the network

An asset code and issuer can exist on two networks with different flags, and
Assay's attestations are currently written to testnet while scanning pubnet —
so before network binding, a pubnet scan and a testnet scan of the same
identifier produced indistinguishable preimages, and an attestation could not
prove which ledger it describes.

The v3 encoding closes that, and v4 keeps it: the network passphrase is part of
the preimage, so the same facts read from two ledgers hash differently. `scan.Scanner` resolves
the network before any fetch — from the Horizon base URL when it is an
SDF-operated host, cross-checked against an explicit `Network` declaration —
and refuses to scan when neither can name it, or when the two contradict. A
misconfigured attester therefore fails at scan time instead of publishing
pubnet facts under a testnet contract.

An undeterminable network is an error, never a default, for the same reason an
unread flag is `Unevaluated` rather than `Clear`: a guessed network name in a
hashed field is a false attestation waiting to be written.

### Formal grammar (ABNF)

The prose above states the intent; this grammar is the contract. It is
written per [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234) over bytes
(LF-terminated UTF-8 lines, HTAB-separated fields), and it describes exactly
what `attest.Preimage` emits. There is one production per version tag, so the
tag determines the layout. The machine-readable suite in
[`conformance/`](../conformance) pins one or more cases per rule;
`internal/attest/conformance_test.go` runs it in CI and fails if any grammar
rule is uncovered. Any other implementation can run the same cases from the
JSON alone, without reading the Go code.

```abnf
; Canonical evidence preimage. Byte-oriented: the ranges below are bytes,
; so a multi-byte UTF-8 sequence passes through as its constituent bytes.
; Literal strings are case-sensitive.

preimage        = v1-preimage / v2-preimage / v3-preimage / v4-preimage

; One layout per tag (#270). The bindings are cumulative: checks, then
; network, then scanner. No other combination has a tag.
v1-preimage     = "assay-evidence-v1" LF field-lines *evidence-line
v2-preimage     = "assay-evidence-v2" LF field-lines checks-line *evidence-line
v3-preimage     = "assay-evidence-v3" LF field-lines checks-line network-line
                  *evidence-line
v4-preimage     = "assay-evidence-v4" LF scanner-line field-lines checks-line
                  network-line *evidence-line

; The scanner's module version or the literal "devel", escaped like every
; other field. Set on every report scan.Scanner produces (#271).
scanner-line    = "scanner" HTAB escaped-value LF

; v1 is exactly these lines: no checks line, not even an empty one (#269).
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

Version selection is part of the contract: a report is written under the one
tag whose bindings it carries (the table at the top of this section), and a
report whose bindings match no tag is refused with `ErrUnencodable`, never
written under the nearest tag.

Version selection describes the bytes a *fresh* report is written under. To
reproduce an attestation already on chain, render the version that record
names instead: `attest.PreimageAs` (and `assay attestation -preimage-version
vN`) apply the rules above to the requested version rather than to the report's
own, so a v1 rendering of a report that holds bindings omits the checks,
network and scanner lines v1 never had. Comparing a fresh scan's default
rendering against a v1 record would compare unlike bytes; this is the rendering
path that makes the comparison meaningful.

Two more rules are load-bearing even though no production rule can express
them: severity and mechanics render as decimal integers of their bit values,
not as the names the report JSON uses (the bit/name table is the ABI section
above), and retrieval timestamps are excluded entirely, so a conformance
input's `retrieved_at` never appears in the expected preimage.

## Not done yet

- **Single admin.** One key can write or revoke any attestation. A production
  deployment wants multisig or a threshold of independent attesters. The
  options are compared, with a recommendation, in
  [multi-attestor.md](multi-attestor.md).
- **No re-attestation schedule.** Nothing refreshes an attestation when an
  issuer's flags change. Freshness is entirely the caller's policy via
  `attested_at` and `max_age_secs`.
- **TTL is extended on write only.** `init`, `attest`, `attest_many` and
  `revoke` extend the contract instance and code to the network maximum, and the
  two write paths extend the attestation entries they write. Reads extend nothing. An attestation nobody re-attests
  is archived after roughly 180 days on current testnet parameters. It is then
  restored on the next access at the reader's expense, not lost. See
  [deployment.md](deployment.md#entry-lifetime). The live testnet deployment
  predates this change, and all its entries are archived today.
- **Testnet only.** No pubnet deployment exists, and the points above are why
  one would be premature.
