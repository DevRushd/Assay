# On-chain "ever escalated" marker (threat model #4)

**Status: design, not implemented.** This record closes threat model class 4
("Reputation, attribution, age, or popularity lowers a severity"), whose
residual risk is accepted only for want of a mechanism:

> Residual risk accepted: a consumer reading only the current attestation sees
> the lower level with no indication that it was ever higher.

The goal is a cheap, monotone, on-chain record so a gate can refuse assets
that were once critical, even after a later scan lowers the attested severity.
Three approaches are compared below, with ABI impact and storage cost, and one
is recommended. Implementation is filed separately and happens only after
sign-off on this design.

## The gap

Severity inside one report cannot go down: final severity is the maximum over
all findings, and `Engine.Run` raises it to the base at the end
([threat-model.md] #4). Across reports it can: if a source withdraws a listing,
the next scan recomputes a lower final severity. `revoke` retracts a claim, and
`attest` events plus the history API let an indexer reconstruct what an asset
was, but **a consumer reading only the current attestation sees the lower level
with no indication it was ever higher**. A gate that wants "never admit an
asset once critical" cannot express that today.

## Approaches compared

### 1. Stored maximum historical severity (recommended)

Add one monotone storage entry per asset:

```
DataKey::MaxSeverity(Address) -> u32   // highest severity ever attested for the asset
```

On every successful `attest` / element of `attest_many`, the contract computes
`max(previous_max_or_0, new_severity)` and stores it. It never decreases. On
`revoke`, the entry is removed along with the attestation, so a revoked asset
reads exactly like never-attested (`0`) and the "no tombstone" principle
([contract-interface.md](#revoked-and-never-attested-look-the-same-on-chain-deliberately))
is preserved.

A new read-only entrypoint:

```rust
pub fn max_severity_ever(env: Env, asset: Address) -> u32;
```

returns the stored maximum, or `0` when the asset was never attested or its
attestation was revoked. A gate can then refuse an asset whose historical
maximum exceeds its ceiling:

```rust
if registry.max_severity_ever(&asset) > max_severity { refuse }
```

An event is emitted only when the stored maximum increases:

```
Topics: ("max_severity_updated", asset)
Data: { previous_max: u32, new_max: u32 }
```

so an indexer can track escalations without decoding every `attest` event, and
a consumer that trusts the indexer gets an on-chain-auditable signal.

**ABI impact:** one new read-only entrypoint and one new event. The `Safety`
struct is unchanged, so existing stored attestations keep reading identically
and no storage migration is needed. Assets attested before this marker exists
read `max_severity_ever == 0` for the period before the marker was introduced
— their pre-marker history is unknown, which is documented rather than
fabricated. This is an additive ABI change.

**Storage cost:** one additional persistent entry per attested asset (a `u32`
value, the same order of magnitude as a `Safety` entry). Each attest write pays
one extra read (`get` of the prior maximum, absent = 0) and one extra write.
The increase event costs ~200 bytes of the contract-event budget only on the
writes that raise the maximum. At `attest_many`'s `MAX_BATCH_SIZE` (50) the
per-call extra cost is bounded by 50 reads + 50 writes + at most 50 increase
events, measured the same way `batch_size_bound_is_measured_and_holds_headroom`
measures `attest_many`.

### 2. De-escalation counter

A separate counter `DataKey::DeEscalations(Address) -> u32` is incremented
whenever a write lowers the stored severity below the previously stored
severity. A gate refuses when the counter is non-zero: the asset was de-escalated
at least once.

**ABI impact:** one new entrypoint and one new counter entry; `Safety`
unchanged. Additive.

**Storage cost:** one counter entry per asset that has ever been de-escalated;
no per-write cost on non-de-escalating writes, but each write must read the
previous severity to detect a decrease.

**Why not recommended:** a counter tells a gate *that* an asset was de-escalated,
but not *how high* it ever was. It cannot distinguish "was critical once" from
"was medium once, then clear", so a gate cannot refuse "once critical" — it can
only refuse "ever lowered at all", which is over-broad (a medium-to-clear
asset would be refused alongside a critical-to-medium one). The maximum is the
strictly more informative record for the same storage class.

### 3. Event-only (current state, not sufficient)

The `attest` event already publishes the previous and current values, and the
history API retains observations
([threat-model.md] #4, third bullet). An indexer that replays events can
reconstruct an asset's historical maximum.

**ABI impact:** none. **Storage cost:** none.

**Why not recommended:** it does not close the gap. A consumer reading only the
current attestation — the exact failure mode in class 4 — sees nothing. The
residual risk remains unchanged, so event-only is the status quo this issue
exists to replace, not a fix.

## Recommendation

**Approach 1: stored maximum historical severity**, exposed through
`max_severity_ever(asset)`, with an increase event.

It is the only option that both closes the gap (a gate can refuse assets that
were once critical) and stays cheap and monotone (one `u32` entry, never
decreases, no change to the `Safety` ABI, no migration for existing entries).
The counter (2) is weaker information for the same cost, and event-only (3)
leaves the residual risk exactly where it is.

## Open points for sign-off

- Whether `revoke` removes the maximum entry (recommended: yes, so revoked and
  never-attested remain identical) or keeps it as an indelible record.
- Whether `max_severity_ever` is a separate entrypoint or folded into an
  extended `Safety` (a separate entrypoint avoids touching the stored `Safety`
  ABI; folding it in would change every stored attestation's encoding and
  require re-attestation of the live set).
- The name of the entrypoint and event (`max_severity_ever`,
  `max_severity_updated` are placeholders pending review).
- The measured cost numbers at `MAX_BATCH_SIZE`, to be pinned in a contract
  test once implemented, mirroring `batch_size_bound_is_measured_and_holds_headroom`.
