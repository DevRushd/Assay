# Calling `get_safety` from your contract

How a Soroban contract reads an Assay attestation and refuses to act on an asset
whose issuer can take it back.

Everything here runs against the live testnet deployment:

```
# Assay registry on Stellar testnet
CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
```

The complete, compiling version of this guide is
[`contracts/example-gate`](../assay-contracts/contracts/example-gate) — it is a
workspace crate with tests, deployed to testnet at
`CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX` and redeployed on
2026-09-16 with the severity ceiling ([#26](https://github.com/use-assay/Assay/issues/26)).
Read [deployment.md](deployment.md) for the transaction hashes.

## What you are trusting

Before the code: the registry is an **attestation store**, not a scanner. A
Soroban contract cannot fetch Horizon mid-transaction, so it cannot read an
issuer's flags itself. What it can do is read, atomically, what an off-chain
scanner concluded — which is the half that actually needs to be on-chain, since
an HTTP call before you submit can be answered against different ledger state
than the one your transaction lands in.

So you are trusting the attester. Today that is one key. `evidence_hash` is what
makes the trust checkable rather than absolute: it commits to the exact evidence
the scanner read, and anyone can re-scan and recompute it. The complete
statement of what the admin key can and cannot do is in [Trust boundary: the
admin key](contract-interface.md#trust-boundary-the-admin-key).

For a complete breakdown of every party you are trusting (issuer, attester key,
Horizon, and reputation providers) and the consequences if each is dishonest or
wrong, see [trust.md](trust.md).

## 1. Declare the interface

You do not need a dependency on Assay. Declare the parts you call:

```rust
use soroban_sdk::{contractclient, contracttype, Address, BytesN, Env};

/// Field names and types are ABI — they must match the registry exactly,
/// because a #[contracttype] struct crosses the boundary as a map keyed by
/// these names.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    pub severity: u32,
    pub flags: u32,
    pub evidence_hash: BytesN<32>,
    pub attested_at: u64,
}

#[contractclient(name = "SafetyRegistryClient")]
pub trait SafetyRegistry {
    fn get_safety(env: Env, asset: Address) -> Option<Safety>;
    fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
}
```

## 2. Decide what you are refusing

The bits, which are ABI and mirror `internal/mechanics`:

| Bit | Mechanic | What the issuer can do |
| --- | --- | --- |
| `1 << 0` | `auth_required` | Decide who may open a trustline |
| `1 << 1` | `auth_revocable` | Freeze an existing holder's balance |
| `1 << 2` | `auth_clawback_enabled` | Confiscate and burn a balance |
| `1 << 3` | `auth_immutable` | Nothing — the flag set can never change again |
| `1 << 4` | `domain_unverified` | Nothing — no verified party claims the asset |
| `1 << 5` | `blocklisted` | Nothing — a curated source flagged the issuer |

Severity `0..=4` is the same information collapsed to one ordered number:
`0` clear, `1` `auth_required`, `2` `auth_revocable`, `3`
`auth_clawback_enabled`, `4` reputation escalation.

**Gate on the bitset *and* on severity. Neither alone is enough.** Severity
answers "how bad"; the bitset answers "which power". They fail in opposite
directions, and both failures were reachable with the assets attested as of
2026-09-16:

- **Severity alone is too coarse.** `USDC` is attested at severity `2` with
  flags `18` (`auth_revocable | domain_unverified`). A gate reading
  `severity <= 2` admits it. A custodial balance that cannot survive a freeze
  should not. `USDZ` shows the same point from the other side: severity `3`,
  flags `6`, and a *verified* domain — verification does not weaken clawback.
- **The bitset alone is blind to reputation.** `DOGE-GA22IDJN…` is attested at
  severity `4` — critical — with flags `48`
  (`domain_unverified | blocklisted`). It carries **no capability bits at all**,
  because its issuer genuinely cannot freeze or confiscate; it is critical
  because a curated source calls it malicious. A gate masking only on
  `auth_revocable | auth_clawback_enabled` computes `48 & 6 == 0` and **admits
  a known scam.**

That second case was not hypothetical: the example gate shipped without the
ceiling and admitted DOGE on testnet. The source now carries the ceiling, with
a regression test reproducing the DOGE scenario
(`critical_by_reputation_without_capability_bits_is_refused`), and the fixed
instance was deployed on 2026-09-16 as the fix for
[#26](https://github.com/use-assay/Assay/issues/26). The live-result block
below shows the new instance; [deployment.md](deployment.md) has the full
matrix, including the refusal reasons verified for each branch.

The reason is structural. Reputation escalation raises `severity` and sets
`blocklisted`; it does not set a capability bit, and it must not — capability
bits describe what the issuer *can do*, and a scam listing is not a capability.
So a mask over capability bits cannot see escalation, by design.

Note also that bits `1 << 3` through `1 << 5` are **reported, not powers** —
and that boundary now has a name on both sides rather than living in the table:
`CAPABILITY_MASK` (Rust, in the registry) and `mechanics.CapabilityMask` (Go)
select exactly the three power bits `auth_required | auth_revocable |
auth_clawback_enabled`, and the ABI drift test fails the build if the two
sides ever disagree (issue #34). Refusing on bits outside the mask —
`domain_unverified`, `blocklisted` — refuses most of the network, including
plenty of assets whose issuers can do nothing to you.

## 3. Write the gate

```rust
use assay_safety_registry::{CAPABILITY_MASK, MECH_AUTH_REVOCABLE, MECH_CLAWBACK_ENABLED};

/// Powers a custodial balance cannot survive: the freeze and clawback bits
/// selected through Assay's exported capability mask rather than hand-rolled
/// from memory. The registry exports CAPABILITY_MASK (all three power bits)
/// and the policy masks below; picking bits by hand is how #26 happened.
pub const REFUSED_MECHANICS: u32 = MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Documented defaults for the deployed gate. These are not hidden globals;
/// they are stored in instance state at construction and are therefore visible
/// to every caller and reviewer.
pub const MAX_SEVERITY: u32 = 2;
pub const MAX_ATTESTATION_AGE: u64 = 24 * 60 * 60;

fn assert_safe(env: &Env, registry: &Address, asset: &Address) -> Result<(), Error> {
    let registry = SafetyRegistryClient::new(env, registry);

    // Handle None first and explicitly. An asset nobody has attested is
    // unknown, not safe — and treating unknown as safe would let any asset
    // through by the simple expedient of never being scanned.
    let Some(safety) = registry.get_safety(asset) else {
        return Err(Error::NotAttested);
    };

    if env.ledger().timestamp().saturating_sub(safety.attested_at) > MAX_ATTESTATION_AGE {
        return Err(Error::AttestationStale);
    }

    // Both axes, and they refuse for different reasons — so report them
    // separately. A caller that cannot tell "the issuer can take it" from
    // "a curated source calls this malicious" cannot act on either.
    if safety.severity > MAX_SEVERITY {
        return Err(Error::SeverityTooHigh);
    }

    if safety.flags & REFUSED_MECHANICS != 0 {
        return Err(Error::IssuerCanTakeIt);
    }

    Ok(())
}
```

The severity check has to be there even though it looks redundant next to the
mask. Every capability bit does have a severity, so for the assets in the table
above the mask appears to subsume it — right up to an asset like DOGE whose
severity comes from somewhere the mask cannot see.

On choosing `MAX_ATTESTATION_AGE`: [freshness.md](freshness.md) measures how
often issuer flags actually change, names the use classes that need different
windows, and marks every recommended number as a provisional default. Read it
before picking a value — the short version is that a day is defensible for a
custodial deposit gate, a fresh scan beats a cached attestation for one-shot
settlements, and no window survives without a re-attestation path behind it.

Then call it before you act, in the same transaction:

```rust
pub fn deposit(env: Env, asset: Address, from: Address, amount: i128) -> Result<(), Error> {
    from.require_auth();
    let registry: Address = env.storage().instance().get(&DataKey::Registry).unwrap();
    assert_safe(&env, &registry, &asset)?;
    // ... credit the balance
    Ok(())
}
```

### Or let the registry decide

If a severity threshold really is your whole policy, `is_safe` is the one-liner,
and it fails closed on every path — never attested, stale, too severe, or
internally inconsistent:

```rust
if !registry.is_safe(&asset, &2, &3600) {
    return Err(Error::AssetNotSafe);
}
```

`max_age_secs = 0` disables the freshness check. Pass it only if you have
decided that staleness is acceptable, not to make a test go green.
[freshness.md](freshness.md) is the guidance for every other value.

## 4. Deploy against the live registry

Take the registry address as a constructor argument rather than hardcoding it,
so the same wasm works on both networks:

```rust
pub fn __constructor(
    env: Env,
    registry: Address,
    max_severity: u32,
    max_age_secs: u64,
    refused_mechanics: u32,
) -> Result<(), Error> {
    if max_severity > 4 {
        return Err(Error::InvalidPolicy);
    }
    env.storage().instance().set(&DataKey::Registry, &registry);
    env.storage().instance().set(&DataKey::MaxSeverity, &max_severity);
    env.storage().instance().set(&DataKey::MaxAttestationAge, &max_age_secs);
    env.storage().instance().set(&DataKey::RefusedMechanics, &refused_mechanics);
    Ok(())
}
```

```sh
stellar contract deploy \
  --wasm target/wasm32v1-none/release/your_contract.wasm \
  --source-account your-key --network testnet \
  -- --registry CBK4FBIHMDTXCUPE4E3ZDVSFJSCY5FJETTKNIQPN4LFJIKKIBLKIXQ73
```

## 5. Look up an asset's address

The registry keys on an asset's **Stellar Asset Contract address**, not on
`CODE:ISSUER`. Address comparison is cheap on-chain; string handling is not.

```sh
stellar contract id asset --asset AQUA:GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA \
  --network testnet
# CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG
```

That address is derived from the network passphrase, so **the same asset has a
different address on testnet than on pubnet**. Derive it for the network you are
deploying to; do not copy one across.

## Trying it against the live deployment

Three attested assets, and one that is deliberately never attested:

```sh
# Testnet deployment; every address below is network-specific.
GATE=CAL5VYSWLKG367D5IYGI57XH7EMN5PLJ4CD6K3MO2HJBYYKEKPG3NKRX

# KALE — attested clear on 2026-09-16
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CCVNR6CGD6NFQG7XC6AVU5HF4YAPVXW5KZJCD73XFKUUO4YZUNEFKU2Z
# true

# USDZ — attested high, issuer can claw back (attestation past 24h)
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CAOM5NKBTSGEXTZZKH3STWSFWURMODC3TZ4NS2THN7W5YUDFK3IOHIHU
# false

# native XLM — never attested
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC
# false

# DOGE — attested critical (severity 4), but no capability bits
stellar contract invoke --id $GATE --source-account your-key --network testnet --send=no \
  -- would_admit --asset CDUV37BUTYKKWNGECZZNRYMM7JIQYYWAI7L2TPTXWQAEMIPG4SXRBRPD
# false — refused by the severity ceiling (#4). The pre-fix instance
#         returned true here; that was #26.
```

Every result above was observed against the deployed gate on 2026-09-16, and
freshness makes them time-dependent: this gate refuses any attestation older
than 24 hours. `USDZ` was last attested in August, so it is refused as stale
(`#2`) before its clawback bit is ever read — the gate behaving correctly, not a
regression. `KALE`, `AQUA` and `DOGE` were attested or re-attested on
2026-09-16, and a re-run more than a day later will see them refused as stale
too unless someone re-attests them.

`DOGE` is the case that matters. With a fresh attestation it is refused through
the severity ceiling — `Error(Contract, #4)`, `SeverityTooHigh` — where the
pre-fix instance admitted it. The registry itself always answered correctly
(`is_safe(DOGE, 2, 0)` returned `false` even while the old gate admitted it), so
the fault was in the example, and it is now fixed in the source, covered by a
regression test, and deployed. If you copied the earlier version, add the
severity ceiling from section 3.

Submitting a `deposit` rather than simulating gives you the reason. Verified on
2026-09-16: the unattested asset fails with `Error(Contract, #1)`
(`NotAttested`), `DOGE` with `#4` (`SeverityTooHigh`), and `USDZ` with `#2`
(`AttestationStale`). A failing call is rejected at simulation, so no
transaction is submitted; the admitted path was exercised with a real deposit,
recorded in [deployment.md](deployment.md).

## Verifying an attestation yourself

You do not have to take the stored severity on faith. `assay verify` automates the check by re-scanning the asset, recomputing the hash, reading the on-chain attestation, and reporting whether they agree:

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
agreement: severity 3, flags 6, hash ca9b13a6, age 4h12m0s
```

The command supports a `-max-age` flag (e.g. `-max-age=24h`) to treat stale attestations as a failure.
If the hashes differ, it reports the specific disagreeing field and exits non-zero. The mismatch means either the asset's sources changed since the attestation or the attestation does not correspond to the evidence it claims. The hash cannot tell you which — that is what `attested_at` and your own re-scan are for.

`assay attestation -preimage` prints the exact bytes hashed, so the check can be reimplemented in any language. The encoding is specified in [contract-interface.md](contract-interface.md).

This is the two-command sketch. [verifying.md](verifying.md) is the full
procedure: deriving the address for the network, reading the attestation, the
`undetermined` scan that makes verification impossible rather than failed, and
the third cause of a mismatch — the verifier's own environment, which is
[#24](https://github.com/use-assay/Assay/issues/24) and is not fixed yet.
### Or let the CLI do all three steps

`assay verify` (issue #39) performs the re-scan, the hash recomputation and the
on-chain read in one command, and exits non-zero on anything other than
agreement:

```sh
$ ./assay verify USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
AGREE: USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR
on-chain attestation matches the live scan
$ echo $?
0
```

The outcomes are deliberately distinct — four different messages and four
different exit codes — because "the attestation disagrees" and "there is no
attestation" demand different reactions from a gate operator:

| Outcome | Meaning | Exit code |
| --- | --- | --- |
| `agree` | scan, recomputed hash and chain all match | 0 |
| `stale` | they match, but the attestation is older than `-max-age` seconds | 2 |
| `mismatch` | one or more of `severity`, `flags`, `evidence_hash` differ; the differing fields are named | 1 |
| `absent` | no attestation on chain for this asset | 3 |
| `unverifiable` | the scan is undetermined (or otherwise nothing attestable), so no verdict is possible | 4 |

An undetermined scan **never** reports agreement: the command refuses to
compare a partial answer against the chain, reporting `unverifiable` instead.
Staleness is only judged when you pass `-max-age <seconds>`; without it a
matching attestation agrees regardless of age, because freshness policy
belongs to the caller (the same policy `is_safe`'s `max_age_secs` encodes
on-chain).

```sh
# fail the check when the attestation is more than an hour old
./assay verify -max-age 3600 USDZ-GAKTLPC4ZV37SSCITQ5IS5AQ4WPF4CF4VZJQPPAROSGXMYOATF5U6XPR

# machine-readable verdict for scripts
./assay verify -json AQUA-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA
```

The command reads the registry through the same simulated `get_safety` call
`make read` uses, so verifying costs nothing and needs no signature. The
registry id and network default to the live testnet deployment recorded in
[deployment.md](deployment.md); override with `ASSAY_CONTRACT_ID` and
`ASSAY_NETWORK` to verify against another deployment.
## Before you rely on this

- It is on **testnet**, not pubnet.
- **10 assets are attested.** Everything else returns `None`, which your gate
  must treat as "unknown", and which — if you gate correctly — means your
  contract refuses nearly every asset on the network.
- **One key can write any attestation.** There is no multisig and no threshold
  of independent attesters yet. The complete statement of powers and limits is
  in [Trust boundary: the admin key](contract-interface.md#trust-boundary-the-admin-key).
- **Nothing refreshes the attestations.** They are exactly as fresh as their
  `attested_at`. Choose a `max_age_secs` you would actually accept.
- Testnet is periodically reset, which removes these attestations. The live
  registry's entries are also archived (see
  [deployment.md](deployment.md#entry-lifetime)). An archived attestation is
  restored when read, with its original `attested_at`, and your transaction pays
  the restore fee. It does **not** read as `None`, so only `max_age_secs`
  protects you from an old one.
