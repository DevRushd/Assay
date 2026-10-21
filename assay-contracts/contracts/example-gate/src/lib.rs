#![no_std]
//! A worked example of gating a Soroban contract on Assay.
//!
//! This is the smallest contract that refuses to accept a deposit in an asset
//! whose issuer can take it back. It exists to be copied: everything an
//! integrator needs is either in this file or in the `assay-gate` crate it
//! depends on — the registry interface, the `Safety` type and the bit
//! constants live there, versioned with the registry's ABI, so this example
//! keeps no private copy that can drift from the deployed registry. At build
//! time it depends only on that interface crate; at run time it still talks to
//! a deployed registry address it was constructed with.
//!
//! It is deliberately not a vault. It stores a balance and nothing else (it
//! performs bookkeeping only and moves no tokens — see [`deposit`](ExampleGate::deposit)),
//! so the only thing worth reading here is the gate.
//!
//! See `docs/integrating.md` for the deployed testnet registry address and the
//! deploy command that wires it in.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env};

// ---------------------------------------------------------------------------
// The registry interface, as an integrator consumes it.
// ---------------------------------------------------------------------------

// The `Safety` type, `SafetyRegistryClient` and the `MECH_*` bits come from
// the `assay-gate` crate — the interface a third-party integrator depends on
// (#469). Re-declaring them here is how copy-pasted gates end up calling a
// different ABI than the one deployed. `Safety` is not named below: it
// arrives as the client's return type.
use assay_gate::{
    check_policy, PolicyViolation, SafetyRegistryClient, MECH_AUTH_REVOCABLE, MECH_CLAWBACK_ENABLED,
};

/// Mechanics this gate refuses outright, whatever the severity number says.
///
/// Severity is a single ordered number and answers "how bad"; the bitset
/// answers "which power", and a contract usually has an opinion about a
/// specific power. A custodial balance cannot survive confiscation or a freeze,
/// so both bits are refused here regardless of how the levels are ordered.
pub const REFUSED_MECHANICS: u32 = MECH_CLAWBACK_ENABLED | MECH_AUTH_REVOCABLE;

/// The severity ceiling, checked *in addition to* [`REFUSED_MECHANICS`].
///
/// Both are necessary and neither is redundant, which is the whole lesson of
/// this example. They catch disjoint things:
///
/// - `USDC` is severity 2 with `auth_revocable` set. The ceiling admits it;
///   the mask refuses it. Without the mask, a freeze-capable issuer gets in.
/// - `DOGE` is severity 4 with flags `48` — `domain_unverified | blocklisted`
///   and **no capability bits at all**, because its issuer genuinely cannot
///   freeze or confiscate. The mask computes `48 & 6 == 0` and admits it; the
///   ceiling refuses it. Without the ceiling, a known scam gets in.
///
/// That second case is not a hypothetical. This contract shipped without the
/// ceiling and admitted `DOGE` on testnet.
///
/// The asymmetry is structural rather than accidental. Reputation escalation
/// raises severity and sets `blocklisted`; it must never set a capability bit,
/// because capability bits describe what an issuer *can do* and a scam listing
/// is not a capability. So a mask over capability bits cannot see escalation,
/// by construction — and any gate that reads only the mask is blind to half
/// the severity model.
pub const MAX_SEVERITY: u32 = 2;
/// A documented default for the policy stored at construction. The registry is
/// not upgradeable in place: a policy change requires a new instance behind a
/// new address, and the docs call that out explicitly.
pub const DEFAULT_MAX_SEVERITY: u32 = MAX_SEVERITY;

/// How stale an attestation may be before this gate stops trusting it.
///
/// Twenty-four hours is this contract's policy, not Assay's. The registry
/// exposes `attested_at` and takes the tolerance as a parameter precisely
/// because a deposit gate and a large settlement should not be forced to agree.
///
/// The derivation lives in `docs/freshness.md`: measured issuer-flag change
/// rates (zero among attested legitimate issuers over six months, month-scale
/// churn demonstrated on a scam issuer), the use classes that need different
/// windows, and the caveat that all ten live attestations are already past
/// this constant — a window without a re-attestation path behind it is a
/// countdown, and this example has no refresher.
pub const MAX_ATTESTATION_AGE: u64 = 24 * 60 * 60;
pub const DEFAULT_MAX_ATTESTATION_AGE: u64 = MAX_ATTESTATION_AGE;

pub const DEFAULT_REFUSED_MECHANICS: u32 = REFUSED_MECHANICS;

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

#[contracttype]
enum DataKey {
    /// The Assay registry this gate reads.
    Registry,
    /// The caller's policy for severity, staleness and blocked mechanics.
    MaxSeverity,
    MaxAttestationAge,
    RefusedMechanics,
    /// Deposited balance per (asset, depositor).
    Balance(Address, Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub max_severity: u32,
    pub max_attestation_age: u64,
    pub refused_mechanics: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// No attestation exists for this asset. The gate does not know the asset,
    /// which is not the same as the asset being safe.
    NotAttested = 1,
    /// The newest attestation is older than the configured freshness policy.
    AttestationStale = 2,
    /// The issuer holds a power in the configured refused-mechanics mask.
    IssuerCanTakeIt = 3,
    /// Severity exceeds the configured policy ceiling.
    SeverityTooHigh = 4,
    /// A caller supplied a policy that is outside the supported range.
    InvalidPolicy = 5,
    /// Deposit amount must be positive.
    InvalidAmount = 6,
    /// Deposited balance would overflow.
    BalanceOverflow = 7,
}

#[contract]
pub struct ExampleGate;

#[contractimpl]
impl ExampleGate {
    /// Binds this gate to a deployed Assay registry and stores the gate policy.
    ///
    /// A policy change requires a redeploy, because Soroban instance storage is
    /// fixed for a deployed contract. This keeps the decision explicit rather
    /// than allowing a silent contract upgrade path.
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
        env.storage()
            .instance()
            .set(&DataKey::MaxSeverity, &max_severity);
        env.storage()
            .instance()
            .set(&DataKey::MaxAttestationAge, &max_age_secs);
        env.storage()
            .instance()
            .set(&DataKey::RefusedMechanics, &refused_mechanics);
        Ok(())
    }

    /// Exposes this gate's configured policy: severity ceiling, maximum attestation age,
    /// and refused mechanics mask as set at construction.
    pub fn policy(env: Env) -> Policy {
        Policy {
            max_severity: env
                .storage()
                .instance()
                .get(&DataKey::MaxSeverity)
                .unwrap_or(DEFAULT_MAX_SEVERITY),
            max_attestation_age: env
                .storage()
                .instance()
                .get(&DataKey::MaxAttestationAge)
                .unwrap_or(DEFAULT_MAX_ATTESTATION_AGE),
            refused_mechanics: env
                .storage()
                .instance()
                .get(&DataKey::RefusedMechanics)
                .unwrap_or(DEFAULT_REFUSED_MECHANICS),
        }
    }

    /// Accepts a deposit, but only in an asset the issuer cannot claw back.
    ///
    /// NOTE: This worked example records internal bookkeeping only and moves no tokens.
    /// It increments an internal ledger balance counter and does NOT invoke `token::Client::transfer`.
    /// Production integrations custodying real assets must call the token contract to transfer funds.
    ///
    /// The read is a cross-contract call in the same transaction as the
    /// deposit, so the attestation cannot change between the check and the
    /// credit. That atomicity is the reason the registry is on-chain at all —
    /// an HTTP call to a scanner before submitting could be answered against a
    /// different ledger state than the one the deposit lands in.
    pub fn deposit(env: Env, asset: Address, from: Address, amount: i128) -> Result<(), Error> {
        from.require_auth();

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        Self::assert_safe(&env, &asset)?;

        let key = DataKey::Balance(asset, from);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = current.checked_add(amount).ok_or(Error::BalanceOverflow)?;
        env.storage().persistent().set(&key, &new_balance);
        Ok(())
    }

    /// Reports whether [`Self::deposit`] would admit this asset right now.
    ///
    /// Exposed so a client can show the reason before spending a fee on a
    /// transaction that would revert.
    pub fn would_admit(env: Env, asset: Address) -> bool {
        Self::assert_safe(&env, &asset).is_ok()
    }

    pub fn balance(env: Env, asset: Address, holder: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(asset, holder))
            .unwrap_or(0)
    }

    /// The gate itself.
    ///
    /// Every path that is not an affirmative, fresh, clean attestation is an
    /// error. `None` is handled first and explicitly: an asset nobody has
    /// attested is unknown, and treating unknown as safe would let any asset
    /// through by the simple expedient of never being scanned.
    fn assert_safe(env: &Env, asset: &Address) -> Result<(), Error> {
        let registry: Address = env
            .storage()
            .instance()
            .get(&DataKey::Registry)
            .expect("gate was constructed with a registry");
        let registry = SafetyRegistryClient::new(env, &registry);

        let Some(safety) = registry.get_safety(asset) else {
            return Err(Error::NotAttested);
        };

        let max_age = env
            .storage()
            .instance()
            .get(&DataKey::MaxAttestationAge)
            .unwrap_or(DEFAULT_MAX_ATTESTATION_AGE);
        let max_severity = env
            .storage()
            .instance()
            .get(&DataKey::MaxSeverity)
            .unwrap_or(DEFAULT_MAX_SEVERITY);
        let refused_mechanics = env
            .storage()
            .instance()
            .get(&DataKey::RefusedMechanics)
            .unwrap_or(DEFAULT_REFUSED_MECHANICS);

        // The judgment half lives in the assay-gate crate (#469): staleness
        // first, then the severity ceiling — without which an asset that is
        // critical purely by reputation passes the mask and is admitted (see
        // DOGE in the module docs and docs/integrating.md) — then the
        // refused-mechanics mask. Mapping the violation back to this
        // contract's error keeps every refusal path exactly where a caller
        // already knows to look.
        check_policy(
            &safety,
            env.ledger().timestamp(),
            max_severity,
            max_age,
            refused_mechanics,
        )
        .map_err(|violation| match violation {
            PolicyViolation::AttestationStale => Error::AttestationStale,
            PolicyViolation::SeverityTooHigh => Error::SeverityTooHigh,
            PolicyViolation::IssuerCanTakeIt => Error::IssuerCanTakeIt,
        })
    }
}

#[cfg(test)]
mod test;
