#![no_std]
//! The Assay integration surface for Soroban contracts: the registry
//! interface, the attestation type, the mechanic bit constants, and one
//! policy-checking helper.
//!
//! # Why this crate exists
//!
//! `docs/integrating.md` used to ask integrators to copy the interface
//! declaration out of the document. Copy-paste is how an example's bugs and
//! stale constants spread: a gate that masks the wrong bits admits a known
//! scam ([#26]), and a stale copy of the bit positions silently renumbers
//! them. This crate is the single, drift-tested source an integrator depends
//! on instead. It is deliberately tiny and `no_std`: it declares the
//! interface of the *deployed* registry, so depending on it adds no
//! on-chain dependency on Assay — the gate still talks to a registry
//! address it was constructed with.
//!
//! # Versioning
//!
//! The constants in this crate are the registry's ABI. They are versioned
//! with the workspace (and therefore with the registry builds in
//! `docs/deployment.md`): pin the dependency to the git revision of the
//! registry build you target, exactly as you would pin the registry address.
//! The Go engine's ABI drift test (`internal/mechanics/abi_drift_test.go`)
//! parses this file and fails the build if these constants ever disagree
//! with the Go side or with `assay-safety-registry`.
//!
//! [#26]: https://github.com/use-assay/Assay/issues/26

use soroban_sdk::{contractclient, contracttype, Address, BytesN, Env};

// ---------------------------------------------------------------------------
// The registry interface, as an integrator declares it.
// ---------------------------------------------------------------------------

/// Mirror of the registry's stored attestation.
///
/// Field names and types are ABI: they must match the registry exactly, because
/// a `#[contracttype]` struct crosses the contract boundary as a map keyed by
/// these names.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    pub severity: u32,
    pub flags: u32,
    pub evidence_hash: BytesN<32>,
    pub attested_at: u64,
}

/// The part of the registry this crate's callers use.
#[contractclient(name = "SafetyRegistryClient")]
pub trait SafetyRegistry {
    fn get_safety(env: Env, asset: Address) -> Option<Safety>;
    /// The contract's interface version, bumped on every ABI change
    /// ([docs/contract-interface.md](../../docs/contract-interface.md)). A
    /// consumer or drift script can call this to learn what the contract is
    /// instead of inferring it from a wasm hash.
    fn version(env: Env) -> u32;
    fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool;
}

// ---------------------------------------------------------------------------
// The bit constants. These are ABI and must not be renumbered; they mirror
// `assay-contracts/contracts/safety-registry/src/lib.rs` and
// `internal/mechanics/severity.go`. The drift test fails the build if the
// three sides ever disagree.
// ---------------------------------------------------------------------------

/// `auth_required`: the issuer controls who may open a trustline.
pub const MECH_AUTH_REQUIRED: u32 = 1 << 0;
/// `auth_revocable`: the issuer can freeze an existing holder's balance.
pub const MECH_AUTH_REVOCABLE: u32 = 1 << 1;
/// `auth_clawback_enabled`: the issuer can confiscate and burn a balance.
pub const MECH_CLAWBACK_ENABLED: u32 = 1 << 2;
/// `auth_immutable`: not a power — the flag set can never change again.
pub const MECH_FLAGS_LOCKED: u32 = 1 << 3;
/// `domain_unverified`: not a power — no verified party claims the asset.
pub const MECH_DOMAIN_UNVERIFIED: u32 = 1 << 4;
/// `blocklisted`: not a power — a curated source flagged the issuer.
pub const MECH_BLOCKLISTED: u32 = 1 << 5;

/// Capability bits only: the mechanics that are issuer powers over a holder's
/// balance. Everything outside this mask is a reported fact, not a power
/// (issue #34). Picking "the dangerous bits" by hand is how [#26] happened.
///
/// [#26]: https://github.com/use-assay/Assay/issues/26
pub const CAPABILITY_MASK: u32 = MECH_AUTH_REQUIRED | MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;

/// Mechanics that let an issuer take a balance outright. Any asset matching
/// this mask has `severity >= 3` by construction.
pub const CONFISCATION_MASK: u32 = MECH_CLAWBACK_ENABLED;

// ---------------------------------------------------------------------------
// The policy helper.
// ---------------------------------------------------------------------------

/// Why a policy refused an attestation.
///
/// The variants are the same three refusals the example gate reports as
/// contract errors, so a caller maps them one-to-one and a caller's client
/// can still tell "the issuer can take it" from "this attestation is stale".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyViolation {
    /// The newest attestation is older than the configured freshness policy.
    AttestationStale,
    /// Severity exceeds the configured policy ceiling.
    SeverityTooHigh,
    /// The issuer holds a power in the configured refused-mechanics mask.
    IssuerCanTakeIt,
}

/// Checks one attestation against a severity ceiling, a freshness window and
/// a refused-mechanics mask, in that order.
///
/// This is the whole judgment half of a gate, in one place, so an integrator
/// cannot assemble it wrong by omission. Both axes are checked because they
/// refuse disjoint things: a mask over capability bits alone is blind to
/// reputation escalation (an asset can be critical with no capability bits
/// at all), and a severity ceiling alone admits assets a specific product
/// cannot custody (a freeze-capable issuer under a ceiling of 2). See
/// `docs/integrating.md` for the reachable examples.
///
/// `now` is the current ledger timestamp (`env.ledger().timestamp()`), and
/// staleness is measured with `saturating_sub` so a ledger timestamp earlier
/// than `attested_at` reads as fresh rather than wrapping.
///
/// Note that `max_age_secs == 0` does NOT disable the freshness check here,
/// even though it does in the registry's own `is_safe`: a gate that trusted
/// an attestation of any age because someone constructed it with `0` would
/// fail open. With `0`, only an attestation from the current ledger second
/// passes.
pub fn check_policy(
    safety: &Safety,
    now: u64,
    max_severity: u32,
    max_age_secs: u64,
    refused_mechanics: u32,
) -> Result<(), PolicyViolation> {
    if now.saturating_sub(safety.attested_at) > max_age_secs {
        return Err(PolicyViolation::AttestationStale);
    }
    if safety.severity > max_severity {
        return Err(PolicyViolation::SeverityTooHigh);
    }
    if safety.flags & refused_mechanics != 0 {
        return Err(PolicyViolation::IssuerCanTakeIt);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    fn attestation(severity: u32, flags: u32, attested_at: u64) -> Safety {
        let env = Env::default();
        Safety {
            severity,
            flags,
            evidence_hash: BytesN::from_array(&env, &[7u8; 32]),
            attested_at,
        }
    }

    // The deployed example gate's policy, reproduced: ceiling 2, one day of
    // freshness, and the freeze + confiscation bits refused.
    const MAX_SEVERITY: u32 = 2;
    const MAX_AGE: u64 = 24 * 60 * 60;
    const REFUSED: u32 = MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED;
    const NOW: u64 = 1_000_000;

    #[test]
    fn clean_fresh_attestation_is_admitted() {
        // Severity 1 (auth_required) with the required bit: below the
        // ceiling, and the required bit is not in the refused mask.
        let s = attestation(1, MECH_AUTH_REQUIRED, NOW - 60);
        assert_eq!(
            check_policy(&s, NOW, MAX_SEVERITY, MAX_AGE, REFUSED),
            Ok(())
        );
    }

    // USDC's live shape: severity 2 with auth_revocable set. The ceiling
    // admits it; the mask must refuse it, or a freeze-capable issuer gets in.
    #[test]
    fn freeze_capable_asset_is_refused_by_the_mask() {
        let s = attestation(2, MECH_AUTH_REVOCABLE | MECH_DOMAIN_UNVERIFIED, NOW - 60);
        assert_eq!(
            check_policy(&s, NOW, MAX_SEVERITY, MAX_AGE, REFUSED),
            Err(PolicyViolation::IssuerCanTakeIt)
        );
    }

    // DOGE's live shape: severity 4 with NO capability bits — critical purely
    // by reputation. The mask computes 48 & 6 == 0 and would admit it; the
    // ceiling must refuse it, or a known scam gets in (#26).
    #[test]
    fn critical_by_reputation_without_capability_bits_is_refused() {
        let s = attestation(4, MECH_DOMAIN_UNVERIFIED | MECH_BLOCKLISTED, NOW - 60);
        assert_eq!(
            check_policy(&s, NOW, MAX_SEVERITY, MAX_AGE, REFUSED),
            Err(PolicyViolation::SeverityTooHigh)
        );
    }

    #[test]
    fn stale_attestation_is_refused_before_anything_else() {
        let s = attestation(4, MECH_CLAWBACK_ENABLED, NOW - MAX_AGE - 1);
        assert_eq!(
            check_policy(&s, NOW, MAX_SEVERITY, MAX_AGE, REFUSED),
            Err(PolicyViolation::AttestationStale)
        );
    }

    // A ledger timestamp at or before attested_at reads as fresh: a
    // clock-skewed ledger must not wrap into an ancient age.
    #[test]
    fn timestamp_before_attested_at_is_fresh() {
        let s = attestation(0, 0, NOW + 30);
        assert_eq!(
            check_policy(&s, NOW, MAX_SEVERITY, MAX_AGE, REFUSED),
            Ok(())
        );
    }

    // A zero freshness window fails closed, unlike the registry's is_safe:
    // only an attestation from the current ledger second passes.
    #[test]
    fn zero_max_age_refuses_an_older_attestation() {
        let fresh = attestation(0, 0, NOW);
        assert_eq!(check_policy(&fresh, NOW, MAX_SEVERITY, 0, REFUSED), Ok(()));
        let older = attestation(0, 0, NOW - 1);
        assert_eq!(
            check_policy(&older, NOW, MAX_SEVERITY, 0, REFUSED),
            Err(PolicyViolation::AttestationStale)
        );
    }

    #[test]
    fn capability_mask_is_exactly_the_three_power_bits() {
        assert_eq!(
            CAPABILITY_MASK,
            MECH_AUTH_REQUIRED | MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED
        );
        assert_eq!(CAPABILITY_MASK, 0b111);
        assert_eq!(CONFISCATION_MASK, MECH_CLAWBACK_ENABLED);
    }
}
