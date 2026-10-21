#![no_std]
//! Assay safety registry: an on-chain gate for Stellar asset trap mechanics.
//!
//! # What this contract is, and what it is not
//!
//! A Soroban contract cannot call Horizon, fetch a stellar.toml, or read an
//! issuer's authorization flags from within a transaction. So this contract
//! does not scan anything. It stores *attestations* produced by an off-chain
//! Assay scanner and lets another contract read one atomically, in the same
//! transaction as the action it is protecting.
//!
//! That distinction is deliberate and is stated here rather than hidden behind
//! a reassuring function name. A caller is trusting the attester, plus the
//! `evidence_hash` that lets anyone verify the attestation against the evidence
//! the scanner actually fetched.
//!
//! # Why severity is safe to gate on
//!
//! [`Safety::severity`] is capability-only: it is derived from the issuer's
//! authorization flags and never adjusted by reputation, attribution, age, or
//! popularity. Two assets whose issuers hold identical power over holders get
//! identical severity. A gate reading `severity <= MEDIUM` is therefore relying
//! on a statement about ledger mechanics, not on anyone's opinion of an issuer.
//!
//! The one exception moves in the safe direction only: a confirmed malicious
//! listing escalates severity to [`SEVERITY_CRITICAL`]. Reputation can raise a
//! level, never lower one.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, BytesN, Env};

/// No authorization flags: the issuer has no special power over holders.
pub const SEVERITY_CLEAR: u32 = 0;
/// `auth_required`: the issuer controls who may open a trustline.
pub const SEVERITY_LOW: u32 = 1;
/// `auth_revocable`: the issuer can freeze an existing holder's balance.
pub const SEVERITY_MEDIUM: u32 = 2;
/// `auth_clawback_enabled`: the issuer can confiscate and burn a balance.
pub const SEVERITY_HIGH: u32 = 3;
/// Reserved for reputation escalation; never produced by reading flags.
pub const SEVERITY_CRITICAL: u32 = 4;

/// Mechanic bits. These positions are ABI and must not be renumbered; they
/// match `internal/mechanics.Mechanic` on the Go side.
pub const MECH_AUTH_REQUIRED: u32 = 1 << 0;
pub const MECH_AUTH_REVOCABLE: u32 = 1 << 1;
pub const MECH_CLAWBACK_ENABLED: u32 = 1 << 2;
pub const MECH_FLAGS_LOCKED: u32 = 1 << 3;
pub const MECH_DOMAIN_UNVERIFIED: u32 = 1 << 4;
pub const MECH_BLOCKLISTED: u32 = 1 << 5;

/// Mechanics that let an issuer take a balance outright. Any asset matching
/// this mask has `severity >= SEVERITY_HIGH` by construction.
pub const CONFISCATION_MASK: u32 = MECH_CLAWBACK_ENABLED;

/// A stored safety attestation for one asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safety {
    /// Capability severity, `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    pub severity: u32,
    /// Bitset of observed mechanics.
    pub flags: u32,
    /// SHA-256 over the canonical evidence bundle the scanner fetched. It lets
    /// a verifier prove this attestation corresponds to specific evidence,
    /// rather than trusting the severity number on its own. The exact bytes
    /// hashed are specified by `internal/attest` and reproducible with
    /// `assay attestation -preimage CODE-ISSUER`.
    pub evidence_hash: BytesN<32>,
    /// Ledger timestamp when this attestation was written.
    pub attested_at: u64,
}

#[contracttype]
enum DataKey {
    /// Contract admin, the only address permitted to attest.
    Admin,
    /// Attestation for one asset, keyed by its Stellar Asset Contract address.
    Safety(Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// `init` was called on an already-initialized contract.
    AlreadyInitialized = 1,
    /// The contract has no admin yet.
    NotInitialized = 2,
    /// Severity outside `SEVERITY_CLEAR..=SEVERITY_CRITICAL`.
    InvalidSeverity = 3,
    /// An attestation violated the confiscation invariant: the clawback bit is
    /// set but severity is below `SEVERITY_HIGH`. Rejected at write time so a
    /// gate can rely on the invariant at read time.
    InconsistentAttestation = 4,
    /// `revoke` was called for an asset with no attestation in storage.
    /// Returned rather than treated as a no-op so a revocation aimed at the
    /// wrong address fails loudly instead of reporting success while the
    /// attestation it was meant to withdraw still stands.
    NotAttested = 5,
}

#[contract]
pub struct SafetyRegistry;

#[contractimpl]
impl SafetyRegistry {
    /// Sets the admin permitted to write attestations.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Writes an attestation for `asset`, identified by its SAC address.
    ///
    /// `severity`, `flags`, and `evidence_hash` come from the off-chain
    /// scanner: `assay attestation CODE-ISSUER` derives all three from a live
    /// scan, and `make attest` submits them. Validation here is not a
    /// formality: it enforces at write time the invariants that
    /// [`Self::is_safe`] relies on at read time.
    pub fn attest(
        env: Env,
        asset: Address,
        severity: u32,
        flags: u32,
        evidence_hash: BytesN<32>,
    ) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        if severity > SEVERITY_CRITICAL {
            return Err(Error::InvalidSeverity);
        }
        if flags & CONFISCATION_MASK != 0 && severity < SEVERITY_HIGH {
            return Err(Error::InconsistentAttestation);
        }

        let safety = Safety {
            severity,
            flags,
            evidence_hash,
            attested_at: env.ledger().timestamp(),
        };
        env.storage()
            .persistent()
            .set(&DataKey::Safety(asset), &safety);
        Ok(())
    }

    /// Removes the attestation for `asset`. Only the admin may revoke.
    ///
    /// After revocation, `get_safety` returns `None` for this asset, and every
    /// gate fails closed. Revoked and never-attested are deliberately
    /// indistinguishable on-chain: both return `None`.
    ///
    /// A revoke that fails (`NotAttested`, unauthorized caller) publishes nothing.
    pub fn revoke(env: Env, asset: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let safety_key = DataKey::Safety(asset.clone());
        if !env.storage().persistent().has(&safety_key) {
            return Err(Error::NotAttested);
        }

        env.storage().persistent().remove(&safety_key);
        Ok(())
    }

    /// Transfers the admin role to a new address.
    ///
    /// The new admin can attest and revoke. The previous admin loses this
    /// capability. Admin transfer is atomic: the new admin is set immediately
    /// and the old one is revoked in the same transaction.
    ///
    /// The caller must be the current admin; this is enforced by
    /// `require_auth()` on the admin address below.
    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;

        // The admin must sign the transfer transaction.
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// Reads the attestation for `asset`.
    ///
    /// Returns `None` when the asset has never been attested. That case is
    /// deliberately distinguishable from an attestation of `SEVERITY_CLEAR`:
    /// collapsing the two would make every unknown asset read as safe, which is
    /// the single worst failure this contract could have.
    pub fn get_safety(env: Env, asset: Address) -> Option<Safety> {
        env.storage().persistent().get(&DataKey::Safety(asset))
    }

    /// The fail-closed gate helper.
    ///
    /// Returns `true` only when an attestation exists, is fresh enough, and is
    /// at or below `max_severity`. Every other path returns `false`: never
    /// attested, stale, too severe, or inconsistent. The safe answer is the
    /// default, so a caller that gets the arguments wrong blocks rather than
    /// admits.
    ///
    /// `max_age_secs` of 0 disables the freshness requirement.
    pub fn is_safe(env: Env, asset: Address, max_severity: u32, max_age_secs: u64) -> bool {
        let Some(safety) = Self::get_safety(env.clone(), asset) else {
            return false; // never attested: fail closed
        };

        if safety.severity > max_severity {
            return false;
        }

        // Defence in depth: attest() rejects this, but a gate must not depend
        // on the writer having been correct.
        if safety.flags & CONFISCATION_MASK != 0 && max_severity < SEVERITY_HIGH {
            return false;
        }

        if max_age_secs > 0 {
            let now = env.ledger().timestamp();
            // saturating_sub avoids underflow if an attestation carries a
            // timestamp ahead of the current ledger.
            if now.saturating_sub(safety.attested_at) > max_age_secs {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod test;