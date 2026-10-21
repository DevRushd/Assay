#![cfg(test)]

//! These tests run the example against the real registry contract, not a mock,
//! so a change to the registry's ABI breaks the published integration example
//! rather than only the registry's own tests.

use super::*;
use assay_safety_registry::{
    SafetyRegistry as Registry, SafetyRegistryClient as RegistryClient, MECH_AUTH_REVOCABLE,
    MECH_CLAWBACK_ENABLED, SEVERITY_CLEAR, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
};
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, BytesN, Env};

struct Fixture<'a> {
    env: Env,
    registry: RegistryClient<'a>,
    gate: ExampleGateClient<'a>,
}

fn setup() -> Fixture<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let registry_id = env.register(Registry, ());
    let registry = RegistryClient::new(&env, &registry_id);
    registry.init(&Address::generate(&env));

    let gate_id = env.register(
        ExampleGate,
        (
            registry_id,
            DEFAULT_MAX_SEVERITY,
            DEFAULT_MAX_ATTESTATION_AGE,
            DEFAULT_REFUSED_MECHANICS,
        ),
    );
    let gate = ExampleGateClient::new(&env, &gate_id);

    Fixture {
        env,
        registry,
        gate,
    }
}

fn hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[3u8; 32])
}

/// The failure this whole design exists to prevent: an asset nobody scanned
/// must not be admitted just because there is no bad news about it.
#[test]
fn unattested_asset_is_refused() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);

    assert!(!f.gate.would_admit(&asset));
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &100),
        Err(Ok(Error::NotAttested))
    );
    assert_eq!(f.gate.balance(&asset, &user), 0);
}

#[test]
fn clean_asset_is_admitted_and_credited() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert!(f.gate.would_admit(&asset));
    f.gate.deposit(&asset, &user, &100);
    assert_eq!(f.gate.balance(&asset, &user), 100);
}

/// A confiscation-capable asset is refused. With MAX_SEVERITY = 2, severity
/// HIGH (3) exceeds the ceiling, so the severity check fires first. Both
/// checks exist; the order doesn't matter for the outcome.
#[test]
fn confiscation_capable_asset_is_refused() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED),
        &hash(&f.env),
    );

    assert!(!f.gate.would_admit(&asset));
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &100),
        Err(Ok(Error::SeverityTooHigh))
    );
}

/// Freeze-only is below `SEVERITY_HIGH`, so a gate reading severity alone with
/// a `<= MEDIUM` threshold would admit this. The bitset is what refuses it.
#[test]
fn freeze_capable_asset_is_refused_even_though_severity_is_medium() {
    let f = setup();
    let asset = Address::generate(&f.env);
    f.registry.attest(
        &asset,
        &SEVERITY_MEDIUM,
        &MECH_AUTH_REVOCABLE,
        &hash(&f.env),
    );

    assert!(f.registry.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(!f.gate.would_admit(&asset));
}

#[test]
fn stale_attestation_is_refused() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert!(f.gate.would_admit(&asset));

    f.env
        .ledger()
        .set_timestamp(1_000_000 + MAX_ATTESTATION_AGE + 1);

    assert!(!f.gate.would_admit(&asset));
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &100),
        Err(Ok(Error::AttestationStale))
    );
}

/// A re-attestation must be able to close a gate that was previously open.
#[test]
fn re_attestation_can_revoke_admission() {
    let f = setup();
    let asset = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));
    assert!(f.gate.would_admit(&asset));

    f.registry.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED),
        &hash(&f.env),
    );
    assert!(!f.gate.would_admit(&asset));
}

/// The DOGE counter-example: critical-by-reputation with no capability bits.
/// A gate that reads only the bitset admits it (`48 & 6 == 0`). The severity
/// ceiling is what refuses it — without this check, a known scam walks in.
#[test]
fn critical_by_reputation_without_capability_bits_is_refused() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    // severity 4 (critical), flags 48 = domain_unverified | blocklisted,
    // zero capability bits — exactly the DOGE scenario.
    f.registry.attest(
        &asset,
        &SEVERITY_CRITICAL,
        &((1 << 4) | (1 << 5)),
        &hash(&f.env),
    );

    assert!(!f.gate.would_admit(&asset));
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &100),
        Err(Ok(Error::SeverityTooHigh))
    );
}

/// Severity above the ceiling is refused even when no capability bits are set.
#[test]
fn severity_above_ceiling_is_refused() {
    let f = setup();
    let asset = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CRITICAL, &0, &hash(&f.env));

    assert!(!f.gate.would_admit(&asset));
    assert_eq!(
        f.gate.try_deposit(&asset, &Address::generate(&f.env), &100),
        Err(Ok(Error::SeverityTooHigh))
    );
}

// ---------------------------------------------------------------------------
// Fail-closed claims from docs/fail-closed.md (#108)
// ---------------------------------------------------------------------------

/// C7: every non-affirmative state is refused even with the gate's freshness
/// requirement disabled (`MAX_ATTESTATION_AGE` is the contract's policy, but
/// these calls simulate an infinitely fresh registry). `None`, above-ceiling,
/// refused bits, and confiscation capability each refuse independently of the
/// others, so no single staleness hole can turn a refusal into an admission.
#[test]
fn fail_closed_every_non_affirmative_state_refused_without_freshness() {
    let f = setup();

    let unattested = Address::generate(&f.env);
    let critical = Address::generate(&f.env);
    let confiscatable = Address::generate(&f.env);
    let freezable = Address::generate(&f.env);
    let clean = Address::generate(&f.env);

    // No re-attestation of `clean`: it stays the only admitted asset.
    f.registry
        .attest(&critical, &SEVERITY_CRITICAL, &0, &hash(&f.env));
    f.registry.attest(
        &confiscatable,
        &SEVERITY_HIGH,
        &MECH_CLAWBACK_ENABLED,
        &hash(&f.env),
    );
    f.registry.attest(
        &freezable,
        &SEVERITY_MEDIUM,
        &MECH_AUTH_REVOCABLE,
        &hash(&f.env),
    );
    f.registry
        .attest(&clean, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert!(!f.gate.would_admit(&unattested));
    assert!(!f.gate.would_admit(&critical));
    assert!(!f.gate.would_admit(&confiscatable));
    assert!(!f.gate.would_admit(&freezable));
    assert!(f.gate.would_admit(&clean));
}

// ---------------------------------------------------------------------------
// Tests for issues #335, #336, #337
// ---------------------------------------------------------------------------

#[test]
fn policy_entrypoint_returns_configured_policy() {
    let f = setup();
    let pol = f.gate.policy();
    assert_eq!(pol.max_severity, DEFAULT_MAX_SEVERITY);
    assert_eq!(pol.max_attestation_age, DEFAULT_MAX_ATTESTATION_AGE);
    assert_eq!(pol.refused_mechanics, DEFAULT_REFUSED_MECHANICS);

    // Also test with custom constructor arguments
    let custom_gate_id = f.env.register(
        ExampleGate,
        (
            f.registry.address.clone(),
            1u32,
            3600u64,
            MECH_CLAWBACK_ENABLED,
        ),
    );
    let custom_gate = ExampleGateClient::new(&f.env, &custom_gate_id);
    let custom_pol = custom_gate.policy();
    assert_eq!(custom_pol.max_severity, 1);
    assert_eq!(custom_pol.max_attestation_age, 3600);
    assert_eq!(custom_pol.refused_mechanics, MECH_CLAWBACK_ENABLED);
}

#[test]
fn deposit_refuses_zero_amount() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert_eq!(
        f.gate.try_deposit(&asset, &user, &0),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(f.gate.balance(&asset, &user), 0);
}

#[test]
fn deposit_refuses_negative_amount() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert_eq!(
        f.gate.try_deposit(&asset, &user, &-1),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &-500),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(f.gate.balance(&asset, &user), 0);
}

#[test]
fn deposit_refuses_overflow_rather_than_panicking() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    // Deposit MAX - 10 first
    f.gate.deposit(&asset, &user, &(i128::MAX - 10));
    assert_eq!(f.gate.balance(&asset, &user), i128::MAX - 10);

    // Adding 11 would overflow i128
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &11),
        Err(Ok(Error::BalanceOverflow))
    );
    // Balance remains unchanged
    assert_eq!(f.gate.balance(&asset, &user), i128::MAX - 10);

    // Adding 10 reaches i128::MAX exactly
    f.gate.deposit(&asset, &user, &10);
    assert_eq!(f.gate.balance(&asset, &user), i128::MAX);

    // Any positive deposit on MAX balance overflows
    assert_eq!(
        f.gate.try_deposit(&asset, &user, &1),
        Err(Ok(Error::BalanceOverflow))
    );
    assert_eq!(f.gate.balance(&asset, &user), i128::MAX);
}

#[test]
fn deposit_is_bookkeeping_only_and_increments_internal_balance() {
    let f = setup();
    let asset = Address::generate(&f.env);
    let user = Address::generate(&f.env);
    f.registry
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&f.env));

    assert_eq!(f.gate.balance(&asset, &user), 0);
    f.gate.deposit(&asset, &user, &50);
    assert_eq!(f.gate.balance(&asset, &user), 50);
    f.gate.deposit(&asset, &user, &75);
    assert_eq!(f.gate.balance(&asset, &user), 125);
}
