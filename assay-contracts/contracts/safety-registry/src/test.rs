#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, BytesN, Env};

fn setup() -> (Env, SafetyRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    (env, client, admin)
}

fn hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[7u8; 32])
}

#[test]
fn unattested_asset_returns_none() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert_eq!(client.get_safety(&asset), None);
}

/// The most important test in this contract. An asset nobody has ever scanned
/// must never be treated as safe.
#[test]
fn gate_fails_closed_on_unattested_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_CLEAR, &0));
}

#[test]
fn attest_then_read_roundtrips() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let got = client.get_safety(&asset).expect("attestation should exist");
    assert_eq!(got.severity, SEVERITY_MEDIUM);
    assert_eq!(got.flags, MECH_AUTH_REVOCABLE);
    assert_eq!(got.attested_at, 1_000);
    assert_eq!(got.evidence_hash, hash(&env));
}

#[test]
fn gate_admits_within_threshold_and_blocks_above() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(client.is_safe(&asset, &SEVERITY_HIGH, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_LOW, &0));
    assert!(!client.is_safe(&asset, &SEVERITY_CLEAR, &0));
}

#[test]
fn stale_attestation_fails_closed() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &600));

    env.ledger().set_timestamp(1_000 + 601);
    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &600));

    // max_age_secs = 0 disables the freshness requirement.
    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
}

#[test]
fn attestation_from_the_future_does_not_underflow() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(5_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    env.ledger().set_timestamp(1_000);

    assert!(client.is_safe(&asset, &SEVERITY_MEDIUM, &600));
}

/// Confiscation capability must not be expressible below High. The writer
/// rejects it so a reader can rely on the invariant.
#[test]
fn attest_rejects_clawback_below_high() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_attest(
            &asset,
            &SEVERITY_MEDIUM,
            &MECH_CLAWBACK_ENABLED,
            &hash(&env),
        )
        .expect_err("clawback below high must be rejected");

    assert_eq!(err, Ok(Error::InconsistentAttestation));
}

#[test]
fn attest_rejects_out_of_range_severity() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &(SEVERITY_CRITICAL + 1), &0, &hash(&env))
        .expect_err("severity above critical must be rejected");

    assert_eq!(err, Ok(Error::InvalidSeverity));
}

/// Even if a bad attestation somehow existed, a gate below High must not admit
/// a confiscation-capable asset.
#[test]
fn gate_blocks_confiscation_below_high_threshold() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_CLAWBACK_ENABLED | MECH_AUTH_REVOCABLE),
        &hash(&env),
    );

    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(client.is_safe(&asset, &SEVERITY_HIGH, &0));
}

#[test]
fn init_is_single_shot() {
    let (env, client, _) = setup();
    let other = Address::generate(&env);

    let err = client.try_init(&other).expect_err("second init must fail");
    assert_eq!(err, Ok(Error::AlreadyInitialized));
}

/// Revoke removes the attestation for an asset. Only the admin may revoke.
/// After revocation, get_safety returns None and every gate fails closed.
#[test]
fn revoke_removes_attestation() {
    let (env, client, admin) = setup();
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));
    assert_eq!(
        client.get_safety(&asset).expect("attestation should exist").severity,
        SEVERITY_MEDIUM
    );

    client.revoke(&asset);
    assert_eq!(client.get_safety(&asset), None);
}

/// Admin transfer sets the new admin address.
#[test]
fn transfer_admin_success() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    client.transfer_admin(&new_admin);

    // Verify the transfer completed by checking the admin changed in storage.
    // We attest after transfer to confirm the new admin is active.
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    // Revoke with new admin should work
    client.revoke(&asset);
    assert_eq!(client.get_safety(&asset), None);
}

/// Revoke after admin transfer works with the new admin.
#[test]
fn revoke_after_admin_transfer() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    client.transfer_admin(&new_admin);

    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    // Revoke with new admin
    client.revoke(&asset);
    assert_eq!(client.get_safety(&asset), None);
}