#![cfg(test)]

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, BytesN, Env, IntoVal, Map, Symbol,
};

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

/// An empty forbidden_mask must NOT become a blanket allow for unattested
/// assets. The gate still requires that an attestation exists.
#[test]
fn masked_gate_fails_closed_on_unattested_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    assert!(!client.is_safe_masked(&asset, &0, &0));
    assert!(!client.is_safe_masked(&asset, &u32::MAX, &0));
}

#[test]
fn masked_gate_admits_when_no_forbidden_bit_is_set() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // Freeze-capable but not confiscation-capable.
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    // A policy that only refuses confiscation admits this asset.
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    // A freeze-inclusive policy refuses it.
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_FREEZE_INCLUSIVE, &0));
}

#[test]
fn masked_gate_blocks_confiscation_capable_asset() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(
        &asset,
        &SEVERITY_HIGH,
        &(MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED),
        &hash(&env),
    );

    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_FREEZE_INCLUSIVE, &0));
}

#[test]
fn masked_gate_all_bits_blocks_any_attested_flag() {
    let (env, client, _) = setup();
    let clean = Address::generate(&env);
    let dirty = Address::generate(&env);

    // Zero flags: an all-bits mask admits it (no forbidden bit is set).
    client.attest(&clean, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe_masked(&clean, &u32::MAX, &0));

    // Any flag set: an all-bits mask refuses it.
    client.attest(&dirty, &SEVERITY_LOW, &MECH_AUTH_REQUIRED, &hash(&env));
    assert!(!client.is_safe_masked(&dirty, &u32::MAX, &0));
}

#[test]
fn masked_gate_stale_attestation_fails_closed() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &600));

    env.ledger().set_timestamp(1_000 + 601);
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &600));

    // max_age_secs = 0 disables the freshness requirement.
    assert!(client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
}

/// A successful attest emits one event with topics ("attest", asset) and data
/// (severity, flags, attested_at). Events published by this contract are
/// isolated with filter_by_contract so any auth-machinery events elsewhere in
/// the environment do not confuse the assertion.
#[test]
fn attest_emits_event_on_success() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);
    env.ledger().set_timestamp(1_234);

    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    // Data is the Map produced by #[contractevent]: field-name Symbols to
    // their values. Building it this way makes what a consumer decoding the
    // event will see explicit.
    let mut data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    data.set(Symbol::new(&env, "attested_at"), 1_234u64.into_val(&env));
    data.set(
        Symbol::new(&env, "flags"),
        MECH_AUTH_REVOCABLE.into_val(&env),
    );
    data.set(
        Symbol::new(&env, "severity"),
        SEVERITY_MEDIUM.into_val(&env),
    );

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("attest"), asset).into_val(&env),
                data.into_val(&env),
            ),
        ],
    );
}

/// A rejected attestation must not publish an event; otherwise observers see
/// writes that never happened.
#[test]
fn attest_publishes_no_event_on_rejection() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // InvalidSeverity.
    let _ = client.try_attest(&asset, &(SEVERITY_CRITICAL + 1), &0, &hash(&env));
    // InconsistentAttestation.
    let _ = client.try_attest(
        &asset,
        &SEVERITY_MEDIUM,
        &MECH_CLAWBACK_ENABLED,
        &hash(&env),
    );

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env, /* empty: rejected attest calls must not emit events */],
    );
}

/// attest() requires auth from the admin set at init time. A non-admin
/// caller must be rejected. This test does not use mock_all_auths(), so
/// require_auth() on the admin address actually enforces.
#[test]
fn attest_rejects_unauthorized_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let _caller = Address::generate(&env);
    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env))
        .expect_err("non-admin must be rejected");

    // The error type is SDK-internal (soroban_sdk::Error), not our contract
    // Error enum. The important property is that it is an error at all: a
    // non-admin caller must not be able to write attestations.
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// Revocation (#86)
// ---------------------------------------------------------------------------

/// Revoking restores the never-attested state exactly: get_safety returns
/// None and both gates fail closed, even with their most permissive arguments.
#[test]
fn admin_revokes_attestation() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe(&asset, &SEVERITY_CRITICAL, &0));

    client.revoke(&asset);

    assert_eq!(client.get_safety(&asset), None);
    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
    assert!(!client.is_safe_masked(&asset, &0, &0));
}

/// Revocation only touches the named asset.
#[test]
fn revoke_leaves_other_assets_attested() {
    let (env, client, _) = setup();
    let revoked = Address::generate(&env);
    let kept = Address::generate(&env);

    client.attest(&revoked, &SEVERITY_CLEAR, &0, &hash(&env));
    client.attest(&kept, &SEVERITY_LOW, &MECH_AUTH_REQUIRED, &hash(&env));
    client.revoke(&revoked);

    assert_eq!(client.get_safety(&revoked), None);
    assert!(client.get_safety(&kept).is_some());
}

/// A revoked asset can be attested again, and the new attestation is read
/// normally with its own timestamp.
#[test]
fn revoke_then_reattest() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    client.revoke(&asset);

    env.ledger().set_timestamp(2_000);
    client.attest(&asset, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));

    let got = client
        .get_safety(&asset)
        .expect("re-attestation should exist");
    assert_eq!(got.severity, SEVERITY_MEDIUM);
    assert_eq!(got.flags, MECH_AUTH_REVOCABLE);
    assert_eq!(got.attested_at, 2_000);
}

/// Revoking an asset with no attestation is an error, not a silent success:
/// a revocation aimed at the wrong address must not report that it worked.
/// The same holds for a second revoke of the same asset.
#[test]
fn revoke_nonexistent_returns_not_attested() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let err = client
        .try_revoke(&asset)
        .expect_err("revoking a never-attested asset must fail");
    assert_eq!(err, Ok(Error::NotAttested));

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    client.revoke(&asset);
    let err = client
        .try_revoke(&asset)
        .expect_err("a second revoke must fail");
    assert_eq!(err, Ok(Error::NotAttested));
}

#[test]
fn revoke_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);

    let err = client
        .try_revoke(&Address::generate(&env))
        .expect_err("revoke before init must fail");
    assert_eq!(err, Ok(Error::NotInitialized));
}

/// revoke() requires the admin's authorization, exactly as attest() does. The
/// attestation is written with the admin's auth mocked for that one call; the
/// revoke is then signed by a different address, which must be rejected and
/// must leave the attestation in place.
#[test]
fn revoke_rejects_unauthorized_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let asset = Address::generate(&env);
    client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "attest",
                args: (&asset, SEVERITY_CLEAR, 0u32, hash(&env)).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    let caller = Address::generate(&env);
    let err = client
        .mock_auths(&[MockAuth {
            address: &caller,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "revoke",
                args: (&asset,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_revoke(&asset)
        .expect_err("non-admin must be rejected");

    // As in attest_rejects_unauthorized_caller, the error is the host's auth
    // error rather than a contract Error; what matters is that it is one.
    assert!(err.is_err());
    assert!(client.get_safety(&asset).is_some());
}

/// A successful revoke emits one event with topics ("revoke", asset).
#[test]
fn revoke_emits_event_on_success() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    env.ledger().set_timestamp(4_321);
    client.revoke(&asset);

    let mut data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    data.set(Symbol::new(&env, "revoked_at"), 4_321u64.into_val(&env));

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("revoke"), asset).into_val(&env),
                data.into_val(&env),
            ),
        ],
    );
}

/// A failed revoke publishes nothing.
#[test]
fn revoke_publishes_no_event_on_rejection() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let _ = client.try_revoke(&asset);

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env, /* empty: a failed revoke must not emit an event */],
    );
}

// ---------------------------------------------------------------------------
// TTL and archival (#87)
// ---------------------------------------------------------------------------

use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};

fn safety_ttl(env: &Env, client: &SafetyRegistryClient, asset: &Address) -> u32 {
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .get_ttl(&DataKey::Safety(asset.clone()))
    })
}

fn instance_ttl(env: &Env, client: &SafetyRegistryClient) -> u32 {
    env.as_contract(&client.address, || env.storage().instance().get_ttl())
}

fn max_ttl(env: &Env, client: &SafetyRegistryClient) -> u32 {
    env.as_contract(&client.address, || env.storage().max_ttl())
}

/// attest extends the attestation entry and the contract instance to the
/// network's maximum TTL, read from the host rather than hard-coded.
#[test]
fn attest_extends_ttl_to_network_max() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    let max = max_ttl(&env, &client);
    assert!(
        max > env.ledger().get().min_persistent_entry_ttl,
        "test is meaningless if the max equals the default"
    );
    assert_eq!(safety_ttl(&env, &client, &asset), max);
    assert_eq!(instance_ttl(&env, &client), max);
}

/// Re-attesting renews the TTL: an entry that has aged is pushed back out to
/// the maximum by the next write.
#[test]
fn reattest_renews_ttl() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let max = max_ttl(&env, &client);

    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + 10_000);
    assert_eq!(safety_ttl(&env, &client, &asset), max - 10_000);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert_eq!(safety_ttl(&env, &client, &asset), max);
}

/// Reads do not extend TTL. Retention follows writes, so an attestation nobody
/// refreshes ages out rather than being kept alive by the gates reading it.
#[test]
fn reads_do_not_extend_ttl() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let max = max_ttl(&env, &client);

    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + 10_000);
    let _ = client.get_safety(&asset);
    let _ = client.is_safe(&asset, &SEVERITY_CRITICAL, &0);
    let _ = client.is_safe_masked(&asset, &0, &0);

    assert_eq!(safety_ttl(&env, &client, &asset), max - 10_000);
}

/// Documents what the host does when an attestation's TTL has run out, which
/// is not what the obvious guess says. The read does not return `None` and does
/// not trap: since protocol 23 an archived persistent entry is restored on
/// access, so the read returns the original attestation with its original
/// `attested_at`. The test host models this, and the same behaviour was
/// observed on testnet on 2026-09-27, where simulating `get_safety` against an
/// archived entry returned it and marked it for restoration in the footprint
/// (see "Entry lifetime" in docs/deployment.md).
///
/// So archival is not an expiry control. What stops a gate trusting a
/// months-old attestation is `max_age_secs`, which still sees the original
/// timestamp; a caller passing `max_age_secs = 0` gets no such protection.
#[test]
fn read_after_archival_returns_original_attestation() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let entry_ttl = safety_ttl(&env, &client, &asset);

    // Keep the instance and code live so only the attestation has expired,
    // then move past its live-until ledger, advancing the clock with it.
    env.as_contract(&client.address, || {
        let max = env.storage().max_ttl();
        env.storage().instance().extend_ttl(max, max);
    });
    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + entry_ttl + 1);
    let aged = 1_000 + u64::from(entry_ttl + 1) * 5;
    env.ledger().set_timestamp(aged);

    let got = client
        .get_safety(&asset)
        .expect("an archived attestation is restored, not read as None");
    assert_eq!(got.attested_at, 1_000, "the original timestamp survives");

    // A freshness window shorter than the entry's age refuses it...
    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &86_400));
    assert!(!client.is_safe_masked(&asset, &0, &86_400));
    // ...and a caller that disabled freshness is served it as-is.
    assert!(client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
}