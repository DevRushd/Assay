#![cfg(test)]

pub mod fail_closed;

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, BytesN, Env, IntoVal, Map, Symbol, Vec,
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

/// attest() requires auth from the admin set at init time. An unsigned call
/// without authorization must be rejected.
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
fn attest_rejects_no_auth_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let asset = Address::generate(&env);

    let err = client
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env))
        .expect_err("unauthorized call must be rejected");

    assert!(err.is_err());
}

/// Verifies host behavior for archived persistent entries. An archived entry
/// is one whose TTL has expired (live_until < current ledger sequence).
/// Per CAP-0066 / Protocol 23, the host automatically restores archived entries
/// when they are accessed during a transaction (including simulation). The
/// restored entry receives a fresh TTL (current_sequence + min_persistent_ttl - 1).
/// This test documents the actual behavior: archived entries return the data
/// (Some(Safety)) with the original attested_at timestamp, making them
/// distinguishable from never-attested entries (which return None).
#[test]
fn archived_entry_auto_restored_and_readable() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // Write an attestation at ledger 0 (default sequence)
    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    // Verify it's readable initially
    let initial = client.get_safety(&asset);
    assert!(
        initial.is_some(),
        "entry should be readable before archival"
    );
    let original_attested_at = initial.unwrap().attested_at;

    // Default min_persistent_entry_ttl is 4096, so live_until = 4095.
    // Advance sequence to 4096 to expire the entry.
    env.ledger().set_sequence_number(4096);

    // Read the archived entry via contract function.
    // In test mode with soroban-sdk 27.0.5, the host auto-restores the entry
    // and extends its TTL. The original attested_at is preserved.
    let archived = client.get_safety(&asset);

    // Archived entries are distinguishable from never-attested:
    // - Never attested: get_safety returns None
    // - Archived: get_safety returns Some(Safety) with original attested_at
    assert!(
        archived.is_some(),
        "archived entry should be auto-restored and readable"
    );
    assert_eq!(
        archived.unwrap().attested_at,
        original_attested_at,
        "attested_at preserved after restoration"
    );

    // The entry now has a fresh TTL (live_until = 4096 + 4095 = 8191)
    // This is verified by the test snapshot.
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

    let got = client.get_safety(&asset).expect("attestation should exist");
    assert_eq!(got.severity, SEVERITY_CLEAR);

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

/// Property test: is_safe MUST return false for any unattested asset across all threshold/age arguments.
#[test]
fn is_safe_property_unattested() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    for max_sev in 0..=5 {
        for max_age in [0, 60, 600, 3600] {
            assert!(
                !client.is_safe(&asset, &max_sev, &max_age),
                "unattested asset must be false for max_sev={}, max_age={}",
                max_sev,
                max_age
            );
        }
    }
}

/// Exhaustive property test for is_safe over the conjunction of all four conditions:
/// 1. Attested state (true)
/// 2. Severity within threshold (attested_severity <= max_severity)
/// 3. Confiscation invariant intact (flags & CONFISCATION_MASK == 0 || max_severity >= SEVERITY_HIGH)
/// 4. Freshness window met (max_age_secs == 0 || age <= max_age_secs)
#[test]
fn is_safe_property_exhaustive() {
    let (env, client, _) = setup();

    let severities = [0, 1, 2, 3, 4, 5]; // Severity values 0..=5 (including out-of-range 5)
    let flag_sets = [
        0u32,
        MECH_AUTH_REQUIRED,
        MECH_CLAWBACK_ENABLED,
        MECH_AUTH_REQUIRED | MECH_CLAWBACK_ENABLED,
        0b111111u32,
    ];
    let max_severities = [0, 1, 2, 3, 4, 5];
    let max_ages = [0u64, 300, 600];
    let nows = [1_000u64, 1_300, 1_600, 2_000]; // ages: 0, 300, 600, 1000

    let attested_at = 1_000u64;

    for &attested_sev in &severities {
        for &attested_flags in &flag_sets {
            for &now in &nows {
                for &max_sev in &max_severities {
                    for &max_age in &max_ages {
                        let asset = Address::generate(&env);
                        env.ledger().set_timestamp(attested_at);

                        // If severity is valid (<= 4) and flags do not violate clawback invariant, write attestation
                        // Note: If clawback bit set and severity < 3, try_attest will reject write, so we manually test stored safety
                        if attested_flags & MECH_CLAWBACK_ENABLED != 0
                            && attested_sev < SEVERITY_HIGH
                        {
                            // Invalid write time invariant; cannot attest on chain directly, skipped from valid store
                            continue;
                        }
                        if attested_sev > SEVERITY_CRITICAL {
                            // Invalid severity; cannot attest on chain directly, skipped from valid store
                            continue;
                        }

                        client.attest(&asset, &attested_sev, &attested_flags, &hash(&env));
                        env.ledger().set_timestamp(now);

                        let age = now.saturating_sub(attested_at);

                        let cond_severity = attested_sev <= max_sev;
                        let cond_confiscation =
                            (attested_flags & CONFISCATION_MASK) == 0 || max_sev >= SEVERITY_HIGH;
                        let cond_freshness = max_age == 0 || age <= max_age;

                        let expected = cond_severity && cond_confiscation && cond_freshness;
                        let actual = client.is_safe(&asset, &max_sev, &max_age);

                        assert_eq!(
                            actual, expected,
                            "is_safe mismatch for sev={}, flags={}, max_sev={}, age={}, max_age={}",
                            attested_sev, attested_flags, max_sev, age, max_age
                        );
                    }
                }
            }
        }
    }
}

/// Contract error discriminants are ABI documented in docs/integrating.md and live results.
/// Reordering or changing discriminants silently breaks integrator error handling.
#[test]
fn error_code_values_are_abi() {
    assert_eq!(Error::AlreadyInitialized as u32, 1);
    assert_eq!(Error::NotInitialized as u32, 2);
    assert_eq!(Error::InvalidSeverity as u32, 3);
    assert_eq!(Error::InconsistentAttestation as u32, 4);
    assert_eq!(Error::NotAttested as u32, 5);
    assert_eq!(Error::NoPendingAdmin as u32, 6);
    assert_eq!(Error::BatchTooLarge as u32, 7);
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

/// init extends the contract instance to the network maximum, so the admin and
/// the deployed wasm stay live before any attestation exists. This is the one
/// write that happens before there is an entry to keep alive.
#[test]
fn ttl_init_extends_instance_to_network_max() {
    let (env, client, _) = setup();

    assert_eq!(instance_ttl(&env, &client), max_ttl(&env, &client));
}

/// revoke is a write and extends the instance TTL exactly as attest does.
/// Without this, retracting the last attestation would leave the contract
/// instance to age out even though a caller had just written to it.
#[test]
fn ttl_revoke_extends_instance_to_network_max() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    let max = max_ttl(&env, &client);

    let seq = env.ledger().sequence();
    env.ledger().set_sequence_number(seq + 10_000);
    assert_eq!(instance_ttl(&env, &client), max - 10_000);

    client.revoke(&asset);
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

// ---------------------------------------------------------------------------
// Batched attestation (#10)
// ---------------------------------------------------------------------------

/// Builds one batch element carrying the same evidence hash the single-write
/// tests use, so a batched write and a single write can be compared for
/// equality field by field.
fn att(env: &Env, asset: &Address, severity: u32, flags: u32) -> Attestation {
    Attestation {
        asset: asset.clone(),
        severity,
        flags,
        evidence_hash: hash(env),
    }
}

/// What the single-write path leaves, the batch path must leave identically:
/// the same stored `Safety` and the same gate answers. This is the parity
/// criterion from the issue, asserted on the value rather than on the calls.
#[test]
fn batch_reads_match_single_write_path() {
    let (env, client, _) = setup();
    env.ledger().set_timestamp(1_000);

    let single = Address::generate(&env);
    let batched = Address::generate(&env);

    // The same claim, once through attest() and once through attest_many().
    client.attest(&single, &SEVERITY_MEDIUM, &MECH_AUTH_REVOCABLE, &hash(&env));
    client.attest_many(&vec![
        &env,
        att(&env, &batched, SEVERITY_MEDIUM, MECH_AUTH_REVOCABLE),
    ]);

    let from_single = client.get_safety(&single).expect("single write must exist");
    let from_batch = client
        .get_safety(&batched)
        .expect("batched write must exist");
    assert_eq!(
        from_single, from_batch,
        "a batched element must read back exactly as a singly-written one"
    );

    // The gates cannot tell them apart either, at any ceiling and freshness.
    for max_severity in [SEVERITY_CLEAR, SEVERITY_MEDIUM, SEVERITY_CRITICAL] {
        for max_age in [0, 600] {
            assert_eq!(
                client.is_safe(&single, &max_severity, &max_age),
                client.is_safe(&batched, &max_severity, &max_age),
            );
        }
    }
    assert_eq!(
        client.is_safe_masked(&single, &POLICY_MASK_FREEZE_INCLUSIVE, &600),
        client.is_safe_masked(&batched, &POLICY_MASK_FREEZE_INCLUSIVE, &600),
    );
}

/// A batch is written in the order it was given, and each element publishes its
/// own `Attested` event with the same schema a single `attest` uses. An indexer
/// subscribed by asset therefore needs no batch-specific decoding path.
#[test]
fn batch_emits_one_event_per_element() {
    let (env, client, _) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    env.ledger().set_timestamp(2_000);

    client.attest_many(&vec![
        &env,
        att(&env, &first, SEVERITY_CLEAR, 0),
        att(&env, &second, SEVERITY_LOW, MECH_AUTH_REQUIRED),
    ]);

    let mut clear_data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    clear_data.set(Symbol::new(&env, "attested_at"), 2_000u64.into_val(&env));
    clear_data.set(Symbol::new(&env, "flags"), 0u32.into_val(&env));
    clear_data.set(Symbol::new(&env, "severity"), SEVERITY_CLEAR.into_val(&env));

    let mut low_data = Map::<Symbol, soroban_sdk::Val>::new(&env);
    low_data.set(Symbol::new(&env, "attested_at"), 2_000u64.into_val(&env));
    low_data.set(
        Symbol::new(&env, "flags"),
        MECH_AUTH_REQUIRED.into_val(&env),
    );
    low_data.set(Symbol::new(&env, "severity"), SEVERITY_LOW.into_val(&env));

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![
            &env,
            (
                client.address.clone(),
                (symbol_short!("attest"), first).into_val(&env),
                clear_data.into_val(&env),
            ),
            (
                client.address.clone(),
                (symbol_short!("attest"), second).into_val(&env),
                low_data.into_val(&env),
            ),
        ],
    );
}

/// The batch path must not be a way around write-time validation. Both
/// rejection modes are exercised with the bad element in the middle of the
/// batch, so a loop that wrote as it went would have already written the
/// element before it: nothing may be stored and nothing may be published.
#[test]
fn batch_with_one_invalid_entry_writes_nothing() {
    let (env, client, _) = setup();
    let before = Address::generate(&env);
    let after = Address::generate(&env);
    let bad = Address::generate(&env);

    for (invalid, want) in [
        (
            att(&env, &bad, SEVERITY_CRITICAL + 1, 0),
            Error::InvalidSeverity,
        ),
        (
            att(&env, &bad, SEVERITY_MEDIUM, MECH_CLAWBACK_ENABLED),
            Error::InconsistentAttestation,
        ),
    ] {
        let err = client
            .try_attest_many(&vec![
                &env,
                att(&env, &before, SEVERITY_CLEAR, 0),
                invalid,
                att(&env, &after, SEVERITY_CLEAR, 0),
            ])
            .expect_err("a batch containing an invalid element must be rejected");

        assert_eq!(err, Ok(want));

        // Neither the valid elements before and after the bad one, nor the bad
        // one itself, were applied. Nothing is partially written.
        assert_eq!(
            client.get_safety(&before),
            None,
            "element before the bad one"
        );
        assert_eq!(client.get_safety(&after), None, "element after the bad one");
        assert_eq!(client.get_safety(&bad), None, "the invalid element itself");

        assert_eq!(
            env.events().all().filter_by_contract(&client.address),
            vec![&env],
            "a rejected batch must publish no events"
        );
    }
}

/// The batch path validates, it does not over-validate: an element that the
/// single-write path accepts is accepted here too. A batch validator that was
/// subtly stricter than `attest` would be its own bug — the pipeline would
/// discover it as an unexplained rejection on live data.
#[test]
fn batch_accepts_what_the_single_path_accepts() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    // Clawback at High is the boundary the invariant allows.
    client.attest_many(&vec![
        &env,
        att(
            &env,
            &asset,
            SEVERITY_HIGH,
            MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED,
        ),
    ]);

    let got = client
        .get_safety(&asset)
        .expect("accepted element must exist");
    assert_eq!(got.severity, SEVERITY_HIGH);
    assert_eq!(got.flags, MECH_AUTH_REVOCABLE | MECH_CLAWBACK_ENABLED);
}

/// One element over the cap is rejected outright. Truncating would report
/// success for attestations that were never written.
#[test]
fn batch_over_the_cap_is_rejected() {
    let (env, client, _) = setup();
    let asset = Address::generate(&env);

    let mut oversized = Vec::new(&env);
    for _ in 0..=MAX_BATCH_SIZE {
        oversized.push_back(att(&env, &asset, SEVERITY_CLEAR, 0));
    }
    assert_eq!(oversized.len(), MAX_BATCH_SIZE + 1);

    let err = client
        .try_attest_many(&oversized)
        .expect_err("a batch larger than the cap must be rejected");
    assert_eq!(err, Ok(Error::BatchTooLarge));

    assert_eq!(client.get_safety(&asset), None);
    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env]
    );
}

/// The cap is inclusive: exactly `MAX_BATCH_SIZE` elements are accepted, and
/// every one of them is written. A cap that quietly refused its own published
/// value would be worse than no cap.
#[test]
fn batch_of_exactly_the_cap_is_accepted() {
    let (env, client, _) = setup();
    env.ledger().set_timestamp(1_234);

    let mut assets = Vec::new(&env);
    let mut batch = Vec::new(&env);
    for _ in 0..MAX_BATCH_SIZE {
        let asset = Address::generate(&env);
        assets.push_back(asset.clone());
        batch.push_back(att(&env, &asset, SEVERITY_CLEAR, 0));
    }

    client.attest_many(&batch);

    for asset in assets.iter() {
        let got = client
            .get_safety(&asset)
            .expect("every element of a full batch must be written");
        assert_eq!(got.severity, SEVERITY_CLEAR);
        assert_eq!(got.attested_at, 1_234);
    }
}

/// An empty batch is a successful no-op: no write, no event, no error. Named
/// here so the behaviour is a decision the tests hold, not an accident of the
/// loop bounds.
#[test]
fn empty_batch_succeeds_and_writes_nothing() {
    let (env, client, _) = setup();

    let empty: Vec<Attestation> = Vec::new(&env);
    client.attest_many(&empty);

    assert_eq!(
        env.events().all().filter_by_contract(&client.address),
        vec![&env]
    );
}

/// Every element written by one batch shares one ledger timestamp.
#[test]
fn batch_elements_share_one_timestamp() {
    let (env, client, _) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);
    env.ledger().set_timestamp(5_000);

    client.attest_many(&vec![
        &env,
        att(&env, &first, SEVERITY_CLEAR, 0),
        att(&env, &second, SEVERITY_LOW, MECH_AUTH_REQUIRED),
    ]);

    let a = client.get_safety(&first).expect("first element");
    let b = client.get_safety(&second).expect("second element");
    assert_eq!(a.attested_at, 5_000);
    assert_eq!(b.attested_at, 5_000);
}

/// A batch extends the TTL of every entry it writes, plus the instance and
/// code, to the network maximum — the same retention policy as the single
/// write path. Writes are the only thing that extends a TTL; a batch is one
/// write, not an exemption from the rule.
#[test]
fn batch_extends_ttl_to_network_max() {
    let (env, client, _) = setup();
    let first = Address::generate(&env);
    let second = Address::generate(&env);

    client.attest_many(&vec![
        &env,
        att(&env, &first, SEVERITY_CLEAR, 0),
        att(&env, &second, SEVERITY_LOW, MECH_AUTH_REQUIRED),
    ]);

    let max = max_ttl(&env, &client);
    assert_eq!(safety_ttl(&env, &client, &first), max);
    assert_eq!(safety_ttl(&env, &client, &second), max);
    assert_eq!(instance_ttl(&env, &client), max);
}

#[test]
fn attest_many_before_init_returns_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let asset = Address::generate(&env);

    let err = client
        .try_attest_many(&vec![&env, att(&env, &asset, SEVERITY_CLEAR, 0)])
        .expect_err("attest_many before init must fail");
    assert_eq!(err, Ok(Error::NotInitialized));
}

/// Batching is a different entrypoint, not a lower bar: the admin's
/// authorization is required exactly as for `attest`. The auth is mocked for
/// an unrelated address, which must be rejected and must leave nothing
/// written.
#[test]
fn attest_many_rejects_unauthorized_caller() {
    let env = Env::default();
    let contract_id = env.register(SafetyRegistry, ());
    let client = SafetyRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let caller = Address::generate(&env);
    let asset = Address::generate(&env);
    let batch = vec![&env, att(&env, &asset, SEVERITY_CLEAR, 0)];

    let err = client
        .mock_auths(&[MockAuth {
            address: &caller,
            invoke: &MockAuthInvoke {
                contract: &contract_id,
                fn_name: "attest_many",
                args: (&batch,).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_attest_many(&batch)
        .expect_err("non-admin must be rejected");

    // The error is the host's auth error rather than a contract Error; what
    // matters is that it is one, and that nothing was written.
    assert!(err.is_err());
    assert_eq!(client.get_safety(&asset), None);
}

/// The cap in `MAX_BATCH_SIZE` is derived from live network limits rather than
/// chosen for roundness, and this is the measurement it is derived from: a full
/// batch, run with the SDK's own invocation-resource enforcement switched on.
///
/// `Env::default` enforces `InvocationResourceLimits::mainnet()`, which is
/// identical to the live testnet settings read on 2026-09-27 with
/// `stellar network settings --network testnet` (protocol 28). So if the cap
/// were too high, `attest_many` would panic here exactly as the transaction
/// would fail on the network — which is what happened during development at
/// 100 elements (`contract events size bytes: 20000 > 16384`), and is why the
/// cap is not 100.
///
/// | Limit | Live network | A full 50-element batch |
/// | --- | --- | --- |
/// | contract event bytes | 16 384 | 10 000 (61%) — binding |
/// | ledger entries written | 200 | 51 |
/// | transaction footprint entries | 400 | 105 |
/// | bytes written | 132 096 | 14 072 |
/// | instructions | 400 000 000 | 3 275 513 |
/// | memory | 41 943 040 | 514 609 |
#[test]
fn batch_size_bound_is_measured_and_holds_headroom() {
    let (env, client, _) = setup();

    let mut batch = Vec::new(&env);
    for _ in 0..MAX_BATCH_SIZE {
        batch.push_back(att(
            &env,
            &Address::generate(&env),
            SEVERITY_MEDIUM,
            MECH_AUTH_REVOCABLE,
        ));
    }

    // This call is itself an assertion: the host enforces the network's limits,
    // so exceeding one panics here instead of on a real ledger.
    client.attest_many(&batch);

    // `resources()` reports what the last top-level invocation cost, in the
    // same units the network's limits are expressed in.
    let r = env.cost_estimate().resources();
    let footprint = r.disk_read_entries + r.memory_read_entries + r.write_entries;

    assert!(
        r.contract_events_size_bytes <= 16_384,
        "event bytes {} exceed the 16 384 budget",
        r.contract_events_size_bytes
    );
    assert!(
        r.write_entries <= 200,
        "write entries {} exceed 200",
        r.write_entries
    );
    assert!(footprint <= 400, "footprint entries {footprint} exceed 400");
    assert!(
        r.write_bytes <= 132_096,
        "write bytes {} exceed 132 096",
        r.write_bytes
    );
    assert!(
        r.instructions <= 400_000_000,
        "instructions {} exceed 400 000 000",
        r.instructions
    );
    assert!(
        r.mem_bytes <= 41_943_040,
        "memory {} exceeds 41 943 040",
        r.mem_bytes
    );

    // The event budget is the binding constraint, and what makes it bind is the
    // per-element `Attested` event. Pin the unit cost so the derivation above
    // fails loudly if the event schema grows, rather than the cap becoming
    // quietly wrong.
    assert_eq!(
        r.contract_events_size_bytes,
        200 * MAX_BATCH_SIZE,
        "per-event cost changed; MAX_BATCH_SIZE and the doc table must be re-derived"
    ); // The cap must use no more than two thirds of the tightest budget, and stay
       // under the ceiling that budget imposes. At 50 elements the batch costs
       // 10 000 of 16 384 event bytes, against a hard ceiling of 81 elements.
    let event_budget: u32 = 16_384;
    let per_event = r.contract_events_size_bytes / MAX_BATCH_SIZE;
    let hard_ceiling = event_budget / per_event;
    assert!(
        MAX_BATCH_SIZE * per_event * 3 <= event_budget * 2,
        "MAX_BATCH_SIZE must leave at least a third of the event budget unused"
    );
    assert!(
        MAX_BATCH_SIZE < hard_ceiling,
        "the cap must stay under the {hard_ceiling}-element hard ceiling"
    );
}
