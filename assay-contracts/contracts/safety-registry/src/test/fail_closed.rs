//! Fail-closed claims from docs/fail-closed.md, as named tests.
//!
//! The registry's individual tests pin each refusal on its own; this module
//! states the *systematic* claim the enumeration makes about them: for the
//! paths the document marks fail-closed, no argument combination — not the
//! most permissive threshold, not an empty policy mask — produces an
//! affirmative answer from a state that is not an affirmative attestation.
//!
//! It lives inside the `test` module so it reuses the suite's `setup` and
//! `hash` helpers rather than duplicating them.

use super::*;

/// C1/C2: an asset that was never attested is refused by both gates at every
/// severity threshold and every policy mask. `u32::MAX` is the most permissive
/// argument either gate accepts; if even that cannot admit an unattested
/// asset, nothing can.
#[test]
fn fail_closed_unattested_refused_at_every_threshold_and_mask() {
    let (_env, client, _admin) = setup();
    let asset = Address::generate(&_env);

    for threshold in 0..=SEVERITY_CRITICAL {
        assert!(
            !client.is_safe(&asset, &threshold, &0),
            "is_safe admitted an unattested asset at threshold {threshold}"
        );
    }
    for mask in [
        0u32,
        POLICY_MASK_CONFISCATION_ONLY,
        POLICY_MASK_FREEZE_INCLUSIVE,
        u32::MAX,
    ] {
        assert!(
            !client.is_safe_masked(&asset, &mask, &0),
            "is_safe_masked admitted an unattested asset with mask {mask:#x}"
        );
    }
}

/// C5: a stale attestation is refused at every threshold, not merely below the
/// one it was written under. Staleness is an independent axis from severity.
#[test]
fn fail_closed_stale_refused_at_every_threshold() {
    let (env, client, _admin) = setup();
    let asset = Address::generate(&env);

    env.ledger().set_timestamp(1_000);
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    env.ledger().set_timestamp(1_000 + 601);
    for threshold in 0..=SEVERITY_CRITICAL {
        assert!(
            !client.is_safe(&asset, &threshold, &600),
            "a stale attestation was admitted at threshold {threshold}"
        );
    }
    assert!(!client.is_safe_masked(&asset, &0, &600));
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &600));
}

/// C3 + C4: a rejected write changes nothing. An invalid severity, an
/// inconsistent bitset, and an unauthorized caller must all leave the asset
/// exactly as it was: unattested, and therefore refused by every gate. After
/// refusal the admin can still attest normally — rejection refuses the write,
/// it does not poison the key.
#[test]
fn fail_closed_rejected_writes_leave_the_asset_unattested() {
    let (env, client, admin) = setup();
    let asset = Address::generate(&env);
    let other = Address::generate(&env);

    let _ = client.try_attest(&asset, &(SEVERITY_CRITICAL + 1), &0, &hash(&env));
    let _ = client.try_attest(
        &asset,
        &SEVERITY_MEDIUM,
        &MECH_CLAWBACK_ENABLED,
        &hash(&env),
    );
    let _ = client
        .mock_auths(&[MockAuth {
            address: &other,
            invoke: &MockAuthInvoke {
                contract: &client.address,
                fn_name: "attest",
                args: (&asset, SEVERITY_CLEAR, 0u32, hash(&env)).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));

    assert_eq!(client.get_safety(&asset), None);
    assert!(!client.is_safe(&asset, &SEVERITY_CRITICAL, &0));
    assert!(!client.is_safe_masked(&asset, &0, &0));

    let _ = admin;
    client.attest(&asset, &SEVERITY_CLEAR, &0, &hash(&env));
    assert!(client.is_safe(&asset, &SEVERITY_CLEAR, &0));
}

/// C6: even a stored clawback-capable attestation is refused by a gate below
/// High. The writer rejects inconsistent attestations, but a gate must not
/// depend on the writer having been correct.
#[test]
fn fail_closed_gate_refuses_confiscation_below_high_even_if_stored() {
    let (env, client, _admin) = setup();
    let asset = Address::generate(&env);

    client.attest(&asset, &SEVERITY_HIGH, &MECH_CLAWBACK_ENABLED, &hash(&env));
    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    // An empty policy admits the same asset: the refusals above come from the
    // severity gate's defence-in-depth branch, not from the policy mask.
    assert!(client.is_safe_masked(&asset, &0, &0));
}

/// C6, discriminating form — the baseline mutation run (docs/mutation-catalogue.md
/// R-M4) showed the tests above cannot catch removal of the defence-in-depth
/// branch: with a well-formed HIGH+clawback attestation, the severity ceiling
/// refuses the gate call anyway, so deleting the bitset check changes nothing.
/// The branch only matters when the stored attestation itself violates the
/// write-time invariant, which is exactly the situation it exists for. Writing
/// such an attestation is impossible through `attest` (C3), so this test goes
/// through the host: it puts an inconsistent entry into storage directly, as a
/// buggy or pre-invariant writer would have.
#[test]
fn fail_closed_gate_refuses_confiscation_when_the_write_time_check_is_bypassed() {
    let (env, client, _admin) = setup();
    let asset = Address::generate(&env);

    // Bypass the write-time invariant by inserting the inconsistent entry as
    // the contract itself would store it.
    env.as_contract(&client.address, || {
        env.storage().persistent().set(
            &DataKey::Safety(asset.clone()),
            &Safety {
                severity: SEVERITY_MEDIUM,
                flags: MECH_CLAWBACK_ENABLED,
                evidence_hash: hash(&env),
                attested_at: env.ledger().timestamp(),
            },
        );
    });

    // The gate below High must refuse on the bitset, not because of severity.
    assert!(!client.is_safe(&asset, &SEVERITY_MEDIUM, &0));
    assert!(!client.is_safe_masked(&asset, &POLICY_MASK_CONFISCATION_ONLY, &0));
    // ...and if the invariant check were deleted, severity alone would admit
    // it: is_safe at HIGH and is_safe_masked with an empty policy must stay
    // honest about what they are and are not checking.
    assert!(client.is_safe(&asset, &SEVERITY_HIGH, &0));
    assert!(client.is_safe_masked(&asset, &0, &0));
}
