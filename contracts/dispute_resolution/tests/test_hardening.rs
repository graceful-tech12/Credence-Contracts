//! Hardening tests for `DisputeResolutionContract` (#1624):
//! creator authorization, counter ids, persistent storage with TTL extension,
//! and size-independent instance storage.
#![allow(clippy::disallowed_macros)]

use dispute_resolution::{DataKey, DisputeError, DisputeResolutionContract, DisputeStatus};
use soroban_sdk::{
    symbol_short,
    testutils::{
        storage::Instance as _,
        storage::Persistent as _,
        Address as _, EnvTestConfig, Events as _,
    },
    Address, Env, IntoVal, TryFromVal,
};

const PERSISTENT_TTL_THRESHOLD: u32 = 518_400;

fn setup() -> (
    Env,
    dispute_resolution::DisputeResolutionContractClient<'static>,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(DisputeResolutionContract, ());
    let client = dispute_resolution::DisputeResolutionContractClient::new(&env, &contract_id);
    (env, client, contract_id)
}

// ─── authorization ─────────────────────────────────────────────────────────

#[test]
fn create_requires_creator_auth() {
    // No mocked auths: the creator must actually sign.
    let env = Env::default();
    let contract_id = env.register(DisputeResolutionContract, ());
    let client = dispute_resolution::DisputeResolutionContractClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);

    let res = client.try_create_dispute(&creator, &resolver);
    assert!(res.is_err(), "create_dispute must require the creator's auth");
    assert!(client.try_get_dispute(&0).is_err(), "no record may be written");
}

#[test]
fn create_records_creator_auth() {
    let (env, client, _) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);

    let id = client.create_dispute(&creator, &resolver);
    let auths = env.auths();
    assert!(
        auths.iter().any(|(addr, _)| addr == &creator),
        "require_auth was not recorded for the creator"
    );

    let dispute = client.get_dispute(&id);
    assert_eq!(dispute.creator, creator);
    assert_eq!(dispute.resolver, resolver);
}

// ─── counter ids ───────────────────────────────────────────────────────────

#[test]
fn ids_are_sequential() {
    let (env, client, _) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);

    assert_eq!(client.create_dispute(&creator, &resolver), 0);
    assert_eq!(client.create_dispute(&creator, &resolver), 1);
    assert_eq!(client.create_dispute(&creator, &resolver), 2);

    assert_eq!(client.get_dispute(&1).creator, creator);
    assert_eq!(client.get_dispute_count(), 3);
}

#[test]
fn distinct_disputes_do_not_share_records() {
    let (env, client, _) = setup();
    let creator = Address::generate(&env);
    let resolver_a = Address::generate(&env);
    let resolver_b = Address::generate(&env);

    let id_a = client.create_dispute(&creator, &resolver_a);
    let id_b = client.create_dispute(&creator, &resolver_b);

    assert_ne!(id_a, id_b);
    client.close(&resolver_a, &id_a);

    assert_eq!(client.get_dispute(&id_a).status, DisputeStatus::Closed);
    assert_eq!(client.get_dispute(&id_b).status, DisputeStatus::Open);
    assert_eq!(client.get_dispute(&id_b).resolver, resolver_b);
}

// ─── storage tier ──────────────────────────────────────────────────────────

#[test]
fn records_in_persistent_storage() {
    let (env, client, contract_id) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);
    client.create_dispute(&creator, &resolver);

    env.as_contract(&contract_id, || {
        let key = DataKey::Dispute(0);
        assert!(
            env.storage().persistent().has(&key),
            "dispute must live in persistent storage"
        );
        assert!(
            !env.storage().instance().has(&key),
            "dispute must not live in instance storage"
        );
        assert_eq!(
            env.storage()
                .instance()
                .get::<DataKey, u64>(&DataKey::DisputeCounter),
            Some(1)
        );
    });
}

#[test]
fn ttl_extended_on_access() {
    let (env, client, contract_id) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);

    let id = client.create_dispute(&creator, &resolver);
    client.resolve(&resolver, &id);

    env.as_contract(&contract_id, || {
        let persistent_ttl = env.storage().persistent().get_ttl(&DataKey::Dispute(id));
        assert!(
            persistent_ttl >= PERSISTENT_TTL_THRESHOLD,
            "persistent TTL {persistent_ttl} is below the configured threshold"
        );
        let instance_ttl = env.storage().instance().get_ttl();
        assert!(
            instance_ttl >= PERSISTENT_TTL_THRESHOLD,
            "instance TTL {instance_ttl} is below the configured threshold"
        );
    });
}

// ─── check ordering ────────────────────────────────────────────────────────

#[test]
fn non_resolver_gets_unauthorized_on_closed() {
    let (env, client, _) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);
    let stranger = Address::generate(&env);

    let id = client.create_dispute(&creator, &resolver);
    client.close(&resolver, &id);

    // The resolver check precedes the status check, so the stranger learns
    // nothing about the dispute's state.
    assert_eq!(
        client.try_close(&stranger, &id).unwrap_err().unwrap(),
        DisputeError::Unauthorized
    );
    assert_eq!(
        client.try_resolve(&stranger, &id).unwrap_err().unwrap(),
        DisputeError::Unauthorized
    );

    // The resolver still observes the real state.
    assert_eq!(
        client.try_close(&resolver, &id).unwrap_err().unwrap(),
        DisputeError::AlreadyClosed
    );
}

// ─── instance cost is independent of dispute count ─────────────────────────

/// Storage footprint of `get_dispute(0)` with 1 vs 200 disputes.
struct Probe {
    read_entries: u32,
    read_bytes: u32,
    write_entries: u32,
    write_bytes: u32,
    instance_entries: u32,
}

/// Measure the storage footprint of a single `get_dispute(0)` invocation in a
/// fresh env holding `count` disputes.
///
/// Only the storage resources are asserted on: the raw instruction counter of
/// the test host also grows with the number of ledger entries the whole fixture
/// has produced (snapshot/rollback overhead that is not part of the contract's
/// cost), so it cannot isolate instance-storage size. `read_entries`,
/// `read_bytes` and the instance entry count measure exactly what the contract
/// touches.
fn probe(count: u32) -> Probe {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();
    let contract_id = env.register(DisputeResolutionContract, ());
    let client = dispute_resolution::DisputeResolutionContractClient::new(&env, &contract_id);

    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);
    for _ in 0..count {
        client.create_dispute(&creator, &resolver);
    }

    let _ = client.get_dispute(&0);
    let resources = env.cost_estimate().resources();
    let instance_entries = env.as_contract(&contract_id, || {
        env.storage().instance().all().len()
    });

    Probe {
        read_entries: resources.read_entries,
        read_bytes: resources.read_bytes,
        write_entries: resources.write_entries,
        write_bytes: resources.write_bytes,
        instance_entries,
    }
}

#[test]
fn instance_cost_independent_of_dispute_count() {
    let small = probe(1);
    let large = probe(200);

    assert_eq!(
        large.read_entries, small.read_entries,
        "get_dispute must read the same number of entries regardless of dispute count"
    );
    assert_eq!(
        large.read_bytes, small.read_bytes,
        "get_dispute must read the same number of bytes regardless of dispute count"
    );
    assert_eq!(large.write_entries, small.write_entries);
    assert_eq!(large.write_bytes, small.write_bytes);

    // Instance storage holds the counter and nothing else, however many
    // disputes exist.
    assert_eq!(small.instance_entries, 1);
    assert_eq!(large.instance_entries, 1);
}

// ─── event schema ──────────────────────────────────────────────────────────

#[test]
fn created_event_carries_creator_and_resolver() {
    let (env, client, _) = setup();
    let creator = Address::generate(&env);
    let resolver = Address::generate(&env);

    let id = client.create_dispute(&creator, &resolver);

    let all = env.events().all();
    let ev = all.iter().next().expect("create_dispute must emit an event");

    // Topics: ("created", id)
    let expected_topics = soroban_sdk::vec![
        &env,
        symbol_short!("created").into_val(&env),
        id.into_val(&env),
    ];
    assert_eq!(ev.1, expected_topics);

    // Data: (creator, resolver)
    let (data_creator, data_resolver): (Address, Address) =
        <(Address, Address)>::try_from_val(&env, &ev.2).expect("data must be (creator, resolver)");
    assert_eq!(data_creator, creator);
    assert_eq!(data_resolver, resolver);
}
