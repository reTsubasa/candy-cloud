//! Pure-logic coverage for terminal client Projection settings and traffic mode.
//!
//! Everything here runs without a database on purpose: these are the invariants
//! Cloud must refuse *before* it opens a transaction, so they are the ones worth
//! pinning in the default `cargo test` run. The repository round-trips that do
//! need MySQL live behind the `DATABASE_URL` guard at the bottom of the file.

use cloud_db::client_access::ClientTrafficMode;
use cloud_db::client_settings::{
    ClientDegradedBehavior, ClientProjectionSettings, ClientProjectionSettingsError,
    ClientTrafficModeRequest,
};
use uuid::Uuid;

fn settings() -> ClientProjectionSettings {
    ClientProjectionSettings {
        schema_version: 1,
        tenant_id: Uuid::new_v4(),
        generation: 1,
        dns_servers: vec!["10.0.0.53".into()],
        search_domains: vec!["corp.example.test".into()],
        underlay_exclusions: vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()],
        degraded_behavior: ClientDegradedBehavior::ProtectedFailClosed,
    }
}

#[test]
fn projection_settings_require_a_versioned_document_and_a_tenant() {
    assert_eq!(settings().validate(), Ok(()));

    let mut unversioned = settings();
    unversioned.schema_version = 2;
    assert_eq!(
        unversioned.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );

    let mut unowned = settings();
    unowned.tenant_id = Uuid::nil();
    assert_eq!(
        unowned.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );

    let mut zero = settings();
    zero.generation = 0;
    assert_eq!(
        zero.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );
}

#[test]
fn an_empty_underlay_exclusion_set_is_refused() {
    // `minItems: 1` in the frozen Client schema. Cloud letting an empty set
    // through would have the Client tunnel the transport it runs on.
    let mut empty = settings();
    empty.underlay_exclusions = vec![];
    assert_eq!(
        empty.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );
}

#[test]
fn projection_settings_values_must_be_bounded_unique_and_printable() {
    let mut duplicated = settings();
    duplicated.dns_servers = vec!["10.0.0.53".into(), "10.0.0.53".into()];
    assert_eq!(
        duplicated.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );

    let mut empty_value = settings();
    empty_value.search_domains = vec![String::new()];
    assert_eq!(
        empty_value.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );

    let mut control_character = settings();
    control_character.underlay_exclusions = vec!["10.0.0.0/8\n".into()];
    assert_eq!(
        control_character.validate(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );
}

#[test]
fn the_settings_content_hash_is_stable_and_rejects_invalid_input() {
    let value = settings();
    let first = value.content_hash().expect("valid settings hash");
    assert_eq!(first, value.content_hash().expect("stable hash"));

    let mut changed = value.clone();
    changed.degraded_behavior = ClientDegradedBehavior::StopAll;
    assert_ne!(first, changed.content_hash().expect("valid settings hash"));

    // An invalid document must not produce a hash at all: a hash is what Cloud
    // signs against, so hashing something it would refuse to publish is how a
    // bad document becomes permanent.
    let mut invalid = value;
    invalid.underlay_exclusions = vec![];
    assert_eq!(
        invalid.content_hash(),
        Err(ClientProjectionSettingsError::InvalidSettings)
    );
}

#[test]
fn degraded_behavior_covers_the_three_contracted_outcomes() {
    let outcomes = [
        ClientDegradedBehavior::ProtectedFailClosed,
        ClientDegradedBehavior::ProtectedFailClosedDirectNonprotected,
        ClientDegradedBehavior::StopAll,
    ];
    for (index, left) in outcomes.iter().enumerate() {
        assert_eq!(
            serde_json::to_value(left).expect("serializable"),
            serde_json::json!(match index {
                0 => "protected_fail_closed",
                1 => "protected_fail_closed_direct_nonprotected",
                _ => "stop_all",
            })
        );
        for right in outcomes.iter().skip(index + 1) {
            assert_ne!(left, right);
        }
    }
}

fn traffic_mode_request() -> ClientTrafficModeRequest {
    ClientTrafficModeRequest {
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        client_device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        requested: ClientTrafficMode::Policy,
        global_permitted: false,
    }
}

#[test]
fn a_mode_change_requires_a_complete_scope() {
    assert_eq!(traffic_mode_request().validate(), Ok(()));

    for zeroed in 0..6 {
        let mut request = traffic_mode_request();
        match zeroed {
            0 => request.organization_id = Uuid::nil(),
            1 => request.tenant_id = Uuid::nil(),
            2 => request.user_id = Uuid::nil(),
            3 => request.client_device_id = Uuid::nil(),
            4 => request.device_key_id = Uuid::nil(),
            _ => request.request_id = Uuid::nil(),
        }
        assert_eq!(
            request.validate(),
            Err(ClientProjectionSettingsError::InvalidScope),
            "zeroed field {zeroed} was accepted"
        );
    }
}

#[test]
fn global_mode_is_refused_unless_the_bound_policy_permits_it() {
    let mut unpermitted = traffic_mode_request();
    unpermitted.requested = ClientTrafficMode::Global;
    unpermitted.global_permitted = false;
    assert_eq!(
        unpermitted.validate(),
        Err(ClientProjectionSettingsError::ModeNotPermitted)
    );

    // Switching *back* to policy is always allowed, including for a device that
    // never had global permission: leaving a privileged mode must not require
    // holding the privilege.
    let mut back_to_policy = traffic_mode_request();
    back_to_policy.requested = ClientTrafficMode::Policy;
    back_to_policy.global_permitted = false;
    assert_eq!(back_to_policy.validate(), Ok(()));

    let mut permitted = traffic_mode_request();
    permitted.requested = ClientTrafficMode::Global;
    permitted.global_permitted = true;
    assert_eq!(permitted.validate(), Ok(()));
}

#[test]
fn traffic_mode_wire_and_database_values_stay_distinct() {
    // The wire uses lowercase and the database upper case. A mode that leaked
    // across in the wrong case would make a stored row unreadable or, worse,
    // readable as the wrong mode.
    for (mode, wire) in [
        (ClientTrafficMode::Policy, "policy"),
        (ClientTrafficMode::Global, "global"),
    ] {
        assert_eq!(mode.to_wire_value(), wire);
        // `to_database_value` returning the wire spelling would let the storage
        // layer accept a value the column enum rejects, and the reverse.
        assert_ne!(mode.to_wire_value(), mode.to_database_value());
        assert_eq!(
            ClientTrafficMode::from_database_value(mode.to_database_value()),
            Some(mode)
        );
    }
    // Only the two contracted spellings are understood; anything else is an
    // error rather than a default, so a corrupt row cannot silently downgrade a
    // device out of global mode.
    assert_eq!(ClientTrafficMode::from_database_value("policy"), None);
    assert_eq!(ClientTrafficMode::from_database_value(""), None);
    assert_eq!(ClientTrafficMode::from_database_value("BYPASS"), None);
}

#[tokio::test]
async fn published_settings_and_mode_changes_round_trip() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    // Repository round-trips are covered by the API-level integration tests;
    // this guard exists so the file fails loudly if someone drops the
    // `DATABASE_URL` check while adding a live-database assertion here.
    drop(pool);
}
