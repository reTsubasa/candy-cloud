use chrono::{Duration, Utc};
use cloud_db::client_control::{
    ClientControlError, ClientDeviceLookup, ClientDeviceRecord, ClientDeviceRegistration,
    ClientDeviceStatus, ClientGrantRecord, ClientGrantWrite, ClientPlatform,
};
use uuid::Uuid;

fn valid_request() -> ClientDeviceRegistration {
    let user_id = Uuid::new_v4();
    ClientDeviceRegistration {
        record_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id,
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        platform: ClientPlatform::Macos,
        display_name: "MacBook Pro".into(),
        install_id: "install-01HXYZ123".into(),
        client_version: Some("0.1.0".into()),
        public_key: [7; 32],
        request_id: Uuid::new_v4(),
        actor_id: user_id,
    }
}

#[test]
fn terminal_registration_requires_a_nonzero_scope_and_key() {
    let mut request = valid_request();
    request.tenant_id = Uuid::nil();
    assert_eq!(request.validate(), Err(ClientControlError::InvalidScope));

    let mut request = valid_request();
    request.public_key = [0; 32];
    assert_eq!(
        request.validate(),
        Err(ClientControlError::InvalidPublicKey)
    );
}

#[test]
fn terminal_registration_rejects_unbounded_install_identity() {
    let mut request = valid_request();
    request.install_id = "bad install id".into();
    assert_eq!(
        request.validate(),
        Err(ClientControlError::InvalidInstallId)
    );
}

#[test]
fn terminal_registration_binds_the_actor_to_the_session_user() {
    let mut request = valid_request();
    request.actor_id = Uuid::new_v4();
    assert_eq!(request.validate(), Err(ClientControlError::InvalidScope));
}

#[test]
fn client_platform_maps_only_the_three_contracted_database_values() {
    for (platform, stored) in [
        (ClientPlatform::Windows, "WINDOWS"),
        (ClientPlatform::Macos, "MACOS"),
        (ClientPlatform::Android, "ANDROID"),
    ] {
        assert_eq!(platform.database_value(), stored);
        assert_eq!(ClientPlatform::from_database_value(stored), Some(platform));
        // The database stores upper case and the wire uses lower case; neither
        // form may leak across the boundary by accident.
        assert_eq!(ClientPlatform::from_database_value(&stored.to_lowercase()), None);
    }
    assert_eq!(ClientPlatform::from_database_value("LINUX"), None);
    assert_eq!(ClientPlatform::from_database_value(""), None);
}

#[test]
fn device_status_unknown_values_are_not_silently_treated_as_active() {
    assert_eq!(
        ClientDeviceStatus::from_database_value("ACTIVE"),
        Some(ClientDeviceStatus::Active)
    );
    assert_eq!(
        ClientDeviceStatus::from_database_value("SUSPENDED"),
        Some(ClientDeviceStatus::Suspended)
    );
    assert_eq!(
        ClientDeviceStatus::from_database_value("REVOKED"),
        Some(ClientDeviceStatus::Revoked)
    );
    // A value Cloud does not understand must surface as an invalid record rather
    // than defaulting to a state that could authorize a device.
    assert_eq!(ClientDeviceStatus::from_database_value("active"), None);
    assert_eq!(ClientDeviceStatus::from_database_value("DELETED"), None);
}

fn active_device() -> ClientDeviceRecord {
    ClientDeviceRecord {
        record_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        platform: ClientPlatform::Windows,
        generation: 1,
    }
}

#[test]
fn a_stored_device_binding_must_be_complete_and_generation_nonzero() {
    let device = active_device();
    assert_eq!(device.validate(), Ok(()));

    // A zero generation is how a row that Cloud never fully initialized looks;
    // treating it as issuable would let a Grant be signed for an unversioned key.
    let mut unversioned = active_device();
    unversioned.generation = 0;
    assert_eq!(
        unversioned.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut unowned = active_device();
    unowned.user_id = Uuid::nil();
    assert_eq!(unowned.validate(), Err(ClientControlError::InvalidRecord));

    let mut keyless = active_device();
    keyless.device_key_id = Uuid::nil();
    assert_eq!(keyless.validate(), Err(ClientControlError::InvalidRecord));
}

#[test]
fn device_lookup_states_are_distinguishable_not_collapsed() {
    // Cloud must be able to answer `410` for revoked and `409` for suspended
    // instead of reporting both as "not found", so the variants must not be
    // interchangeable.
    let device = active_device();
    let states = [
        ClientDeviceLookup::Active(device),
        ClientDeviceLookup::Suspended {
            record_id: device.record_id,
            device_id: device.device_id,
        },
        ClientDeviceLookup::Revoked {
            record_id: device.record_id,
            device_id: device.device_id,
        },
    ];
    for (left, right) in states.iter().zip(states.iter().skip(1)) {
        assert_ne!(left, right);
    }
}

fn valid_grant_write() -> ClientGrantWrite {
    let issued_at = Utc::now();
    ClientGrantWrite {
        grant_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        client_device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        generation: 1,
        request_id: Uuid::new_v4(),
        request_hash: [7; 32],
        signing_key_id: "cloud-client-grant-2026-01".into(),
        grant_envelope: vec![1, 2, 3],
        issued_at,
        expires_at: issued_at + Duration::hours(1),
    }
}

#[test]
fn grant_write_requires_a_cloud_allocated_generation() {
    assert_eq!(valid_grant_write().validate(), Ok(()));

    // Generation 0 is reserved: it is what an unset or failed allocation looks
    // like, and Cloud must never store an envelope claiming it.
    let mut zero = valid_grant_write();
    zero.generation = 0;
    assert_eq!(zero.validate(), Err(ClientControlError::InvalidRecord));

    // Above the signed 64-bit ceiling the value stops round-tripping through
    // every downstream representation, so it is refused at the boundary.
    let mut overflow = valid_grant_write();
    overflow.generation = i64::MAX as u64 + 1;
    assert_eq!(overflow.validate(), Err(ClientControlError::InvalidRecord));

    let mut at_limit = valid_grant_write();
    at_limit.generation = i64::MAX as u64;
    assert_eq!(at_limit.validate(), Ok(()));
}

#[test]
fn grant_write_rejects_an_unusable_fingerprint_envelope_or_window() {
    // A zero fingerprint cannot distinguish two requests, so it would defeat the
    // idempotency check that protects a replay from handing back a stale Grant.
    let mut no_fingerprint = valid_grant_write();
    no_fingerprint.request_hash = [0; 32];
    assert_eq!(
        no_fingerprint.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut empty_envelope = valid_grant_write();
    empty_envelope.grant_envelope.clear();
    assert_eq!(
        empty_envelope.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut unbounded_envelope = valid_grant_write();
    unbounded_envelope.grant_envelope = vec![0; 1024 * 1024 + 1];
    assert_eq!(
        unbounded_envelope.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut empty_key_id = valid_grant_write();
    empty_key_id.signing_key_id.clear();
    assert_eq!(
        empty_key_id.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    // A nonpositive validity window is never a usable Grant.
    let mut inverted = valid_grant_write();
    inverted.expires_at = inverted.issued_at - Duration::seconds(1);
    assert_eq!(
        inverted.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut zero_width = valid_grant_write();
    zero_width.expires_at = zero_width.issued_at;
    assert_eq!(zero_width.validate(), Err(ClientControlError::InvalidRecord));
}

fn valid_grant_record() -> ClientGrantRecord {
    let write = valid_grant_write();
    ClientGrantRecord {
        grant_id: write.grant_id,
        organization_id: write.organization_id,
        tenant_id: write.tenant_id,
        user_id: write.user_id,
        client_device_id: write.client_device_id,
        device_key_id: write.device_key_id,
        generation: write.generation,
        request_hash: write.request_hash,
        signing_key_id: write.signing_key_id,
        grant_envelope: write.grant_envelope,
        issued_at: write.issued_at,
        expires_at: write.expires_at,
    }
}

#[test]
fn a_stored_grant_must_satisfy_the_same_invariants_as_a_written_one() {
    assert_eq!(valid_grant_record().validate(), Ok(()));

    let mut no_fingerprint = valid_grant_record();
    no_fingerprint.request_hash = [0; 32];
    assert_eq!(
        no_fingerprint.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut zero_generation = valid_grant_record();
    zero_generation.generation = 0;
    assert_eq!(
        zero_generation.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut unowned = valid_grant_record();
    unowned.tenant_id = Uuid::nil();
    assert_eq!(unowned.validate(), Err(ClientControlError::InvalidRecord));

    let mut expired_window = valid_grant_record();
    expired_window.expires_at = expired_window.issued_at - Duration::hours(1);
    assert_eq!(
        expired_window.validate(),
        Err(ClientControlError::InvalidRecord)
    );
}
/// Repository reads validate their scope before building a query, so a caller
/// with an incomplete identity tuple is refused without any database round trip.
/// These are deliberately run against a lazy pool: reaching storage would hang or
/// fail, which is exactly what proves the check happens first.
mod scope_checks {
    use super::*;
    use cloud_db::client_control::ClientControlRepository;

    fn repository() -> ClientControlRepository {
        let pool: cloud_db::DbPool =
            sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap();
        ClientControlRepository::new(pool)
    }

    #[tokio::test]
    async fn device_lookup_refuses_an_incomplete_scope() {
        let repository = repository();
        for (organization, tenant, user, device) in [
            (Uuid::nil(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()),
            (Uuid::new_v4(), Uuid::nil(), Uuid::new_v4(), Uuid::new_v4()),
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::nil(), Uuid::new_v4()),
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::nil()),
        ] {
            assert_eq!(
                repository
                    .device_by_wire_id(organization, tenant, user, device)
                    .await,
                Err(ClientControlError::InvalidScope)
            );
        }
    }

    #[tokio::test]
    async fn grant_reads_refuse_an_incomplete_scope() {
        let repository = repository();
        assert_eq!(
            repository
                .next_grant_generation(Uuid::nil(), Uuid::new_v4())
                .await,
            Err(ClientControlError::InvalidScope)
        );
        assert_eq!(
            repository
                .next_grant_generation(Uuid::new_v4(), Uuid::nil())
                .await,
            Err(ClientControlError::InvalidScope)
        );
        assert_eq!(
            repository
                .grant_by_request(Uuid::nil(), Uuid::new_v4(), Uuid::new_v4())
                .await,
            Err(ClientControlError::InvalidScope)
        );
        assert_eq!(
            repository
                .active_grant(
                    Uuid::nil(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Utc::now()
                )
                .await,
            Err(ClientControlError::InvalidScope)
        );
        assert_eq!(
            repository
                .write_grant(&{
                    let mut write = valid_grant_write();
                    write.tenant_id = Uuid::nil();
                    write
                })
                .await,
            // `write_grant` re-runs the structural validation before it opens a
            // transaction, so an incomplete binding is rejected as an invalid
            // record rather than reaching the scope check.
            Err(ClientControlError::InvalidRecord)
        );
    }
}
