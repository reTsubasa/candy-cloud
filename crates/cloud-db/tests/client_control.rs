use chrono::{Duration, Timelike, Utc};
use cloud_db::client_access::ClientTrafficMode;
use cloud_db::client_control::{
    ClientControlError, ClientControlRepository, ClientDeviceKeyRotation,
    ClientDeviceKeyRotationOutcome, ClientDeviceLookup, ClientDeviceRecord,
    ClientDeviceRegistration, ClientDeviceStatus, ClientDeviceStatusOutcome, ClientGrantRecord,
    ClientGrantWrite, ClientPlatform, SetDeviceStatus,
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
        assert_eq!(
            ClientPlatform::from_database_value(&stored.to_lowercase()),
            None
        );
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

#[test]
fn device_status_wire_and_database_spellings_never_bleed_into_each_other() {
    // The column stores upper case and the management contract speaks lower case.
    // Parsing one spelling with the other's parser must fail rather than return a
    // plausible-looking state, because a device silently read as `ACTIVE` is the
    // exact failure this split exists to prevent.
    for (status, database, wire) in [
        (ClientDeviceStatus::Active, "ACTIVE", "active"),
        (ClientDeviceStatus::Suspended, "SUSPENDED", "suspended"),
        (ClientDeviceStatus::Revoked, "REVOKED", "revoked"),
    ] {
        assert_eq!(status.to_database_value(), database);
        assert_eq!(status.to_wire_value(), wire);
        assert_eq!(
            ClientDeviceStatus::from_database_value(database),
            Some(status)
        );
        assert_eq!(ClientDeviceStatus::from_wire_value(wire), Some(status));
        // Crossed over on purpose: neither parser may accept the other's form.
        assert_eq!(ClientDeviceStatus::from_wire_value(database), None);
        assert_eq!(ClientDeviceStatus::from_database_value(wire), None);
    }
    assert_eq!(ClientDeviceStatus::from_wire_value(""), None);
    assert_eq!(ClientDeviceStatus::from_wire_value("suspended "), None);
}

#[test]
fn only_revocation_is_terminal() {
    assert!(ClientDeviceStatus::Revoked.is_terminal());
    assert!(!ClientDeviceStatus::Active.is_terminal());
    assert!(!ClientDeviceStatus::Suspended.is_terminal());
}

#[test]
fn device_status_plan_allows_suspend_and_activate_but_refuses_revocation() {
    use cloud_db::client_control::plan_device_status_change;
    use ClientDeviceStatus::{Active, Revoked, Suspended};

    // Both directions of the supported transition are allowed.
    assert_eq!(
        plan_device_status_change(Active, Suspended),
        Ok(Some(Suspended))
    );
    assert_eq!(
        plan_device_status_change(Suspended, Active),
        Ok(Some(Active))
    );

    // Asking for the state the device is already in is an idempotent replay:
    // `None` means "write nothing", which is what stops a retried operator action
    // from emitting a second audit event.
    assert_eq!(plan_device_status_change(Active, Active), Ok(None));
    assert_eq!(plan_device_status_change(Suspended, Suspended), Ok(None));

    // Revocation is terminal in *both* directions. A revoked device is never
    // resurrected by a status call, and revocation itself is performed by the
    // dedicated revoke path -- never as a side effect of this one.
    for (current, requested) in [
        (Revoked, Revoked),
        (Revoked, Active),
        (Revoked, Suspended),
        (Active, Revoked),
        (Suspended, Revoked),
    ] {
        assert_eq!(
            plan_device_status_change(current, requested),
            Err(ClientControlError::InvalidTransition),
            "{current:?} -> {requested:?} must be refused"
        );
    }
}

#[test]
fn device_status_outcome_reports_state_identity_and_replay_separately() {
    let device_id = Uuid::new_v4();
    let applied = ClientDeviceStatusOutcome::Suspended {
        device_id,
        replayed: false,
    };
    let replayed = ClientDeviceStatusOutcome::Suspended {
        device_id,
        replayed: true,
    };
    let activated = ClientDeviceStatusOutcome::Activated {
        device_id,
        replayed: false,
    };

    // `replayed` must be readable from the outcome rather than inferred by the
    // HTTP layer, and the two directions must not compare equal.
    assert!(!applied.replayed());
    assert!(replayed.replayed());
    assert_ne!(applied, replayed);
    assert_ne!(applied, activated);
    assert_eq!(applied.device_id(), device_id);
    assert_eq!(applied.status(), ClientDeviceStatus::Suspended);
    assert_eq!(activated.status(), ClientDeviceStatus::Active);
}

fn valid_rotation() -> ClientDeviceKeyRotation {
    ClientDeviceKeyRotation {
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        public_key: vec![7; 32],
    }
}

#[test]
fn key_rotation_requires_a_complete_scope_and_usable_key() {
    assert_eq!(valid_rotation().validate(), Ok(()));

    for nil_field in 0..4 {
        let mut rotation = valid_rotation();
        match nil_field {
            0 => rotation.organization_id = Uuid::nil(),
            1 => rotation.tenant_id = Uuid::nil(),
            2 => rotation.device_id = Uuid::nil(),
            _ => rotation.device_key_id = Uuid::nil(),
        }
        assert_eq!(rotation.validate(), Err(ClientControlError::InvalidScope));
    }

    // The window mirrors the `OCTET_LENGTH(public_key) BETWEEN 32 AND 64` CHECK
    // in 0038, so both edges are accepted and both neighbours are refused.
    for len in [32_usize, 33, 64] {
        let mut rotation = valid_rotation();
        rotation.public_key = vec![7; len];
        assert_eq!(rotation.validate(), Ok(()), "len {len} must be accepted");
    }
    for len in [0_usize, 31, 65] {
        let mut rotation = valid_rotation();
        rotation.public_key = vec![7; len];
        assert_eq!(
            rotation.validate(),
            Err(ClientControlError::InvalidPublicKey),
            "len {len} must be refused"
        );
    }

    // An all-zero key is structurally in range but is not a public key any client
    // can prove possession of, so storing it would brick the device.
    let mut zeroed = valid_rotation();
    zeroed.public_key = vec![0; 32];
    assert_eq!(zeroed.validate(), Err(ClientControlError::InvalidPublicKey));
}

#[test]
fn key_rotation_plan_refuses_non_active_devices_and_reused_key_identities() {
    use cloud_db::client_control::plan_device_key_rotation;
    use ClientDeviceStatus::{Active, Revoked, Suspended};

    assert_eq!(plan_device_key_rotation(Active, false), Ok(()));

    // A suspended device must be activated before its key is rotated, and a
    // revoked one is never rotated back into service.
    assert_eq!(
        plan_device_key_rotation(Suspended, false),
        Err(ClientControlError::InvalidTransition)
    );
    assert_eq!(
        plan_device_key_rotation(Revoked, false),
        Err(ClientControlError::InvalidTransition)
    );

    // A `device_key_id` is unique per tenant because it names a Projection
    // audience. Reusing one would make two keys indistinguishable, so it is a
    // conflict even when the caller believes it is retrying a rotation.
    assert_eq!(
        plan_device_key_rotation(Active, true),
        Err(ClientControlError::BindingConflict)
    );
    // The non-active case is decided first: a rotation against a suspended device
    // is a state conflict regardless of the key identity.
    assert_eq!(
        plan_device_key_rotation(Suspended, true),
        Err(ClientControlError::InvalidTransition)
    );
}

#[test]
fn key_rotation_is_never_reported_as_replayed() {
    let outcome = ClientDeviceKeyRotationOutcome::Rotated {
        device_id: Uuid::new_v4(),
        previous_device_key_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        revoked_grants: 2,
        revoked_projections: 1,
        replayed: false,
    };
    assert!(!outcome.replayed());
    let ClientDeviceKeyRotationOutcome::Rotated {
        previous_device_key_id,
        device_key_id,
        revoked_grants,
        revoked_projections,
        replayed,
        ..
    } = outcome;
    // The counters exist so an operator (and a test) can prove the old key's
    // authorization really was retired rather than left verifiable.
    assert_ne!(previous_device_key_id, device_key_id);
    assert_eq!(revoked_grants, 2);
    assert_eq!(revoked_projections, 1);
    assert!(!replayed);
}

#[test]
fn device_status_scope_has_no_user_dimension() {
    let scope = SetDeviceStatus {
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        new_status: ClientDeviceStatus::Suspended,
    };
    assert_eq!(scope.validate(), Ok(()));

    for nil_field in 0..3 {
        let mut scope = scope;
        match nil_field {
            0 => scope.organization_id = Uuid::nil(),
            1 => scope.tenant_id = Uuid::nil(),
            _ => scope.device_id = Uuid::nil(),
        }
        assert_eq!(scope.validate(), Err(ClientControlError::InvalidScope));
    }
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
        traffic_mode: ClientTrafficMode::Policy,
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
        assignment_lease_until: issued_at + Duration::minutes(5),
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
    assert_eq!(inverted.validate(), Err(ClientControlError::InvalidRecord));

    let mut zero_width = valid_grant_write();
    zero_width.expires_at = zero_width.issued_at;
    assert_eq!(
        zero_width.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    // The recorded assignment lease has to describe the same window the signed
    // payload validator accepts: strictly after `issued_at`, never past
    // `expires_at`. A zero-width or inverted lease is refused here so Cloud can
    // never store a Grant whose own validator would reject the envelope.
    let mut lease_at_issue = valid_grant_write();
    lease_at_issue.assignment_lease_until = lease_at_issue.issued_at;
    assert_eq!(
        lease_at_issue.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut lease_before_issue = valid_grant_write();
    lease_before_issue.assignment_lease_until = lease_before_issue.issued_at - Duration::seconds(1);
    assert_eq!(
        lease_before_issue.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut lease_past_expiry = valid_grant_write();
    lease_past_expiry.assignment_lease_until = lease_past_expiry.expires_at + Duration::seconds(1);
    assert_eq!(
        lease_past_expiry.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    // The lease may equal `expires_at`: that is the clamped window Cloud signs
    // when the configured lease is longer than the Grant it fits inside.
    let mut lease_at_expiry = valid_grant_write();
    lease_at_expiry.assignment_lease_until = lease_at_expiry.expires_at;
    assert_eq!(lease_at_expiry.validate(), Ok(()));
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
        assignment_lease_until: Some(write.assignment_lease_until),
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

    // `None` is the pre-`0047` row: no recorded lease, still a readable record.
    let mut no_lease = valid_grant_record();
    no_lease.assignment_lease_until = None;
    assert_eq!(no_lease.validate(), Ok(()));

    // A recorded lease must not describe a window the payload validator forbids.
    let mut lease_at_issue = valid_grant_record();
    lease_at_issue.assignment_lease_until = Some(lease_at_issue.issued_at);
    assert_eq!(
        lease_at_issue.validate(),
        Err(ClientControlError::InvalidRecord)
    );

    let mut lease_past_expiry = valid_grant_record();
    lease_past_expiry.assignment_lease_until =
        Some(lease_past_expiry.expires_at + Duration::seconds(1));
    assert_eq!(
        lease_past_expiry.validate(),
        Err(ClientControlError::InvalidRecord)
    );
}
/// Repository reads validate their scope before building a query, so a caller
/// with an incomplete identity tuple is refused without any database round trip.
/// These are deliberately run against a lazy pool: reaching storage would hang or
/// fail, which is exactly what proves the check happens first.
mod scope_checks {
    use super::*;

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
                .active_grant(Uuid::nil(), Uuid::new_v4(), Uuid::new_v4(), Utc::now())
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

    #[tokio::test]
    async fn device_status_change_refuses_an_incomplete_scope() {
        let repository = repository();
        for (organization, tenant, device) in [
            (Uuid::nil(), Uuid::new_v4(), Uuid::new_v4()),
            (Uuid::new_v4(), Uuid::nil(), Uuid::new_v4()),
            (Uuid::new_v4(), Uuid::new_v4(), Uuid::nil()),
        ] {
            assert_eq!(
                repository
                    .set_device_status(organization, tenant, device, ClientDeviceStatus::Suspended)
                    .await,
                Err(ClientControlError::InvalidScope)
            );
        }
    }

    #[tokio::test]
    async fn key_rotation_refuses_an_incomplete_scope_and_an_unusable_key() {
        let repository = repository();
        for nil_field in 0..3 {
            let mut rotation = valid_rotation();
            match nil_field {
                0 => rotation.organization_id = Uuid::nil(),
                1 => rotation.tenant_id = Uuid::nil(),
                _ => rotation.device_id = Uuid::nil(),
            }
            assert_eq!(
                repository.rotate_device_key(&rotation).await,
                Err(ClientControlError::InvalidScope)
            );
        }

        // The key check precedes the scope check inside `validate`, so an
        // oversized key on a *complete* scope is still refused without storage.
        let mut oversized = valid_rotation();
        oversized.public_key = vec![7; 65];
        assert_eq!(
            repository.rotate_device_key(&oversized).await,
            Err(ClientControlError::InvalidPublicKey)
        );
    }
}

/// Live-database round trip for the recorded assignment lease (migration `0047`).
///
/// Skipped entirely when `DATABASE_URL` is unset, which is the case on a machine
/// with no MySQL runtime: the pure-logic coverage above is what the default
/// `cargo test` run actually exercises, and nothing here claims otherwise. CI
/// provides MySQL 8.4 and a `DATABASE_URL`, so this is the run that proves the
/// column is written and read back rather than only type-checked.
#[tokio::test]
async fn a_written_grant_records_and_reads_back_its_assignment_lease() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let repository = ClientControlRepository::new(pool.clone());

    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("lease-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO human_users (id, email_normalized, display_name, password_hash, status) VALUES (?, ?, ?, 'unused', 'ACTIVE')")
        .bind(user_id)
        .bind(format!("{user_id}@lease.example.test"))
        .bind("Lease Tester")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role, status) VALUES (?, ?, 'ORGANIZATION_OWNER', 'ACTIVE')")
        .bind(organization_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("lease-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();

    // `write_grant` requires an ACTIVE key row for the exact binding, so the
    // device goes through the real registration path rather than raw inserts.
    let mut registration = valid_request();
    registration.organization_id = organization_id;
    registration.tenant_id = tenant_id;
    registration.user_id = user_id;
    registration.actor_id = user_id;
    registration.install_id = format!("lease-install-{tenant_id}");
    repository.register_device(&registration).await.unwrap();

    // Deliberately use nanosecond precision: the persistence boundary must
    // canonicalize it to MySQL TIMESTAMP(6) precision before storing.
    let issued_at = Utc::now();
    let issued_at = issued_at
        .with_nanosecond(issued_at.timestamp_subsec_nanos() / 1_000 * 1_000 + 903)
        .unwrap();
    let expires_at = issued_at + Duration::hours(24);
    let lease_until = issued_at + Duration::hours(1);
    let mut write = valid_grant_write();
    write.organization_id = organization_id;
    write.tenant_id = tenant_id;
    write.user_id = user_id;
    write.client_device_id = registration.record_id;
    write.device_key_id = registration.device_key_id;
    write.issued_at = issued_at;
    write.expires_at = expires_at;
    write.assignment_lease_until = lease_until;
    repository.write_grant(&write).await.unwrap();

    // The read path the reuse decision uses must see the recorded deadline.
    let active = repository
        .active_grant(
            tenant_id,
            registration.record_id,
            registration.device_key_id,
            issued_at,
        )
        .await
        .unwrap()
        .expect("the just-written Grant is active");
    let canonical_lease_until = lease_until
        .with_nanosecond(lease_until.nanosecond() / 1_000 * 1_000)
        .unwrap();
    assert_eq!(active.assignment_lease_until, Some(canonical_lease_until));

    // And the idempotent read path used for replay must agree byte for byte.
    let by_request = repository
        .grant_by_request(tenant_id, registration.record_id, write.request_id)
        .await
        .unwrap()
        .expect("the just-written Grant is readable by request");
    assert_eq!(
        by_request.assignment_lease_until,
        Some(canonical_lease_until)
    );
    assert_eq!(by_request.grant_envelope, active.grant_envelope);

    // A historical row written before `0047` has no lease value; inserting one
    // directly is how the "no evidence" path is reproduced without rewriting the
    // migration. The read must surface `None`, not an error or a guessed value.
    let legacy_request = Uuid::new_v4();
    sqlx::query("INSERT INTO client_grants (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_id, request_hash, signing_key_id, grant_digest, grant_envelope, issued_at, expires_at, status, assignment_lease_until) VALUES (?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', NULL)")
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(registration.record_id)
        .bind(registration.device_key_id)
        .bind(legacy_request)
        .bind([9_u8; 32].as_slice())
        .bind("cloud-client-grant-2026-01")
        .bind([10_u8; 32].as_slice())
        .bind(vec![4_u8, 5, 6])
        .bind(issued_at)
        .bind(expires_at)
        .execute(&pool)
        .await
        .unwrap();
    let legacy = repository
        .grant_by_request(tenant_id, registration.record_id, legacy_request)
        .await
        .unwrap()
        .expect("the legacy row is readable");
    assert_eq!(legacy.assignment_lease_until, None);
}
