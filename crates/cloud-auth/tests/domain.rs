use cloud_auth::domain::{
    AuthorizationSnapshot, DeviceEnrollmentRequest, DeviceStatus, EntitlementSnapshot,
    GrantIssuanceCandidate, GrantIssuanceKey, GrantIssuanceRecord, GrantIssuanceResolution,
    GrantRequest, ServiceClass, SnapshotDevice, SnapshotStatus,
};
use uuid::Uuid;

fn valid_enrollment() -> DeviceEnrollmentRequest {
    DeviceEnrollmentRequest {
        tenant_id: Uuid::new_v4(),
        device_identity: Uuid::new_v4().to_string(),
        display_name: "branch-router-01".into(),
        key_id: "device-key-2026-01".into(),
        operational_public_key: vec![7; 32],
    }
}

#[test]
fn enrollment_accepts_canonical_identity_and_ed25519_public_key() {
    let request = valid_enrollment();

    let enrollment = request
        .clone()
        .complete(Uuid::new_v4())
        .expect("valid enrollment");

    assert_eq!(enrollment.device.tenant_id, request.tenant_id);
    assert_eq!(
        enrollment.device.identity.to_string(),
        request.device_identity
    );
    assert_eq!(enrollment.device.status, DeviceStatus::Pending);
    assert_eq!(enrollment.operational_key.key_id, request.key_id);
    assert_eq!(enrollment.operational_key.public_key.as_slice(), &[7; 32]);
}

#[test]
fn enrollment_rejects_noncanonical_identity() {
    let mut request = valid_enrollment();
    request.device_identity = request.device_identity.to_uppercase();

    let error = request
        .complete(Uuid::new_v4())
        .expect_err("invalid enrollment");

    assert_eq!(error.code(), "invalid_device_identity");
}

#[test]
fn enrollment_rejects_wrong_operational_public_key_size() {
    let mut request = valid_enrollment();
    request.operational_public_key = vec![7; 31];

    let error = request
        .complete(Uuid::new_v4())
        .expect_err("invalid enrollment");

    assert_eq!(error.code(), "invalid_operational_public_key");
}

fn valid_snapshot() -> (AuthorizationSnapshot, Uuid, Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    (
        AuthorizationSnapshot {
            tenant_id,
            authorization_generation: 42,
            device: SnapshotDevice {
                id: device_id,
                tenant_id,
                status: DeviceStatus::Active,
            },
            subscription_status: SnapshotStatus::Active,
            entitlement: EntitlementSnapshot {
                id: Uuid::new_v4(),
                tenant_id,
                node_pool_id,
                service_class: ServiceClass::CandyShared,
                service_permission: "shared.accelerator.connect".into(),
                status: SnapshotStatus::Active,
                generation: 8,
            },
            policy_generation: 12,
            revocation_generation: 19,
        },
        tenant_id,
        device_id,
        node_pool_id,
    )
}

#[test]
fn authorization_snapshot_allows_only_matching_active_device_and_entitlement() {
    let (snapshot, tenant_id, device_id, node_pool_id) = valid_snapshot();
    let request = GrantRequest {
        tenant_id,
        device_id,
        device_key_id: Uuid::new_v4(),
        node_pool_id,
        service_class: ServiceClass::CandyShared,
        service_permission: "shared.accelerator.connect".into(),
    };

    assert!(snapshot.authorize(&request).is_ok());
}

#[test]
fn authorization_snapshot_rejects_cross_service_class_use() {
    let (snapshot, tenant_id, device_id, node_pool_id) = valid_snapshot();
    let request = GrantRequest {
        tenant_id,
        device_id,
        device_key_id: Uuid::new_v4(),
        node_pool_id,
        service_class: ServiceClass::Private,
        service_permission: "shared.accelerator.connect".into(),
    };

    let error = snapshot
        .authorize(&request)
        .expect_err("class mismatch must deny");
    assert_eq!(error.code(), "entitlement_mismatch");
}

fn candidate() -> GrantIssuanceCandidate {
    GrantIssuanceCandidate {
        key: GrantIssuanceKey {
            tenant_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            authorization_generation: 42,
            request_id: "grant-request-0001".into(),
        },
        request_fingerprint: [1; 32],
        signing_key_id: "grant-key-2026-01".into(),
        grant_digest: [2; 32],
        expires_at_unix: 1_800_000_000,
    }
}

#[test]
fn same_idempotency_key_and_fingerprint_replays_record() {
    let candidate = candidate();
    let record =
        GrantIssuanceRecord::from_candidate(Uuid::new_v4(), candidate.clone(), 1_700_000_000)
            .expect("valid record");

    assert_eq!(
        candidate.resolve(Some(&record)).expect("resolution"),
        GrantIssuanceResolution::Replay(record)
    );
}

#[test]
fn reused_idempotency_key_with_different_request_is_rejected() {
    let candidate = candidate();
    let record =
        GrantIssuanceRecord::from_candidate(Uuid::new_v4(), candidate.clone(), 1_700_000_000)
            .expect("valid record");
    let conflicting = GrantIssuanceCandidate {
        request_fingerprint: [3; 32],
        ..candidate
    };

    let error = conflicting
        .resolve(Some(&record))
        .expect_err("idempotency conflict");
    assert_eq!(error.code(), "idempotency_conflict");
}
