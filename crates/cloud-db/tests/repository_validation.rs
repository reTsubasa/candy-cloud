use chrono::{Duration, TimeZone, Utc};
use cloud_db::repositories::{
    AuditEvent, AuditRepository, DeviceLookup, GrantIssuanceRepository, GrantIssuanceWrite,
    LeaseAcquireRequest, RepositoryError,
};
use uuid::Uuid;

#[test]
fn device_lookup_requires_tenant_and_canonical_identity() {
    let tenant_id = Uuid::new_v4();
    let identity = Uuid::new_v4().to_string();

    let lookup = DeviceLookup::new(tenant_id, identity.clone()).expect("valid lookup");

    assert_eq!(lookup.tenant_id(), tenant_id);
    assert_eq!(lookup.device_identity(), identity);
    assert_eq!(
        DeviceLookup::new(Uuid::nil(), identity)
            .expect_err("nil tenant must fail")
            .code(),
        "invalid_tenant_id"
    );
}

#[test]
fn device_lookup_rejects_noncanonical_identity() {
    let identity = Uuid::new_v4().to_string().to_uppercase();

    assert_eq!(
        DeviceLookup::new(Uuid::new_v4(), identity)
            .expect_err("noncanonical identity must fail")
            .code(),
        "invalid_device_identity"
    );
}

#[test]
fn lease_request_is_bounded_and_requires_future_expiry() {
    let now = Utc.with_ymd_and_hms(2026, 7, 29, 12, 0, 0).unwrap();
    let request =
        LeaseAcquireRequest::new("grant-refresh", "worker-a", now, now + Duration::minutes(1))
            .expect("valid request");

    assert_eq!(request.lease_name(), "grant-refresh");
    assert_eq!(request.owner_id(), "worker-a");
    assert_eq!(request.expires_at(), now + Duration::minutes(1));
    assert_eq!(
        LeaseAcquireRequest::new("", "worker-a", now, now + Duration::minutes(1))
            .expect_err("empty lease name must fail")
            .code(),
        "invalid_lease_name"
    );
    assert_eq!(
        LeaseAcquireRequest::new("grant-refresh", "worker-a", now, now)
            .expect_err("nonfuture expiry must fail")
            .code(),
        "invalid_lease_expiry"
    );
    assert_eq!(
        LeaseAcquireRequest::new(
            "grant-refresh",
            "x".repeat(121),
            now,
            now + Duration::minutes(1),
        )
        .expect_err("oversized owner must fail")
        .code(),
        "invalid_lease_owner"
    );
}

#[tokio::test]
async fn audit_write_rejects_missing_scope_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = AuditRepository::new(pool);
    let event = AuditEvent {
        id: Uuid::new_v4(),
        organization_id: Uuid::nil(),
        tenant_id: Uuid::new_v4(),
        actor_type: "USER".into(),
        actor_id: "admin".into(),
        action: "DEVICE_CREATE".into(),
        object_type: "DEVICE".into(),
        object_id: "device-1".into(),
        metadata_json: "{}".into(),
    };
    assert!(matches!(
        repository.append(&event).await,
        Err(RepositoryError::InvalidAuditScope)
    ));
}

#[tokio::test]
async fn grant_record_rejects_missing_scope_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = GrantIssuanceRepository::new(pool);
    let write = GrantIssuanceWrite {
        id: Uuid::new_v4(),
        tenant_id: Uuid::nil(),
        device_id: Uuid::new_v4(),
        request_id: "refresh-1".into(),
        authorization_generation: 1,
        request_fingerprint: [1; 32],
        key_id: "k1".into(),
        grant_digest: [2; 32],
        expires_at: Utc::now() + Duration::hours(24),
    };
    assert!(matches!(
        repository.record(&write).await,
        Err(RepositoryError::InvalidGrantScope)
    ));
}
