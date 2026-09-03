use chrono::{Duration, Utc};
use cloud_db::certificate_renewal::{
    CertificateRenewalOutcome, CertificateRenewalRepository, CertificateRenewalWrite,
};
use uuid::Uuid;

#[tokio::test]
async fn renewal_insert_failure_rolls_back_old_certificate_revocation() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let old_certificate_id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("rollback-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("rollback-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, 'rollback-device', 'ACTIVE')")
        .bind(device_id)
        .bind(tenant_id)
        .bind(device_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, assurance_level, status) VALUES (?, ?, ?, ?, ?, 1, 'ACTIVE')")
        .bind(device_key_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id.to_string())
        .bind([7u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_certificates (id, organization_id, tenant_id, device_id, device_key_id, issuer_key_id, serial_number, certificate_der, certificate_chain_pem, san_uri, environment, assurance_level, not_before, not_after, status) VALUES (?, ?, ?, ?, ?, 'old-ca', ?, ?, 'old-chain', ?, 'test', 1, ?, ?, 'ACTIVE')")
        .bind(old_certificate_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id)
        .bind([8u8; 16].as_slice())
        .bind([1u8, 2, 3].as_slice())
        .bind(format!("candy:device:{device_id}"))
        .bind(now - Duration::days(6))
        .bind(now + Duration::days(1))
        .execute(&pool)
        .await
        .unwrap();

    let outcome = CertificateRenewalRepository::new(pool.clone())
        .renew(&CertificateRenewalWrite {
            request_id: Uuid::new_v4().to_string(),
            organization_id,
            tenant_id,
            device_id,
            device_key_id,
            operational_public_key: [7; 32],
            previous_certificate_id: old_certificate_id,
            certificate_id: Uuid::now_v7(),
            issuer_key_id: "old-ca".into(),
            serial_number: [8; 16],
            certificate_der: vec![4, 5, 6],
            certificate_chain_pem: "new-chain".into(),
            san_uri: format!("candy:device:{device_id}"),
            environment: "test".into(),
            assurance_level: 1,
            not_before: now,
            not_after: now + Duration::days(7),
            renewed_at: now,
            replay_until: now + Duration::hours(1),
        })
        .await;
    assert!(outcome.is_err());
    let status: String = sqlx::query_scalar("SELECT status FROM device_certificates WHERE id = ?")
        .bind(old_certificate_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "ACTIVE");
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND action = 'DEVICE_CERTIFICATE_RENEWED'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 0);

    let stale = CertificateRenewalRepository::new(pool)
        .renew(&CertificateRenewalWrite {
            request_id: Uuid::new_v4().to_string(),
            organization_id,
            tenant_id,
            device_id,
            device_key_id,
            operational_public_key: [7; 32],
            previous_certificate_id: Uuid::new_v4(),
            certificate_id: Uuid::now_v7(),
            issuer_key_id: "new-ca".into(),
            serial_number: [9; 16],
            certificate_der: vec![7, 8, 9],
            certificate_chain_pem: "new-chain".into(),
            san_uri: format!("candy:device:{device_id}"),
            environment: "test".into(),
            assurance_level: 1,
            not_before: now,
            not_after: now + Duration::days(7),
            renewed_at: now,
            replay_until: now + Duration::hours(1),
        })
        .await
        .unwrap();
    assert_eq!(stale, CertificateRenewalOutcome::IdentityChanged);
}
