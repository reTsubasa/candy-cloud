use std::sync::Arc;

use chrono::{Duration, Utc};
use cloud_auth::{
    certificate_renewal::{CertificateRenewalCommand, CertificateRenewalCoordinator},
    certificates::DeviceCertificateIssuer,
    device_identity::{DeviceIdentityAuthenticator, DeviceIdentityError},
    routes::AuthenticatedDevice,
};
use ed25519_dalek::SigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use sqlx::Row;
use uuid::Uuid;
use x509_parser::parse_x509_certificate;

fn test_ca() -> Arc<DeviceCertificateIssuer> {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Candy Renewal Test CA");
    params.distinguished_name = name;
    let certificate = params.self_signed(&key).unwrap();
    Arc::new(
        DeviceCertificateIssuer::from_pem(
            "device-ca-renewal-test",
            "test",
            &certificate.pem(),
            &key.serialize_pem(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn renewal_reuses_operational_key_and_atomically_supersedes_old_certificate() {
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
    let operational_key = SigningKey::from_bytes(&[41; 32]);
    let operational_public_key = operational_key.verifying_key().to_bytes();
    let issuer = test_ca();
    let old = issuer
        .issue(
            device_id,
            device_key_id,
            operational_public_key,
            1,
            Utc::now() - Duration::days(7) + Duration::hours(1),
        )
        .unwrap();

    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("renew-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("renew-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, 'renew-device', 'ACTIVE')")
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
        .bind(operational_public_key.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_certificates (id, organization_id, tenant_id, device_id, device_key_id, issuer_key_id, serial_number, certificate_der, certificate_chain_pem, san_uri, environment, assurance_level, not_before, not_after, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'ACTIVE')")
        .bind(old_certificate_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id)
        .bind(&old.issuer_key_id)
        .bind(old.serial_number.as_slice())
        .bind(&old.certificate_der)
        .bind(&old.certificate_chain_pem)
        .bind(&old.san_uri)
        .bind(&old.environment)
        .bind(old.not_before)
        .bind(old.not_after)
        .execute(&pool)
        .await
        .unwrap();

    let actor = AuthenticatedDevice::new(
        organization_id,
        tenant_id,
        device_id,
        device_key_id,
        old_certificate_id,
        1,
    )
    .unwrap();
    let request_id = Uuid::new_v4().to_string();
    let coordinator = CertificateRenewalCoordinator::new(pool.clone(), issuer);
    let receipt = coordinator
        .renew(CertificateRenewalCommand {
            actor,
            request_id: request_id.clone(),
        })
        .await
        .unwrap();

    let (_, renewed) = parse_x509_certificate(&receipt.certificate_der).unwrap();
    assert_eq!(
        renewed.public_key().subject_public_key.data.as_ref(),
        operational_public_key
    );
    let rows = sqlx::query("SELECT id, status, revoked_at FROM device_certificates WHERE device_id = ? ORDER BY created_at, id")
        .bind(device_id)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let old_row = rows
        .iter()
        .find(|row| row.get::<Uuid, _>("id") == old_certificate_id)
        .unwrap();
    assert_eq!(old_row.get::<String, _>("status"), "SUPERSEDED");
    assert!(old_row
        .get::<Option<chrono::DateTime<Utc>>, _>("revoked_at")
        .is_some());
    let new_row = rows
        .iter()
        .find(|row| row.get::<Uuid, _>("id") != old_certificate_id)
        .unwrap();
    assert_eq!(new_row.get::<String, _>("status"), "ACTIVE");
    let new_certificate_id = new_row.get::<Uuid, _>("id");

    let authenticator = DeviceIdentityAuthenticator::new(pool.clone(), "test").unwrap();
    assert_eq!(
        authenticator
            .authenticate_verified_certificate(&old.certificate_der, Utc::now())
            .await
            .unwrap_err(),
        DeviceIdentityError::InactiveCertificate
    );
    let renewed_identity = authenticator
        .authenticate_verified_certificate(&receipt.certificate_der, Utc::now())
        .await
        .unwrap();
    assert_eq!(renewed_identity.device_id(), device_id);
    assert_eq!(renewed_identity.device_key_id(), device_key_id);
    assert_eq!(renewed_identity.certificate_id(), new_certificate_id);
    let replay_actor = authenticator
        .authenticate_verified_renewal_certificate(&old.certificate_der, Utc::now())
        .await
        .unwrap();
    let replay = coordinator
        .renew(CertificateRenewalCommand {
            actor: replay_actor.clone(),
            request_id: request_id.clone(),
        })
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.certificate_der, receipt.certificate_der);
    assert_eq!(replay.certificate_chain_pem, receipt.certificate_chain_pem);
    assert_eq!(replay.not_after, receipt.not_after);
    let wrong_replay = coordinator
        .renew(CertificateRenewalCommand {
            actor: replay_actor,
            request_id: Uuid::new_v4().to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        wrong_replay,
        cloud_auth::certificate_renewal::CertificateRenewalError::IdentityChanged
    );
    let not_due = coordinator
        .renew(CertificateRenewalCommand {
            actor: renewed_identity,
            request_id: Uuid::new_v4().to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        not_due,
        cloud_auth::certificate_renewal::CertificateRenewalError::NotDue
    );

    let audit_metadata: String = sqlx::query_scalar("SELECT CAST(metadata_json AS CHAR) FROM audit_events WHERE tenant_id = ? AND action = 'DEVICE_CERTIFICATE_RENEWED' AND object_id = ?")
        .bind(tenant_id)
        .bind(new_certificate_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(audit_metadata.contains(&request_id));
    assert!(audit_metadata.contains(&old_certificate_id.to_string()));
    assert!(audit_metadata.contains(&device_key_id.to_string()));
    let certificate_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_certificates WHERE device_id = ?")
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE tenant_id = ? AND action = 'DEVICE_CERTIFICATE_RENEWED'",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(certificate_count, 2);
    assert_eq!(audit_count, 1);
}
