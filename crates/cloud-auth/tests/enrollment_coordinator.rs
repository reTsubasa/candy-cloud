use chrono::{Duration, Utc};
use cloud_auth::{
    certificates::DeviceCertificateIssuer,
    device_identity::{DeviceIdentityAuthenticator, DeviceIdentityError},
    enrollment::{
        hash_activation_credential, EnrollmentChallengeCommand, EnrollmentCompleteCommand,
        EnrollmentCoordinator, EnrollmentCoordinatorError,
    },
    enrollment_crypto::EnrollmentTranscript,
};
use cloud_db::enrollment::{ActivationCodeWrite, EnrollmentRepository};
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use uuid::Uuid;

fn test_ca() -> DeviceCertificateIssuer {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Candy Test Device Intermediate");
    params.distinguished_name = name;
    let certificate = params.self_signed(&key).unwrap();
    DeviceCertificateIssuer::from_pem(
        "device-ca-test-1",
        "test",
        &certificate.pem(),
        &key.serialize_pem(),
    )
    .unwrap()
}

async fn setup() -> Option<(cloud_db::DbPool, Uuid, [u8; 32])> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    let mut credential = [0; 32];
    credential[..16].copy_from_slice(organization_id.as_bytes());
    credential[16..].copy_from_slice(tenant_id.as_bytes());
    EnrollmentRepository::new(pool.clone())
        .insert_activation_code(&ActivationCodeWrite {
            id: Uuid::new_v4(),
            organization_id,
            tenant_id,
            site_id: None,
            requested_display_name: None,
            requested_platform: None,
            requested_architecture: None,
            code_hash: hash_activation_credential(&credential),
            expires_at: Utc::now() + Duration::hours(1),
            created_by: "admin".into(),
        })
        .await
        .unwrap();
    Some((pool, organization_id, credential))
}

#[tokio::test]
async fn challenge_and_complete_issue_one_replayable_device_identity() {
    let Some((pool, organization_id, credential)) = setup().await else {
        return;
    };
    let operational_key = SigningKey::from_bytes(&[7; 32]);
    let coordinator = EnrollmentCoordinator::new(pool.clone(), test_ca());
    let challenge_command = EnrollmentChallengeCommand {
        activation_credential: credential,
        request_id: format!("challenge-{}", Uuid::new_v4()),
        enrollment_instance_id: "installer-1".into(),
        display_name: "branch-router-1".into(),
        root_public_key: [8; 32],
        operational_public_key: operational_key.verifying_key().to_bytes(),
        metadata_hash: [9; 32],
        attestation_hash: [10; 32],
    };
    let challenge = coordinator
        .challenge(challenge_command.clone())
        .await
        .unwrap();
    let challenge_replay = coordinator.challenge(challenge_command).await.unwrap();
    assert_eq!(challenge.organization_id, organization_id);
    assert!(!challenge.replayed);
    assert!(challenge_replay.replayed);
    assert_eq!(challenge_replay.challenge_id, challenge.challenge_id);
    assert_eq!(challenge_replay.server_nonce, challenge.server_nonce);

    let operational_public_key = operational_key.verifying_key().to_bytes();
    let transcript = EnrollmentTranscript::new(
        challenge.challenge_id,
        &challenge.server_nonce,
        &[8; 32],
        &operational_public_key,
        challenge.organization_id,
        &[9; 32],
        &[10; 32],
    )
    .unwrap();
    let proof = operational_key
        .sign(&transcript.encode().unwrap())
        .to_bytes();
    let command = EnrollmentCompleteCommand {
        challenge_id: challenge.challenge_id,
        request_id: format!("complete-{}", challenge.challenge_id),
        operational_proof: proof,
    };

    let issued = coordinator.complete(command.clone()).await.unwrap();
    let replayed = coordinator.complete(command).await.unwrap();

    assert!(!issued.replayed);
    assert!(replayed.replayed);
    assert_eq!(replayed.device_id, issued.device_id);
    assert_eq!(replayed.device_key_id, issued.device_key_id);
    assert_eq!(replayed.certificate_der, issued.certificate_der);
    assert_eq!(replayed.certificate_chain_pem, issued.certificate_chain_pem);
    assert_eq!(replayed.not_after, issued.not_after);

    let authenticator = DeviceIdentityAuthenticator::new(pool.clone(), "test").unwrap();
    let identity = authenticator
        .authenticate_verified_certificate(&issued.certificate_der, Utc::now())
        .await
        .unwrap();
    assert_eq!(identity.organization_id(), organization_id);
    assert_eq!(identity.device_id(), issued.device_id);
    assert_eq!(identity.device_key_id(), issued.device_key_id);
    assert_eq!(identity.assurance_level(), 1);
    let wrong_environment = DeviceIdentityAuthenticator::new(pool.clone(), "production").unwrap();
    assert_eq!(
        wrong_environment
            .authenticate_verified_certificate(&issued.certificate_der, Utc::now())
            .await
            .unwrap_err(),
        DeviceIdentityError::InvalidCertificate
    );

    sqlx::query(
        "UPDATE device_certificates SET status = 'REVOKED', revoked_at = ? WHERE device_id = ?",
    )
    .bind(Utc::now())
    .bind(issued.device_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        authenticator
            .authenticate_verified_certificate(&issued.certificate_der, Utc::now())
            .await
            .unwrap_err(),
        DeviceIdentityError::InactiveCertificate
    );

    let mut altered_certificate = issued.certificate_der;
    altered_certificate[0] ^= 1;
    assert_eq!(
        authenticator
            .authenticate_verified_certificate(&altered_certificate, Utc::now())
            .await
            .unwrap_err(),
        DeviceIdentityError::InvalidCertificate
    );
}

#[tokio::test]
async fn invalid_operational_proof_does_not_consume_the_challenge() {
    let Some((pool, _organization_id, credential)) = setup().await else {
        return;
    };
    let operational_key = SigningKey::from_bytes(&[11; 32]);
    let coordinator = EnrollmentCoordinator::new(pool.clone(), test_ca());
    let challenge = coordinator
        .challenge(EnrollmentChallengeCommand {
            activation_credential: credential,
            request_id: format!("challenge-{}", Uuid::new_v4()),
            enrollment_instance_id: "installer-2".into(),
            display_name: "branch-router-2".into(),
            root_public_key: [12; 32],
            operational_public_key: operational_key.verifying_key().to_bytes(),
            metadata_hash: [13; 32],
            attestation_hash: [14; 32],
        })
        .await
        .unwrap();

    let error = coordinator
        .complete(EnrollmentCompleteCommand {
            challenge_id: challenge.challenge_id,
            request_id: format!("complete-{}", challenge.challenge_id),
            operational_proof: [0; 64],
        })
        .await
        .unwrap_err();

    assert_eq!(error, EnrollmentCoordinatorError::ProofRejected);
    let status: String =
        sqlx::query_scalar("SELECT status FROM enrollment_challenges WHERE id = ?")
            .bind(challenge.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "CHALLENGED");
}
