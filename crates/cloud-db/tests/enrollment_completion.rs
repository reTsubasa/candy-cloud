use chrono::{Duration, Utc};
use cloud_db::{
    enrollment::{ActivationCodeWrite, EnrollmentChallengeWrite, EnrollmentRepository},
    enrollment_completion::{
        EnrollmentCompletionOutcome, EnrollmentCompletionRepository, EnrollmentCompletionWrite,
    },
};
use uuid::Uuid;

async fn setup() -> Option<(cloud_db::DbPool, Uuid, Uuid, Uuid)> {
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

    let challenge_id = Uuid::now_v7();
    let mut code_hash = [0; 32];
    code_hash[..16].copy_from_slice(organization_id.as_bytes());
    code_hash[16..].copy_from_slice(tenant_id.as_bytes());
    let enrollment = EnrollmentRepository::new(pool.clone());
    enrollment
        .insert_activation_code(&ActivationCodeWrite {
            id: Uuid::new_v4(),
            organization_id,
            tenant_id,
            code_hash,
            expires_at: Utc::now() + Duration::hours(1),
            created_by: "admin".into(),
        })
        .await
        .unwrap();
    enrollment
        .reserve_challenge(
            &code_hash,
            &EnrollmentChallengeWrite {
                id: challenge_id,
                request_id: format!("challenge-{challenge_id}"),
                request_fingerprint: [1; 32],
                enrollment_instance_id: "bootstrap-instance".into(),
                display_name: "branch-router".into(),
                root_public_key: [2; 32],
                operational_public_key: [3; 32],
                metadata_hash: [4; 32],
                attestation_hash: [5; 32],
                server_nonce: [6; 32],
                assurance_level: 1,
                expires_at: Utc::now() + Duration::minutes(10),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    Some((pool, organization_id, tenant_id, challenge_id))
}

fn completion(
    challenge_id: Uuid,
    organization_id: Uuid,
    tenant_id: Uuid,
) -> EnrollmentCompletionWrite {
    let device_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    let issued_at = Utc::now();
    EnrollmentCompletionWrite {
        challenge_id,
        organization_id,
        tenant_id,
        completion_request_id: format!("complete-{challenge_id}"),
        device_record_id: device_id,
        device_identity: device_id,
        key_record_id: key_id,
        key_id: key_id.to_string(),
        certificate_id: Uuid::now_v7(),
        issuer_key_id: "device-ca-2026-01".into(),
        serial_number: *Uuid::now_v7().as_bytes(),
        certificate_der: vec![0x30, 0x01, 0x00],
        certificate_chain_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
            .into(),
        environment: "production".into(),
        not_before: issued_at,
        not_after: issued_at + Duration::days(7),
        issued_at,
    }
}

#[tokio::test]
async fn completion_atomically_consumes_activation_and_issues_identity() {
    let Some((pool, organization_id, tenant_id, challenge_id)) = setup().await else {
        return;
    };
    let repository = EnrollmentCompletionRepository::new(pool.clone());
    let write = completion(challenge_id, organization_id, tenant_id);

    let issued = repository.complete(&write).await.unwrap();
    assert!(matches!(issued, EnrollmentCompletionOutcome::Issued(_)));
    let replay = repository.complete(&write).await.unwrap();
    assert!(matches!(replay, EnrollmentCompletionOutcome::Replay(_)));

    let challenge_status: String =
        sqlx::query_scalar("SELECT status FROM enrollment_challenges WHERE id = ?")
            .bind(challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let activation_status: String = sqlx::query_scalar(
        "SELECT ac.status FROM enrollment_activation_codes ac JOIN enrollment_challenges ec ON ec.activation_code_id = ac.id WHERE ec.id = ?",
    )
    .bind(challenge_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(challenge_status, "ISSUED");
    assert_eq!(activation_status, "CONSUMED");
}

#[tokio::test]
async fn completion_request_id_cannot_be_reused_with_different_identity_material() {
    let Some((pool, organization_id, tenant_id, challenge_id)) = setup().await else {
        return;
    };
    let repository = EnrollmentCompletionRepository::new(pool);
    let write = completion(challenge_id, organization_id, tenant_id);
    repository.complete(&write).await.unwrap();
    let mut conflicting = write;
    conflicting.device_record_id = Uuid::now_v7();
    conflicting.device_identity = conflicting.device_record_id;

    assert_eq!(
        repository.complete(&conflicting).await.unwrap(),
        EnrollmentCompletionOutcome::Conflict
    );
}

#[tokio::test]
async fn certificate_persistence_failure_rolls_back_proof_and_activation_state() {
    let Some((_pool, first_org, first_tenant, first_challenge)) = setup().await else {
        return;
    };
    let Some((pool, second_org, second_tenant, second_challenge)) = setup().await else {
        return;
    };
    let repository = EnrollmentCompletionRepository::new(pool.clone());
    let first = completion(first_challenge, first_org, first_tenant);
    repository.complete(&first).await.unwrap();
    let mut second = completion(second_challenge, second_org, second_tenant);
    second.certificate_id = first.certificate_id;

    assert!(repository.complete(&second).await.is_err());
    let challenge_status: String =
        sqlx::query_scalar("SELECT status FROM enrollment_challenges WHERE id = ?")
            .bind(second_challenge)
            .fetch_one(&pool)
            .await
            .unwrap();
    let activation_status: String = sqlx::query_scalar(
        "SELECT ac.status FROM enrollment_activation_codes ac JOIN enrollment_challenges ec ON ec.activation_code_id = ac.id WHERE ec.id = ?",
    )
    .bind(second_challenge)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(challenge_status, "CHALLENGED");
    assert_eq!(activation_status, "RESERVED");
}

#[tokio::test]
async fn completion_request_id_is_unique_across_a_tenant() {
    let Some((_pool, organization_id, tenant_id, first_challenge)) = setup().await else {
        return;
    };
    let enrollment = EnrollmentRepository::new(_pool.clone());
    let second_challenge = Uuid::now_v7();
    let mut second_code_hash = [0; 32];
    second_code_hash[..16].copy_from_slice(tenant_id.as_bytes());
    second_code_hash[16..].copy_from_slice(second_challenge.as_bytes());
    enrollment
        .insert_activation_code(&ActivationCodeWrite {
            id: Uuid::new_v4(),
            organization_id,
            tenant_id,
            code_hash: second_code_hash,
            expires_at: Utc::now() + Duration::hours(1),
            created_by: "admin".into(),
        })
        .await
        .unwrap();
    enrollment
        .reserve_challenge(
            &second_code_hash,
            &EnrollmentChallengeWrite {
                id: second_challenge,
                request_id: format!("challenge-{second_challenge}"),
                request_fingerprint: [10; 32],
                enrollment_instance_id: "bootstrap-instance-2".into(),
                display_name: "branch-router-2".into(),
                root_public_key: [11; 32],
                operational_public_key: [12; 32],
                metadata_hash: [13; 32],
                attestation_hash: [14; 32],
                server_nonce: [15; 32],
                assurance_level: 1,
                expires_at: Utc::now() + Duration::minutes(10),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let repository = EnrollmentCompletionRepository::new(_pool);
    let mut first = completion(first_challenge, organization_id, tenant_id);
    first.completion_request_id = "shared-completion-request".into();
    repository.complete(&first).await.unwrap();
    let mut second = completion(second_challenge, organization_id, tenant_id);
    second.completion_request_id = first.completion_request_id.clone();

    assert_eq!(
        repository.complete(&second).await.unwrap(),
        EnrollmentCompletionOutcome::Conflict
    );
}
