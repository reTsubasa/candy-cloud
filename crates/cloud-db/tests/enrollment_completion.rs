use chrono::{Duration, Utc};
use cloud_db::{
    enrollment::{ActivationCodeWrite, EnrollmentChallengeWrite, EnrollmentRepository},
    enrollment_completion::{
        EnrollmentCompletionOutcome, EnrollmentCompletionRepository, EnrollmentCompletionWrite,
    },
};
use serde_json::json;
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
            site_id: None,
            requested_display_name: None,
            requested_platform: None,
            requested_architecture: None,
            replace_node_id: None,
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

    let activations = EnrollmentRepository::new(pool)
        .list_activation_codes(tenant_id, Utc::now())
        .await
        .unwrap();
    let activation = activations
        .into_iter()
        .find(|item| item.status == "CONSUMED")
        .unwrap();
    assert_eq!(activation.display_name.as_deref(), Some("branch-router"));
    assert_eq!(activation.device_id, Some(write.device_record_id));
    assert_eq!(activation.device_key_id, Some(write.key_record_id));
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
            site_id: None,
            requested_display_name: None,
            requested_platform: None,
            requested_architecture: None,
            replace_node_id: None,
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

#[tokio::test]
async fn reenrollment_rotates_identity_without_replacing_the_control_node() {
    let Some((pool, organization_id, tenant_id, _)) = setup().await else {
        return;
    };
    let site_id = Uuid::now_v7();
    let control_node_id = Uuid::now_v7();
    let old_device_id = Uuid::now_v7();
    let old_key_id = Uuid::now_v7();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, 'old-node', 'ACTIVE')")
        .bind(old_device_id)
        .bind(tenant_id)
        .bind(old_device_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, assurance_level, status) VALUES (?, ?, ?, ?, ?, 1, 'ACTIVE')")
        .bind(old_key_id)
        .bind(tenant_id)
        .bind(old_device_id)
        .bind(old_key_id.to_string())
        .bind([9u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    for (kind, id, document) in [
        (
            "SITE",
            site_id,
            json!({"metadata":{"schema_version":1,"id":site_id,"tenant_id":tenant_id,"revision":1,"state":"ACTIVE"},"resource":{"kind":"SITE","spec":{"name":"Branch","kind":"EDGE"}}}),
        ),
        (
            "NODE",
            control_node_id,
            json!({"metadata":{"schema_version":1,"id":control_node_id,"tenant_id":tenant_id,"revision":1,"state":"ACTIVE"},"resource":{"kind":"NODE","spec":{"device_id":old_device_id,"device_key_id":old_key_id,"site_id":site_id,"display_name":"Branch Router","platform":"OPEN_WRT","architecture":"armv7"}}}),
        ),
    ] {
        sqlx::query("INSERT INTO sdwan_control_resources (tenant_id, resource_kind, id, revision, state, document_hash, document_json, created_by, updated_by) VALUES (?, ?, ?, 1, 'ACTIVE', ?, CAST(? AS JSON), 'test', 'test')")
            .bind(tenant_id)
            .bind(kind)
            .bind(id)
            .bind([7u8; 32].as_slice())
            .bind(document.to_string())
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO sdwan_control_resource_references (tenant_id, source_kind, source_id, target_kind, target_id) VALUES (?, 'NODE', ?, 'SITE', ?)")
        .bind(tenant_id)
        .bind(control_node_id)
        .bind(site_id)
        .execute(&pool)
        .await
        .unwrap();

    let activation_id = Uuid::now_v7();
    let challenge_id = Uuid::now_v7();
    let mut code_hash = [0u8; 32];
    code_hash[..16].copy_from_slice(activation_id.as_bytes());
    code_hash[16..].copy_from_slice(challenge_id.as_bytes());
    let enrollment = EnrollmentRepository::new(pool.clone());
    enrollment
        .insert_activation_code(&ActivationCodeWrite {
            id: activation_id,
            organization_id,
            tenant_id,
            site_id: Some(site_id),
            requested_display_name: Some("Branch Router".into()),
            requested_platform: Some("OPEN_WRT".into()),
            requested_architecture: Some("armv7".into()),
            replace_node_id: Some(control_node_id),
            code_hash,
            expires_at: Utc::now() + Duration::minutes(10),
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
                request_fingerprint: [21; 32],
                enrollment_instance_id: "replacement-installation".into(),
                display_name: "Branch Router".into(),
                root_public_key: [22; 32],
                operational_public_key: [23; 32],
                metadata_hash: [24; 32],
                attestation_hash: [25; 32],
                server_nonce: [26; 32],
                assurance_level: 1,
                expires_at: Utc::now() + Duration::minutes(10),
            },
            Utc::now(),
        )
        .await
        .unwrap();
    let write = completion(challenge_id, organization_id, tenant_id);
    assert!(matches!(
        EnrollmentCompletionRepository::new(pool.clone())
            .complete(&write)
            .await
            .unwrap(),
        EnrollmentCompletionOutcome::Issued(_)
    ));

    let (revision, document): (u64, String) = sqlx::query_as("SELECT revision, CAST(document_json AS CHAR) FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND id = ?")
        .bind(tenant_id)
        .bind(control_node_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(revision, 2);
    assert!(document.contains(&write.device_record_id.to_string()));
    assert!(document.contains(&write.key_record_id.to_string()));
    let old_device_status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = ?")
        .bind(old_device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let old_key_status: String = sqlx::query_scalar("SELECT status FROM device_keys WHERE id = ?")
        .bind(old_key_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(old_device_status, "REVOKED");
    assert_eq!(old_key_status, "REVOKED");
    let reference_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sdwan_control_resource_references WHERE tenant_id = ? AND source_kind = 'NODE' AND source_id = ? AND target_kind = 'SITE' AND target_id = ?")
        .bind(tenant_id)
        .bind(control_node_id)
        .bind(site_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reference_count, 1);
}
