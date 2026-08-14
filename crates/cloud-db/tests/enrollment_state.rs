use chrono::{Duration, Utc};
use cloud_db::enrollment::{
    ActivationCodeOutcome, ActivationCodeWrite, BootstrapExchangeWrite, BootstrapManifestOutcome,
    ChallengeCreationOutcome, EnrollmentChallengeWrite, EnrollmentRepository,
};
use sha2::Digest;
use uuid::Uuid;

async fn test_repository() -> Option<(cloud_db::DbPool, EnrollmentRepository, Uuid, Uuid)> {
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
    let repository = EnrollmentRepository::new(pool.clone());
    Some((pool, repository, organization_id, tenant_id))
}

async fn insert_site(pool: &cloud_db::DbPool, tenant_id: Uuid) -> Uuid {
    let site_id = Uuid::new_v4();
    let document = serde_json::json!({
        "metadata": {
            "schema_version": 1,
            "id": site_id,
            "tenant_id": tenant_id,
            "revision": 1,
            "state": "ACTIVE"
        },
        "resource": { "kind": "SITE", "spec": { "name": "Test site" } }
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let document_hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    sqlx::query("INSERT INTO sdwan_control_resources (tenant_id, resource_kind, id, revision, state, document_hash, document_json, created_by, updated_by) VALUES (?, 'SITE', ?, 1, 'ACTIVE', ?, ?, 'test', 'test')")
        .bind(tenant_id)
        .bind(site_id)
        .bind(document_hash.as_slice())
        .bind(String::from_utf8(bytes).unwrap())
        .execute(pool)
        .await
        .unwrap();
    site_id
}

fn bootstrap_activation(
    organization_id: Uuid,
    tenant_id: Uuid,
    site_id: Uuid,
    code_hash: [u8; 32],
) -> ActivationCodeWrite {
    ActivationCodeWrite {
        id: Uuid::new_v4(),
        organization_id,
        tenant_id,
        site_id: Some(site_id),
        requested_display_name: Some("Tokyo edge".into()),
        requested_platform: Some("LINUX".into()),
        requested_architecture: Some("aarch64".into()),
        code_hash,
        expires_at: Utc::now() + Duration::minutes(10),
        created_by: "admin-1".into(),
    }
}

#[tokio::test]
async fn bootstrap_exchange_is_single_device_and_idempotent() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let site_id = insert_site(&pool, tenant_id).await;
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&bootstrap_activation(
            organization_id,
            tenant_id,
            site_id,
            code_hash,
        ))
        .await
        .unwrap();
    let write = BootstrapExchangeWrite {
        installation_instance_id: "linux-install-1".into(),
        enrollment_credential_hash: [41; 32],
    };

    let first = repository
        .exchange_bootstrap_code(&code_hash, &write, Utc::now())
        .await
        .unwrap();
    let replay = repository
        .exchange_bootstrap_code(&code_hash, &write, Utc::now())
        .await
        .unwrap();
    let other_instance = repository
        .exchange_bootstrap_code(
            &code_hash,
            &BootstrapExchangeWrite {
                installation_instance_id: "linux-install-2".into(),
                enrollment_credential_hash: [42; 32],
            },
            Utc::now(),
        )
        .await
        .unwrap();

    assert_eq!(first.0, BootstrapManifestOutcome::Issued);
    assert_eq!(first.1.unwrap().site_id, site_id);
    assert_eq!(replay.0, BootstrapManifestOutcome::Replay);
    assert_eq!(other_instance.0, BootstrapManifestOutcome::Conflict);
}

#[tokio::test]
async fn bootstrap_exchange_rejects_expired_and_legacy_codes() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let site_id = insert_site(&pool, tenant_id).await;
    let expired_hash = unique_code_hash(organization_id, site_id);
    let mut expired = bootstrap_activation(organization_id, tenant_id, site_id, expired_hash);
    expired.expires_at = Utc::now() + Duration::seconds(1);
    repository.insert_activation_code(&expired).await.unwrap();
    let legacy_hash = [44; 32];
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, legacy_hash))
        .await
        .unwrap();
    let write = BootstrapExchangeWrite {
        installation_instance_id: "linux-install-1".into(),
        enrollment_credential_hash: [43; 32],
    };

    let expired_result = repository
        .exchange_bootstrap_code(&expired_hash, &write, Utc::now() + Duration::seconds(2))
        .await
        .unwrap();
    let legacy_result = repository
        .exchange_bootstrap_code(&legacy_hash, &write, Utc::now())
        .await
        .unwrap();

    assert_eq!(expired_result.0, BootstrapManifestOutcome::Unavailable);
    assert_eq!(legacy_result.0, BootstrapManifestOutcome::Unavailable);
    assert!(legacy_result.1.is_none());
}

#[tokio::test]
async fn bootstrap_exchange_rejects_unsafe_installation_instance_ids() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let site_id = insert_site(&pool, tenant_id).await;
    let code_hash = unique_code_hash(organization_id, site_id);
    repository
        .insert_activation_code(&bootstrap_activation(
            organization_id,
            tenant_id,
            site_id,
            code_hash,
        ))
        .await
        .unwrap();

    let result = repository
        .exchange_bootstrap_code(
            &code_hash,
            &BootstrapExchangeWrite {
                installation_instance_id: "install instance/1".into(),
                enrollment_credential_hash: [45; 32],
            },
            Utc::now(),
        )
        .await;

    assert!(result.is_err());
}

fn activation(organization_id: Uuid, tenant_id: Uuid, code_hash: [u8; 32]) -> ActivationCodeWrite {
    ActivationCodeWrite {
        id: Uuid::new_v4(),
        organization_id,
        tenant_id,
        site_id: None,
        requested_display_name: None,
        requested_platform: None,
        requested_architecture: None,
        code_hash,
        expires_at: Utc::now() + Duration::hours(1),
        created_by: "admin-1".into(),
    }
}

fn unique_code_hash(organization_id: Uuid, tenant_id: Uuid) -> [u8; 32] {
    let mut hash = [0; 32];
    hash[..16].copy_from_slice(organization_id.as_bytes());
    hash[16..].copy_from_slice(tenant_id.as_bytes());
    hash
}

fn challenge(request_id: &str) -> EnrollmentChallengeWrite {
    EnrollmentChallengeWrite {
        id: Uuid::now_v7(),
        request_id: request_id.into(),
        request_fingerprint: [8; 32],
        enrollment_instance_id: "bootstrap-instance-1".into(),
        display_name: "branch-router-1".into(),
        root_public_key: [2; 32],
        operational_public_key: [3; 32],
        metadata_hash: [4; 32],
        attestation_hash: [5; 32],
        server_nonce: [6; 32],
        assurance_level: 1,
        expires_at: Utc::now() + Duration::minutes(10),
    }
}

#[tokio::test]
async fn activation_code_is_reserved_once_and_same_request_replays() {
    let Some((_pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    let activation = activation(organization_id, tenant_id, code_hash);
    assert_eq!(
        repository
            .insert_activation_code(&activation)
            .await
            .unwrap(),
        ActivationCodeOutcome::Inserted
    );
    let write = challenge("challenge-request-1");

    let created = repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();
    let replayed = repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    assert!(matches!(created, ChallengeCreationOutcome::Created(_)));
    assert!(matches!(replayed, ChallengeCreationOutcome::Replay(_)));
}

#[tokio::test]
async fn reserved_activation_code_cannot_start_a_second_challenge() {
    let Some((_pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    repository
        .reserve_challenge(&code_hash, &challenge("challenge-request-1"), Utc::now())
        .await
        .unwrap();

    let outcome = repository
        .reserve_challenge(&code_hash, &challenge("challenge-request-2"), Utc::now())
        .await
        .unwrap();

    assert_eq!(outcome, ChallengeCreationOutcome::ActivationUnavailable);
}

#[tokio::test]
async fn replay_still_requires_the_original_activation_credential() {
    let Some((_pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    let write = challenge("challenge-request-replay-auth");
    repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    let outcome = repository
        .reserve_challenge(&[14; 32], &write, Utc::now())
        .await
        .unwrap();

    assert_eq!(outcome, ChallengeCreationOutcome::ActivationUnavailable);
}

#[tokio::test]
async fn challenge_scope_is_derived_from_the_activation_credential() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    let write = challenge("challenge-request-derived-scope");
    let outcome = repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();
    let stored_scope: (Uuid, Uuid) =
        sqlx::query_as("SELECT organization_id, tenant_id FROM enrollment_challenges WHERE id = ?")
            .bind(write.id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(matches!(outcome, ChallengeCreationOutcome::Created(_)));
    assert_eq!(stored_scope, (organization_id, tenant_id));
}

#[tokio::test]
async fn expired_challenge_is_never_replayed() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    let write = challenge("challenge-request-stale");
    repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();
    sqlx::query("UPDATE enrollment_challenges SET status = 'EXPIRED', expires_at = ? WHERE id = ?")
        .bind(Utc::now() - Duration::seconds(1))
        .bind(write.id)
        .execute(&pool)
        .await
        .unwrap();

    let outcome = repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    assert_eq!(outcome, ChallengeCreationOutcome::ActivationUnavailable);
}

#[tokio::test]
async fn expired_activation_code_fails_closed() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    let active = activation(organization_id, tenant_id, code_hash);
    repository.insert_activation_code(&active).await.unwrap();
    sqlx::query("UPDATE enrollment_activation_codes SET expires_at = ? WHERE id = ?")
        .bind(Utc::now() - Duration::seconds(1))
        .bind(active.id)
        .execute(&pool)
        .await
        .unwrap();

    let outcome = repository
        .reserve_challenge(
            &code_hash,
            &challenge("challenge-request-expired"),
            Utc::now(),
        )
        .await
        .unwrap();

    assert_eq!(outcome, ChallengeCreationOutcome::ActivationUnavailable);
}

#[tokio::test]
async fn challenge_expiry_is_clamped_to_its_activation_authorization() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    let mut short_lived = activation(organization_id, tenant_id, code_hash);
    short_lived.expires_at = Utc::now() + Duration::minutes(2);
    repository
        .insert_activation_code(&short_lived)
        .await
        .unwrap();
    let mut write = challenge("challenge-request-too-long");
    write.expires_at = Utc::now() + Duration::minutes(10);

    let outcome = repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    let ChallengeCreationOutcome::Created(record) = outcome else {
        panic!("short-lived activation did not create a bounded challenge");
    };
    let stored_expiry: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM enrollment_challenges WHERE id = ?")
            .bind(write.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(record.expires_at, short_lived.expires_at);
    assert_eq!(stored_expiry, short_lived.expires_at);
}

#[tokio::test]
async fn proof_lookup_returns_the_complete_server_bound_transcript() {
    let Some((_pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    let write = challenge("challenge-request-proof-material");
    repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    let record = repository
        .load_challenge_for_proof(write.id, Utc::now())
        .await
        .unwrap()
        .expect("active challenge");

    assert_eq!(record.id, write.id);
    assert_eq!(record.organization_id, organization_id);
    assert_eq!(record.tenant_id, tenant_id);
    assert_eq!(record.enrollment_instance_id, write.enrollment_instance_id);
    assert_eq!(record.display_name, write.display_name);
    assert_eq!(record.root_public_key, write.root_public_key);
    assert_eq!(record.operational_public_key, write.operational_public_key);
    assert_eq!(record.metadata_hash, write.metadata_hash);
    assert_eq!(record.attestation_hash, write.attestation_hash);
    assert_eq!(record.server_nonce, write.server_nonce);
    assert_eq!(record.assurance_level, write.assurance_level);
    assert_eq!(record.completion_request_id, None);
}

#[tokio::test]
async fn proof_lookup_rejects_expired_or_intermediate_challenges() {
    let Some((pool, repository, organization_id, tenant_id)) = test_repository().await else {
        return;
    };
    let code_hash = unique_code_hash(organization_id, tenant_id);
    repository
        .insert_activation_code(&activation(organization_id, tenant_id, code_hash))
        .await
        .unwrap();
    let write = challenge("challenge-request-proof-unavailable");
    repository
        .reserve_challenge(&code_hash, &write, Utc::now())
        .await
        .unwrap();

    sqlx::query("UPDATE enrollment_challenges SET status = 'PROVED' WHERE id = ?")
        .bind(write.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(repository
        .load_challenge_for_proof(write.id, Utc::now())
        .await
        .unwrap()
        .is_none());

    sqlx::query(
        "UPDATE enrollment_challenges SET status = 'CHALLENGED', expires_at = ? WHERE id = ?",
    )
    .bind(Utc::now() - Duration::seconds(1))
    .bind(write.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .load_challenge_for_proof(write.id, Utc::now())
        .await
        .unwrap()
        .is_none());
}
