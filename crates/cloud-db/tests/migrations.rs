#[tokio::test]
async fn migration_is_repeatable_and_creates_core_tables() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();

    let required = [
        "organizations",
        "tenants",
        "devices",
        "device_keys",
        "node_pools",
        "nodes",
        "subscriptions",
        "entitlements",
        "policies",
        "authorization_generations",
        "grant_issuance_records",
        "revocation_generations",
        "accounting_sessions",
        "accounting_records",
        "audit_events",
        "worker_leases",
        "enrollment_activation_codes",
        "enrollment_challenges",
        "device_certificates",
        "segments",
        "sites",
        "site_prefixes",
        "segment_attachments",
        "segment_route_publications",
        "site_route_projection_publications",
        "segment_route_publication_members",
        "segment_expansion_publications",
        "runtime_configuration_status",
        "sdwan_control_resources",
        "sdwan_control_resource_references",
        "management_idempotency_records",
        "segment_generation_heads",
        "segment_generation_jobs",
        "human_users",
        "organization_memberships",
        "human_sessions",
        "human_refresh_tokens",
        "human_action_tokens",
        "organization_invitations",
        "development_demo_accounts",
    ];
    for table in required {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "missing table {table}");
    }
}

#[test]
fn development_demo_marker_never_stores_a_password() {
    let migration = include_str!("../migrations/0012_development_demo_accounts.sql");
    assert!(migration.contains("CREATE TABLE development_demo_accounts"));
    assert!(migration.contains("FOREIGN KEY (user_id) REFERENCES human_users(id)"));
    assert!(!migration.contains("password"));
}

#[test]
fn organization_access_migration_models_invites_and_membership_status_without_plaintext_tokens() {
    let migration = include_str!("../migrations/0011_organization_access.sql");
    assert!(migration.contains("CREATE TABLE organization_invitations"));
    assert!(migration.contains("token_hash BINARY(32)"));
    assert!(migration.contains("ADD COLUMN status ENUM('ACTIVE','SUSPENDED')"));
    assert!(migration.contains("uq_organization_single_owner"));
    assert!(migration.contains("owner_guard"));
    assert!(!migration.contains("invitation_token VARCHAR"));
    assert!(!migration.contains("ORGANIZATION_OWNER') NOT NULL"));
}

#[test]
fn human_identity_migration_stores_only_token_hashes_and_models_roles() {
    let migration = include_str!("../migrations/0010_human_identity.sql");
    for table in [
        "human_users",
        "organization_memberships",
        "human_sessions",
        "human_refresh_tokens",
        "human_action_tokens",
    ] {
        assert!(migration.contains(&format!("CREATE TABLE {table}")));
    }
    assert!(migration.contains("password_hash VARCHAR(255)"));
    assert!(migration.contains("token_hash BINARY(32)"));
    assert!(migration.contains("ORGANIZATION_OWNER"));
    assert!(migration.contains("BILLING_VIEWER"));
    assert!(!migration.contains("refresh_token VARCHAR"));
    assert!(!migration.contains("action_token VARCHAR"));
}

#[test]
fn runtime_configuration_status_is_current_projection_scoped() {
    let migration = include_str!("../migrations/0009_runtime_configuration_status.sql");
    assert!(migration.contains("CREATE TABLE runtime_configuration_status"));
    assert!(migration.contains("PRIMARY KEY (tenant_id, device_id, device_key_id)"));
    assert!(migration.contains("UNIQUE KEY uq_projection_runtime_identity"));
    assert!(migration
        .contains("FOREIGN KEY (tenant_id, device_id, device_key_id, projection_publication_id)"));
    assert!(migration.contains("apply_state ENUM('ACTIVE','REJECTED')"));
    assert!(migration.contains("envelope_sha256 BINARY(32)"));
}

#[test]
fn management_control_migration_is_versioned_tenant_scoped_and_recoverable() {
    let migration = include_str!("../migrations/0008_sdwan_management_control.sql");
    for table in [
        "sdwan_control_resources",
        "sdwan_control_resource_references",
        "management_idempotency_records",
        "segment_generation_heads",
        "segment_generation_jobs",
    ] {
        assert!(migration.contains(&format!("CREATE TABLE {table}")));
    }
    assert!(migration.contains("PRIMARY KEY (tenant_id, resource_kind, id)"));
    assert!(migration.contains("idx_control_resource_references_target"));
    assert!(migration.contains("PRIMARY KEY (tenant_id, actor_id, idempotency_key)"));
    assert!(migration.contains("PRIMARY KEY (tenant_id, segment_id)"));
    assert!(migration.contains(
        "UNIQUE KEY uq_generation_job_revision (tenant_id, segment_id, desired_revision)"
    ));
    assert!(migration.contains("ENUM('PENDING','LEASED','RETRY','PUBLISHED','PERMANENT_FAILURE')"));
    assert!(migration.contains("lease_until TIMESTAMP(6) NULL"));
    assert!(!migration.contains("required_contract_version"));
    assert!(migration.contains("DNS_INTENT"));
}

#[test]
fn sdwan_expansion_migration_is_scoped_to_atomic_segment_publications() {
    let migration = include_str!("../migrations/0006_sdwan_expansion_publications.sql");
    assert!(migration.contains("CREATE TABLE segment_expansion_publications"));
    assert!(migration.contains("SHARED_HUB_ADMISSION"));
    assert!(migration.contains("MESH_MEMBERSHIP"));
    assert!(migration.contains("DYNAMIC_ROUTE_SNAPSHOT"));
    assert!(migration.contains(
        "FOREIGN KEY (segment_publication_id) REFERENCES segment_route_publications(id)"
    ));
    assert!(migration.contains(
        "UNIQUE KEY uq_expansion_version (tenant_id, segment_id, object_kind, policy_id, generation)"
    ));
}

#[test]
fn fabric_assignment_extends_the_existing_expansion_kind_without_rewriting_it() {
    let migration = include_str!("../migrations/0007_sdwan_fabric_assignment.sql");
    assert!(migration.contains("ALTER TABLE segment_expansion_publications"));
    assert!(migration.contains("FABRIC_ASSIGNMENT"));
    assert!(migration.contains("DYNAMIC_ROUTE_SNAPSHOT"));
}

#[test]
fn enrollment_pki_migration_stores_only_hashed_activation_credentials() {
    let migration = include_str!("../migrations/0002_enrollment_pki.sql");
    let global_hash_migration = include_str!("../migrations/0004_global_activation_code_hash.sql");

    assert!(migration.contains("code_hash BINARY(32) NOT NULL"));
    assert!(
        migration.contains("UNIQUE KEY uq_enrollment_activation_code_hash (tenant_id, code_hash)")
    );
    assert!(global_hash_migration.contains("DROP INDEX uq_enrollment_activation_code_hash"));
    assert!(
        global_hash_migration.contains("UNIQUE KEY uq_enrollment_activation_code_hash (code_hash)")
    );
    assert!(!migration.contains("code_plaintext"));
    assert!(!migration.contains("activation_secret"));
    assert!(!global_hash_migration.contains("code_plaintext"));
    assert!(!global_hash_migration.contains("activation_secret"));
}

#[test]
fn enrollment_pki_migration_models_the_full_issuance_state_machine() {
    let migration = include_str!("../migrations/0002_enrollment_pki.sql");

    assert!(migration.contains("ENUM('PENDING','CHALLENGED','PROVED','ISSUED','EXPIRED')"));
    assert!(
        migration.contains("UNIQUE KEY uq_enrollment_challenge_request (tenant_id, request_id)")
    );
    assert!(
        migration.contains("UNIQUE KEY uq_enrollment_challenge_activation (activation_code_id)")
    );
    assert!(migration.contains("URI:candy:device:"));
    assert!(
        migration.contains("UPDATE device_keys SET status = 'RETIRING' WHERE status = 'RETIRED'")
    );
}

#[test]
fn enrollment_completion_migration_links_the_issued_identity_once() {
    let migration = include_str!("../migrations/0003_enrollment_completion.sql");

    assert!(migration.contains("certificate_id BINARY(16) NULL"));
    assert!(migration.contains("completion_fingerprint BINARY(32) NULL"));
    assert!(migration.contains(
        "UNIQUE KEY uq_enrollment_completion_request (tenant_id, completion_request_id)"
    ));
    assert!(migration.contains("FOREIGN KEY (certificate_id) REFERENCES device_certificates(id)"));
}

#[test]
fn sdwan_migration_keeps_publications_tenant_scoped_and_audited() {
    let migration = include_str!("../migrations/0005_sdwan_route_contract.sql");

    for table in [
        "segments",
        "sites",
        "site_prefixes",
        "segment_attachments",
        "segment_route_publications",
        "site_route_projection_publications",
        "segment_route_publication_members",
    ] {
        assert!(migration.contains(&format!("CREATE TABLE {table}")));
    }
    assert!(migration.contains(
        "UNIQUE KEY uq_segment_router_address (tenant_id, segment_id, overlay_router_ipv4)"
    ));
    assert!(migration.contains("expected_previous_generation BIGINT UNSIGNED NOT NULL"));
    assert!(migration.contains("signed_envelope MEDIUMBLOB NOT NULL"));
    assert!(migration.contains("audit_event_id BINARY(16) NOT NULL"));
    assert!(migration.contains("FOREIGN KEY (audit_event_id) REFERENCES audit_events(id)"));
}
