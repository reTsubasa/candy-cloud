use sha2::{Digest, Sha256};

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
        "runtime_telemetry_latest",
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
        "identity_abuse_buckets",
        "runtime_projection_transport_catalog",
        "runtime_projection_path_catalog",
        "runtime_transport_identity_requests",
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
fn runtime_telemetry_is_identity_scoped_bounded_latest_state() {
    let migration = include_str!("../migrations/0016_runtime_telemetry_latest.sql");
    assert!(migration.contains("PRIMARY KEY (tenant_id, device_id, device_key_id)"));
    assert!(migration.contains("packet_loss_ppm <= 1000000"));
    assert!(!migration.contains("runtime_telemetry_history"));
}

#[test]
fn runtime_path_telemetry_is_bounded_latest_state() {
    let migration = include_str!("../migrations/0017_runtime_path_telemetry.sql");
    assert!(migration.contains("paths_json JSON"));
    assert!(migration.contains("JSON_LENGTH(paths_json) <= 256"));
}

#[test]
fn runtime_path_catalog_is_immutable_projection_scoped_and_republished() {
    let original = include_str!("../migrations/0025_runtime_projection_path_catalog.sql");
    let repair = include_str!("../migrations/0026_republish_exact_runtime_path_catalog.sql");
    let original_digest: [u8; 32] = Sha256::digest(original.as_bytes()).into();
    assert_eq!(
        original_digest,
        [
            0x6e, 0x5d, 0xd7, 0x09, 0x3e, 0x04, 0x26, 0xc2, 0x12, 0x56, 0xbb, 0xc9, 0x21, 0x88,
            0xeb, 0x20, 0x71, 0x8d, 0x38, 0xa7, 0x44, 0x2f, 0xbd, 0x30, 0x63, 0x76, 0x2e, 0x9a,
            0xc1, 0x82, 0xdc, 0xbb,
        ]
    );
    assert!(original.contains("PRIMARY KEY (projection_publication_id, candidate_id)"));
    assert!(original.contains(
        "FOREIGN KEY (projection_publication_id) REFERENCES site_route_projection_publications(id)"
    ));
    assert!(original.contains("source_attachment_id"));
    assert!(original.contains("destination_attachment_id"));
    assert!(repair.contains("DELETE FROM runtime_projection_path_catalog"));
    assert!(repair.contains("runtime_exact_path_catalog_refresh_segments"));
    assert!(repair.contains("INSERT INTO segment_generation_jobs"));
    assert!(!repair.contains("JOIN sdwan_control_resources"));
    assert!(repair.contains("candy/runtime-exact-path-catalog-v1/"));
}

#[test]
fn runtime_local_network_telemetry_is_non_null_bounded_latest_state() {
    let migration = include_str!("../migrations/0020_runtime_local_network_telemetry.sql");
    assert!(migration.contains("local_networks_json JSON NOT NULL DEFAULT (JSON_ARRAY())"));
    assert!(migration.contains("JSON_TYPE(local_networks_json) = 'ARRAY'"));
    assert!(migration.contains("JSON_LENGTH(local_networks_json) <= 64"));
}

#[test]
fn node_reenrollment_is_explicitly_bound_to_one_control_node() {
    let migration = include_str!("../migrations/0018_node_reenrollment.sql");
    assert!(migration.contains("replace_node_id BINARY(16) NULL"));
    assert!(migration.contains("idx_enrollment_activation_replacement"));
}

#[test]
fn revoked_attachment_does_not_reserve_overlay_address_forever() {
    let migration = include_str!("../migrations/0019_reusable_segment_router_address.sql");
    assert!(migration.contains("DROP INDEX uq_segment_router_address"));
    assert!(migration.contains("active_overlay_router_ipv4"));
    assert!(migration.contains("state IN ('ACTIVE', 'STANDBY')"));
    assert!(migration.contains("ADD UNIQUE KEY uq_active_segment_router_address"));
    assert!(migration.contains("ADD INDEX idx_segment_router_address"));
}

#[test]
fn control_plane_readiness_requires_the_latest_telemetry_migration() {
    let source = include_str!("../src/control.rs");
    assert!(source.contains("_sqlx_migrations WHERE version = 26 AND success = TRUE"));
}

#[test]
fn trial_tunnel_quota_migration_replaces_only_the_known_placeholder_and_republishes() {
    let migration = include_str!("../migrations/0022_sdwan_trial_tunnel_quota.sql");
    assert!(migration.contains("subscription.plan_code = 'sdwan-trial'"));
    assert!(migration.contains("$.upload_rate_bps')) AS UNSIGNED) = 10000000"));
    assert!(migration.contains("$.download_rate_bps')) AS UNSIGNED) = 20000000"));
    assert!(migration.contains("'$.upload_rate_bps', 0"));
    assert!(migration.contains("'$.download_rate_bps', 0"));
    assert!(migration.contains("INSERT INTO segment_generation_jobs"));
    assert!(migration.contains("candy/sdwan-trial-quota-v2/"));
}

#[test]
fn trial_datagram_capacity_migration_repairs_only_the_known_active_default_and_republishes() {
    let migration = include_str!("../migrations/0024_sdwan_trial_datagram_capacity.sql");
    assert!(migration.contains("subscription.plan_code = 'sdwan-trial'"));
    assert!(migration.contains("subscription.status IN ('TRIAL', 'ACTIVE')"));
    assert!(migration.contains("entitlement.service_permission = 'private.tun.connect'"));
    assert!(migration.contains("entitlement.status = 'ACTIVE'"));
    assert!(migration.contains("segment.state = 'ACTIVE'"));
    assert!(migration.contains("entitlement.node_pool_id = segment.hub_node_pool_id"));
    assert!(migration.contains("$.max_datagram_record')) AS UNSIGNED) = 1200"));
    assert!(migration.contains("'$.max_datagram_record', 1350"));
    assert!(migration.contains("INSERT INTO segment_generation_jobs"));
    assert!(migration.contains("candy/sdwan-trial-datagram-capacity-v1/"));
}

#[test]
fn initial_trial_datagram_capacity_covers_the_production_projection_record() {
    let identity = include_str!("../src/identity.rs");
    let publisher = include_str!("../../cloud-worker/src/control_publisher.rs");
    assert!(publisher.contains("max_inner_mtu: 1300"));
    assert!(identity.contains("SDWAN_PROJECTION_MAX_INNER_MTU_BYTES: u64 = 1_300"));
    assert!(identity.contains("SDWAN_IP_PACKET_RECORD_WORST_CASE_OVERHEAD_BYTES: u64 = 50"));
    assert!(identity.contains("SDWAN_TRIAL_MAX_DATAGRAM_RECORD_BYTES"));
    assert!(identity.contains(".bind(SDWAN_TRIAL_MAX_DATAGRAM_RECORD_BYTES)"));
}

#[test]
fn deleted_segment_migration_withdraws_materialized_state_and_pending_work() {
    let migration = include_str!("../migrations/0023_retire_deleted_segments.sql");
    assert!(migration.contains("control_segment.state = 'DELETED'"));
    assert!(migration.contains("SET segment.state = 'DELETED'"));
    assert!(migration.contains("job.state IN ('PENDING','LEASED','RETRY')"));
    assert!(migration.contains("job.last_error_code = 'SEGMENT_DELETED'"));
}

#[test]
fn transport_activation_migration_is_identity_scoped_and_fail_closed() {
    let migration = include_str!("../migrations/0015_sdwan_transport_activation.sql");
    assert!(migration.contains("uq_nodes_device_identity"));
    assert!(migration.contains("transport ENUM('CANDY_QUIC_UDP')"));
    assert!(migration.contains("server_cert_sha256 BINARY(32)"));
    assert!(migration.contains("status ENUM('ACTIVE','DISABLED')"));
    assert!(migration.contains("runtime_projection_transport_catalog"));
    assert!(migration.contains("runtime_transport_identity_requests"));
    assert!(migration.contains("PRIMARY KEY (tenant_id, device_id, request_id)"));
    assert!(migration.contains("request_hash BINARY(32)"));
    assert!(!migration.contains("private_key"));
    assert!(!migration.contains("certificate_der"));
}

#[tokio::test]
async fn database_connections_use_read_committed_isolation() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    let isolation: String = sqlx::query_scalar("SELECT @@transaction_isolation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(isolation, "READ-COMMITTED");
}

#[test]
fn identity_abuse_buckets_are_digest_only_and_expiring() {
    let migration = include_str!("../migrations/0013_identity_public_security.sql");
    assert!(migration.contains("subject_hash BINARY(32)"));
    assert!(migration.contains("expires_at TIMESTAMP(6)"));
    assert!(migration.contains("idx_identity_abuse_buckets_expiry"));
    assert!(!migration.contains("email"));
    assert!(!migration.contains("ip_address"));
    assert!(!migration.contains("token VARCHAR"));
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
