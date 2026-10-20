use std::time::Duration;

use chrono::Utc;
use cloud_control::{
    ControlResourceV1, Ipv4PrefixV1, ResourceMetadataV1, ResourceSpecV1, ResourceState, SegmentV1,
    CONTROL_SCHEMA_V1,
};
use cloud_db::control::{ControlRepository, GenerationJobRepository};
use uuid::Uuid;

/// Real MySQL coverage: a route certificate refresh preserves the tunnel
/// activation path, while an unpublished transport edit must retain its fence.
#[tokio::test]
async fn renewal_is_policy_only_unless_unpublished_transport_changes_remain() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let node_pool = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization)
        .bind(format!("renewal-{organization}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant)
        .bind(organization)
        .bind(format!("renewal-{tenant}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience) VALUES (?, ?, 'PRIVATE', ?, 'private')")
        .bind(node_pool)
        .bind(tenant)
        .bind(format!("renewal-{node_pool}"))
        .execute(&pool)
        .await
        .unwrap();
    let mut segments = Vec::new();
    // A completed TUNNEL job is not a transport change. An unpublished failed
    // policy edit is safe to renew in place, but an unpublished TUNNEL edit is
    // not. A later successful job already includes earlier failed edits.
    for (index, (failed_mode, superseded, expected)) in [
        (None, false, "POLICY_ONLY"),
        (Some("POLICY_ONLY"), false, "POLICY_ONLY"),
        (Some("TUNNEL"), false, "TUNNEL"),
        (Some("TUNNEL"), true, "POLICY_ONLY"),
    ]
    .into_iter()
    .enumerate()
    {
        let segment = Uuid::new_v4();
        let desired_revision = if superseded {
            3_u64
        } else if failed_mode.is_some() {
            2
        } else {
            1
        };
        sqlx::query("INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len, current_generation, current_content_hash) VALUES (?, ?, ?, ?, ?, 24, 1, ?)")
            .bind(segment)
            .bind(tenant)
            .bind(format!("renewal-{segment}"))
            .bind(node_pool)
            .bind([100_u8, 64, u8::try_from(index).unwrap(), 0].as_slice())
            .bind([1_u8; 32].as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let audit_id = Uuid::new_v4();
        sqlx::query("INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'WORKER', 'renewal-test', 'SDWAN_SEGMENT_ROUTES_PUBLISHED', 'SEGMENT', ?, JSON_OBJECT())")
            .bind(audit_id)
            .bind(tenant)
            .bind(segment.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO segment_route_publications (id, tenant_id, segment_id, expected_previous_generation, expected_previous_hash, generation, content_hash, signed_envelope, audit_event_id, actor_id, expires_at, stale_until) VALUES (?, ?, ?, 0, ?, 1, ?, ?, ?, 'renewal-test', 1, 2)")
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(segment)
            .bind([0_u8; 32].as_slice())
            .bind([1_u8; 32].as_slice())
            .bind([1_u8; 64].as_slice())
            .bind(audit_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO segment_generation_heads (tenant_id, segment_id, desired_revision) VALUES (?, ?, ?)")
            .bind(tenant)
            .bind(segment)
            .bind(desired_revision)
            .execute(&pool)
            .await
            .unwrap();
        for revision in 1..=desired_revision {
            let failed = revision == 2 && failed_mode.is_some();
            sqlx::query("INSERT INTO segment_generation_jobs (id, tenant_id, segment_id, desired_revision, idempotency_hash, activation_mode, state, published_generation, published_content_hash, last_error_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(Uuid::new_v4())
                .bind(tenant)
                .bind(segment)
                .bind(revision)
                .bind([u8::try_from(revision).unwrap(); 32].as_slice())
                .bind(if failed { failed_mode.unwrap() } else { "TUNNEL" })
                .bind(if failed { "PERMANENT_FAILURE" } else { "PUBLISHED" })
                .bind((!failed).then_some(1_u64))
                .bind((!failed).then_some([1_u8; 32].to_vec()))
                .bind(failed.then_some("TEST_UNPUBLISHED_CHANGE"))
                .execute(&pool)
                .await
                .unwrap();
        }
        let resource = ControlResourceV1 {
            metadata: ResourceMetadataV1 {
                schema_version: CONTROL_SCHEMA_V1,
                id: segment,
                tenant_id: tenant,
                revision: 1,
                state: ResourceState::Active,
            },
            resource: ResourceSpecV1::Segment(SegmentV1 {
                name: format!("renewal-{segment}"),
                overlay_prefix: Ipv4PrefixV1 {
                    network: std::net::Ipv4Addr::new(100, 64, u8::try_from(index).unwrap(), 0),
                    prefix_len: 24,
                },
            }),
        };
        sqlx::query("INSERT INTO sdwan_control_resources (tenant_id, resource_kind, id, revision, state, segment_id, document_hash, document_json, created_by, updated_by) VALUES (?, 'SEGMENT', ?, 1, 'ACTIVE', ?, ?, CAST(? AS JSON), 'renewal-test', 'renewal-test')")
            .bind(tenant)
            .bind(segment)
            .bind(segment)
            .bind(resource.resource.document_hash().unwrap().as_slice())
            .bind(serde_json::to_string(&resource).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        segments.push((segment, desired_revision, expected));
    }
    let jobs = GenerationJobRepository::new(pool.clone());
    jobs.refresh_expiring(Utc::now(), Duration::from_secs(300), 128)
        .await
        .unwrap();
    for (segment, revision, expected) in &segments {
        let mode: String = sqlx::query_scalar("SELECT activation_mode FROM segment_generation_jobs WHERE tenant_id = ? AND segment_id = ? AND desired_revision = ?")
            .bind(tenant)
            .bind(segment)
            .bind(revision + 1)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(&mode, expected);
        let snapshot = ControlRepository::new(pool.clone())
            .segment_snapshot(tenant, *segment, revision + 1)
            .await
            .unwrap();
        assert_eq!(snapshot.policy_only, *expected == "POLICY_ONLY");
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM segment_generation_jobs WHERE tenant_id = ? AND segment_id = ?",
        )
        .bind(tenant)
        .bind(segment)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(u64::try_from(count).unwrap(), revision + 1);
    }
    // A second scan cannot enqueue duplicate refreshes while the first job is
    // pending. Existing signatures and catalog generations are never mutated.
    jobs.refresh_expiring(Utc::now(), Duration::from_secs(300), 128)
        .await
        .unwrap();
    // A later transport edit is part of the current resource graph even if an
    // older policy-only queue job is selected. The old job cannot bypass the
    // transport prepare barrier merely because its own activation mode is old.
    let (segment, original_revision, _) = segments[0];
    sqlx::query("UPDATE segment_generation_heads SET desired_revision = ? WHERE tenant_id = ? AND segment_id = ?")
        .bind(original_revision + 2)
        .bind(tenant)
        .bind(segment)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO segment_generation_jobs (id, tenant_id, segment_id, desired_revision, idempotency_hash, activation_mode) VALUES (?, ?, ?, ?, ?, 'TUNNEL')")
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(segment)
        .bind(original_revision + 2)
        .bind([9_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let snapshot = ControlRepository::new(pool.clone())
        .segment_snapshot(tenant, segment, original_revision + 1)
        .await
        .unwrap();
    assert!(!snapshot.policy_only);
    for (segment, revision, _) in segments.iter().skip(1) {
        let head: u64 = sqlx::query_scalar("SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ?")
            .bind(tenant)
            .bind(segment)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(head, revision + 1);
    }
    // Startup recovery must enqueue a real reconciliation job when the desired
    // published receipt no longer describes the active segment publication.
    // This exercises the INSERT bindings, rather than just its SQL spelling.
    let desired = original_revision + 2;
    sqlx::query("UPDATE segment_generation_jobs SET state = 'PUBLISHED', published_generation = 999, published_content_hash = ? WHERE tenant_id = ? AND segment_id = ? AND desired_revision = ?")
        .bind([7_u8; 32].as_slice())
        .bind(tenant)
        .bind(segment)
        .bind(desired)
        .execute(&pool)
        .await
        .unwrap();
    jobs.recover_route_input_head_failures().await.unwrap();
    let (mode, state): (String, String) = sqlx::query_as("SELECT activation_mode, state FROM segment_generation_jobs WHERE tenant_id = ? AND segment_id = ? AND desired_revision = ?")
        .bind(tenant).bind(segment).bind(desired + 1)
        .fetch_one(&pool).await.unwrap();
    assert_eq!(mode, "TUNNEL");
    assert_eq!(state, "PENDING");
    let head: u64 = sqlx::query_scalar("SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ?")
        .bind(tenant).bind(segment).fetch_one(&pool).await.unwrap();
    assert_eq!(head, desired + 1);
}
