use std::{net::Ipv4Addr, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use cloud_control::{
    ControlResourceV1, Ipv4PrefixV1, ResourceMetadataV1, ResourceSpecV1, ResourceState, SegmentV1,
    CONTROL_SCHEMA_V1,
};
use cloud_db::control::{
    ControlRepository, ControlStoreError, GenerationJobRepository, JobFailure, MutationContext,
    MutationOutcome, ResourceMutation,
};
use uuid::Uuid;

async fn fixture() -> Option<(cloud_db::DbPool, Uuid)> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = cloud_db::connect(&url).await.ok()?;
    cloud_db::migrate(&pool).await.ok()?;
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization)
        .bind(format!("control-test-{organization}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant)
        .bind(organization)
        .bind(format!("control-test-{tenant}"))
        .execute(&pool)
        .await
        .unwrap();
    Some((pool, tenant))
}

fn segment(tenant: Uuid, id: Uuid, revision: u64, name: &str) -> ControlResourceV1 {
    ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id: tenant,
            revision,
            state: ResourceState::Active,
        },
        resource: ResourceSpecV1::Segment(SegmentV1 {
            name: name.into(),
            overlay_prefix: Ipv4PrefixV1 {
                network: Ipv4Addr::new(10, 200, 0, 0),
                prefix_len: 16,
            },
        }),
    }
}

fn mutation(
    resource: ControlResourceV1,
    key: &str,
    hash: u8,
    expected_revision: Option<u64>,
) -> ResourceMutation {
    let now = Utc::now();
    ResourceMutation {
        context: MutationContext {
            actor_id: "integration-test".into(),
            idempotency_key: key.into(),
            request_method: if expected_revision.is_some() {
                "PUT".into()
            } else {
                "POST".into()
            },
            request_path: format!("/test/{}", resource.metadata.id),
            request_hash: [hash; 32],
            idempotency_replay_until: now + ChronoDuration::hours(1),
        },
        resource,
        expected_revision,
    }
}

#[tokio::test]
async fn audit_events_decode_mysql_json_as_api_text() {
    let Some((pool, tenant)) = fixture().await else {
        return;
    };
    let repository = ControlRepository::new(pool.clone());
    let event_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'USER', NULL, 'TEST_ACTION', 'TEST_OBJECT', NULL, JSON_OBJECT('result', 'ok'))",
    )
    .bind(event_id)
    .bind(tenant)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO audit_events (id, tenant_id, actor_type, action, object_type, metadata_json) VALUES (?, ?, 'IDENTITY', 'IDENTITY_REFRESH_SUCCEEDED', 'HUMAN_ACCOUNT', JSON_OBJECT('result', 'ok'))",
    )
    .bind(Uuid::new_v4())
    .bind(tenant)
    .execute(&pool)
    .await
    .unwrap();
    let organization: Uuid = sqlx::query_scalar("SELECT organization_id FROM tenants WHERE id = ?")
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO audit_events (id, organization_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'USER', 'owner', 'ORGANIZATION_MEMBER_REMOVED', 'ORGANIZATION_MEMBERSHIP', 'member', JSON_OBJECT())",
    )
    .bind(Uuid::new_v4())
    .bind(organization)
    .execute(&pool)
    .await
    .unwrap();

    let events = repository.audit_events(tenant, 10, false).await.unwrap();
    assert_eq!(events.len(), 2);
    let event = events.iter().find(|event| event.id == event_id).unwrap();
    assert_eq!(event.actor_type, "USER");
    assert_eq!(event.actor_id, None);
    assert_eq!(event.action, "TEST_ACTION");
    assert_eq!(event.object_type, "TEST_OBJECT");
    assert_eq!(event.object_id, None);
    assert_eq!(event.metadata_json, r#"{"result": "ok"}"#);
    assert!(events
        .iter()
        .any(|event| event.action == "ORGANIZATION_MEMBER_REMOVED"));
    assert!(!events
        .iter()
        .any(|event| event.action == "IDENTITY_REFRESH_SUCCEEDED"));
    assert_eq!(
        repository
            .audit_events(tenant, 10, true)
            .await
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn resource_delete_is_audited_with_state_change() {
    let Some((pool, tenant)) = fixture().await else {
        return;
    };
    let repository = ControlRepository::new(pool);
    let resource_id = Uuid::new_v4();
    let create = mutation(
        segment(tenant, resource_id, 1, "temporary-segment"),
        "audit-create",
        10,
        None,
    );
    repository.mutate(&create, Utc::now()).await.unwrap();

    let mut deleted = segment(tenant, resource_id, 2, "temporary-segment");
    deleted.metadata.state = ResourceState::Deleted;
    let mut delete = mutation(deleted, "audit-delete", 11, Some(1));
    delete.context.request_method = "DELETE".into();
    repository.mutate(&delete, Utc::now()).await.unwrap();

    let events = repository.audit_events(tenant, 10, false).await.unwrap();
    assert_eq!(events[0].action, "CONTROL_RESOURCE_DELETED");
    let metadata: serde_json::Value = serde_json::from_str(&events[0].metadata_json).unwrap();
    assert_eq!(metadata["operation"], "delete");
    assert_eq!(metadata["changed_fields"], serde_json::json!(["state"]));
}

#[tokio::test]
async fn repository_enforces_tenant_revision_idempotency_and_lease_recovery() {
    let Some((pool, tenant)) = fixture().await else {
        return;
    };
    let repository = ControlRepository::new(pool.clone());
    let jobs = GenerationJobRepository::new(pool);
    let resource_id = Uuid::parse_str("c63ece79-9380-4fa2-8f80-ff80fe807f81").unwrap();
    let create = mutation(
        segment(tenant, resource_id, 1, "branch-segment"),
        "create-1",
        1,
        None,
    );

    assert!(matches!(
        repository.mutate(&create, Utc::now()).await.unwrap(),
        MutationOutcome::Applied(_)
    ));
    assert!(matches!(
        repository.mutate(&create, Utc::now()).await.unwrap(),
        MutationOutcome::Replayed(_)
    ));
    let mut divergent = create.clone();
    divergent.context.request_hash = [2; 32];
    assert!(matches!(
        repository.mutate(&divergent, Utc::now()).await,
        Err(ControlStoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        repository
            .get(
                Uuid::new_v4(),
                cloud_control::ResourceKind::Segment,
                resource_id
            )
            .await,
        Err(ControlStoreError::NotFound)
    ));

    let update = mutation(
        segment(tenant, resource_id, 2, "branch-segment-renamed"),
        "update-1",
        3,
        Some(1),
    );
    assert!(matches!(
        repository.mutate(&update, Utc::now()).await.unwrap(),
        MutationOutcome::Applied(_)
    ));
    let replayed_create = repository.mutate(&create, Utc::now()).await.unwrap();
    match replayed_create {
        MutationOutcome::Replayed(resource) => {
            assert_eq!(resource.metadata.revision, 1);
            assert_eq!(resource, create.resource);
        }
        MutationOutcome::Applied(_) => panic!("original create was applied twice"),
    }
    let stale = mutation(
        segment(tenant, resource_id, 2, "stale"),
        "update-stale",
        4,
        Some(1),
    );
    assert!(matches!(
        repository.mutate(&stale, Utc::now()).await,
        Err(ControlStoreError::RevisionConflict)
    ));
    let events = repository.audit_events(tenant, 10, false).await.unwrap();
    assert_eq!(
        events.len(),
        2,
        "replays and rejected writes must not duplicate audit events"
    );
    assert_eq!(events[0].action, "CONTROL_RESOURCE_UPDATED");
    assert_eq!(events[0].object_type, "SEGMENT");
    assert_eq!(events[0].actor_id.as_deref(), Some("integration-test"));
    let metadata: serde_json::Value = serde_json::from_str(&events[0].metadata_json).unwrap();
    assert_eq!(metadata["operation"], "update");
    assert_eq!(metadata["resource_name"], "branch-segment-renamed");
    assert_eq!(metadata["previous_revision"], 1);
    assert_eq!(metadata["revision"], 2);
    assert_eq!(metadata["changed_fields"], serde_json::json!(["name"]));
    assert_eq!(events[1].action, "CONTROL_RESOURCE_CREATED");

    let now = Utc::now();
    let first = jobs
        .claim_next("worker-a", now, Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.attempt_count, 1);
    assert!(jobs
        .claim_next("worker-b", now, Duration::from_secs(30))
        .await
        .unwrap()
        .is_none());
    let recovered = jobs
        .claim_next(
            "worker-b",
            now + ChronoDuration::seconds(2),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.id, first.id);
    assert_eq!(recovered.attempt_count, 2);
    jobs.fail(
        &recovered,
        now + ChronoDuration::seconds(2),
        &JobFailure::Permanent {
            code: "ROUTE_INPUT_LOAD_SEGMENT_PUBLICATION_HEAD".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(jobs.recover_route_input_head_failures().await.unwrap(), 0);
    let next = jobs
        .claim_next(
            "worker-c",
            now + ChronoDuration::seconds(3),
            Duration::from_secs(30),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.desired_revision, 2);
    assert_eq!(next.attempt_count, 1);
}
