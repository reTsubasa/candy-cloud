use std::net::SocketAddr;

use chrono::{Duration, Utc};
use cloud_control::{
    ControlResourceV1, NodePlatformV1, NodeV1, ResourceMetadataV1, ResourceSpecV1, ResourceState,
    SiteKindV1, SiteV1, CONTROL_SCHEMA_V1,
};
use cloud_db::control::{
    ControlRepository, ControlStoreError, MutationContext, ResourceMutation,
    RuntimeTransportPreset, TransportIdentityProvision,
};
use sqlx::Row;
use uuid::Uuid;

fn mutation(resource: ControlResourceV1, request_id: &str, hash: u8) -> ResourceMutation {
    ResourceMutation {
        context: MutationContext {
            actor_id: "transport-activation-test".into(),
            idempotency_key: request_id.into(),
            request_method: "POST".into(),
            request_path: "/test/transport-activation".into(),
            request_hash: [hash; 32],
            idempotency_replay_until: Utc::now() + Duration::hours(1),
        },
        resource,
        expected_revision: None,
    }
}

fn resource(tenant_id: Uuid, id: Uuid, resource: ResourceSpecV1) -> ControlResourceV1 {
    ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: 1,
            state: ResourceState::Active,
        },
        resource,
    }
}

#[tokio::test]
async fn transport_identity_is_atomic_idempotent_and_explicitly_withdrawn() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();

    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let control_node_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    let subscription_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("transport-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("transport-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
        .bind(device_id)
        .bind(tenant_id)
        .bind(Uuid::new_v4().to_string())
        .bind("Transport node")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(device_key_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(format!("transport-key-{device_key_id}"))
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience, status) VALUES (?, ?, 'PRIVATE', ?, 'private', 'ACTIVE')")
        .bind(node_pool_id)
        .bind(tenant_id)
        .bind(format!("transport-pool-{node_pool_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO subscriptions (id, tenant_id, plan_code, status, starts_at) VALUES (?, ?, 'sdwan-test', 'ACTIVE', ?)")
        .bind(subscription_id)
        .bind(tenant_id)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO entitlements (id, tenant_id, subscription_id, node_pool_id, service_permission, quota_json, status) VALUES (?, ?, ?, ?, 'private.tun.connect', JSON_OBJECT(), 'ACTIVE')")
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(subscription_id)
        .bind(node_pool_id)
        .execute(&pool)
        .await
        .unwrap();

    let repository = ControlRepository::new(pool.clone());
    repository
        .mutate(
            &mutation(
                resource(
                    tenant_id,
                    site_id,
                    ResourceSpecV1::Site(SiteV1 {
                        name: "Transport site".into(),
                        kind: SiteKindV1::Edge,
                    }),
                ),
                "site-create",
                1,
            ),
            Utc::now(),
        )
        .await
        .unwrap();
    repository
        .mutate(
            &mutation(
                resource(
                    tenant_id,
                    control_node_id,
                    ResourceSpecV1::Node(NodeV1 {
                        device_id,
                        device_key_id,
                        site_id,
                        display_name: "Transport node".into(),
                        platform: NodePlatformV1::Linux,
                        architecture: "x86_64".into(),
                    }),
                ),
                "node-create",
                2,
            ),
            Utc::now(),
        )
        .await
        .unwrap();

    let dual_stack = vec![
        TransportIdentityProvision {
            endpoint: "203.0.113.20:4433".parse::<SocketAddr>().unwrap(),
            server_cert_sha256: [2; 32],
            transport_preset: RuntimeTransportPreset::Current,
        },
        TransportIdentityProvision {
            endpoint: "[2001:db8::20]:4433".parse::<SocketAddr>().unwrap(),
            server_cert_sha256: [3; 32],
            transport_preset: RuntimeTransportPreset::BbrV1,
        },
    ];
    let first = repository
        .provision_private_transport_identity_for_device(
            tenant_id,
            device_id,
            device_key_id,
            "publish-1",
            &dual_stack,
        )
        .await
        .unwrap();
    assert_eq!(first.node_id, control_node_id);
    assert_eq!(first.endpoints.len(), 2);
    assert!(!first.replayed);
    assert!(
        first
            .endpoints
            .iter()
            .all(|endpoint| endpoint.server_name
                == format!("device-{device_id}.sdwan.candy.internal"))
    );

    let mut reverse_order = dual_stack.clone();
    reverse_order.reverse();
    let replay = repository
        .provision_private_transport_identity_for_device(
            tenant_id,
            device_id,
            device_key_id,
            "publish-1",
            &reverse_order,
        )
        .await
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.endpoints, first.endpoints);

    let changed = vec![TransportIdentityProvision {
        endpoint: "203.0.113.21:4433".parse().unwrap(),
        server_cert_sha256: [4; 32],
        transport_preset: RuntimeTransportPreset::Aggressive,
    }];
    assert!(matches!(
        repository
            .provision_private_transport_identity_for_device(
                tenant_id,
                device_id,
                device_key_id,
                "publish-1",
                &changed,
            )
            .await,
        Err(ControlStoreError::IdempotencyConflict)
    ));
    let active_after_conflict: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM node_endpoints ne JOIN nodes n ON n.id = ne.node_id WHERE n.tenant_id = ? AND n.device_id = ? AND ne.status = 'ACTIVE'",
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_after_conflict, 2);

    repository
        .provision_private_transport_identity_for_device(
            tenant_id,
            device_id,
            device_key_id,
            "publish-2",
            &changed,
        )
        .await
        .unwrap();
    let rows = sqlx::query(
        "SELECT endpoint, ne.status AS endpoint_status FROM node_endpoints ne JOIN nodes n ON n.id = ne.node_id WHERE n.tenant_id = ? AND n.device_id = ? ORDER BY endpoint",
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.iter()
            .filter(|row| row.get::<String, _>("endpoint_status") == "ACTIVE")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.get::<String, _>("endpoint_status") == "ACTIVE")
            .unwrap()
            .get::<String, _>("endpoint"),
        "203.0.113.21:4433"
    );

    repository
        .withdraw_private_transport_identity_for_device(tenant_id, device_id, device_key_id)
        .await
        .unwrap();
    let active_after_withdrawal: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM node_endpoints ne JOIN nodes n ON n.id = ne.node_id WHERE n.tenant_id = ? AND n.device_id = ? AND ne.status = 'ACTIVE'",
    )
    .bind(tenant_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_after_withdrawal, 0);
}
