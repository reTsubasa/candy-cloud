use chrono::Utc;
use cloud_db::authorization::{AuthorizationLookup, AuthorizationRepository};
use uuid::Uuid;

#[tokio::test]
async fn authorization_snapshot_preserves_unsigned_policy_generation() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();

    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    let subscription_id = Uuid::new_v4();
    let policy_generation = u32::MAX as u64 + 7;

    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("authorization-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("authorization-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
        .bind(device_id)
        .bind(tenant_id)
        .bind(Uuid::new_v4().to_string())
        .bind("Authorization node")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, assurance_level, status) VALUES (?, ?, ?, ?, ?, 2, 'ACTIVE')")
        .bind(device_key_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(format!("authorization-key-{device_key_id}"))
        .bind([7_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience, status) VALUES (?, ?, 'PRIVATE', ?, 'private', 'ACTIVE')")
        .bind(node_pool_id)
        .bind(tenant_id)
        .bind(format!("authorization-pool-{node_pool_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO subscriptions (id, tenant_id, plan_code, status, starts_at) VALUES (?, ?, 'authorization-test', 'ACTIVE', ?)")
        .bind(subscription_id)
        .bind(tenant_id)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO entitlements (id, tenant_id, subscription_id, node_pool_id, service_permission, quota_json, status) VALUES (?, ?, ?, ?, 'private.connect', JSON_OBJECT(), 'ACTIVE')")
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(subscription_id)
        .bind(node_pool_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policies (tenant_id, generation, policy_json) VALUES (?, ?, JSON_OBJECT())",
    )
    .bind(tenant_id)
    .bind(policy_generation)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO authorization_generations (tenant_id, generation) VALUES (?, 3)")
        .bind(tenant_id)
        .execute(&pool)
        .await
        .unwrap();

    let record = AuthorizationRepository::new(pool)
        .load(&AuthorizationLookup {
            tenant_id,
            device_id,
            device_key_id,
            node_pool_id,
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(record.policy_generation, policy_generation);
    assert_eq!(record.authorization_generation, 3);
    assert_eq!(record.device_key_id, device_key_id);
}
