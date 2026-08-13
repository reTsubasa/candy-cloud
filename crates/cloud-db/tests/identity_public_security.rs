use chrono::{Duration, Utc};
use cloud_db::identity::{IdentityRepository, IdentitySecurityAudit};
use uuid::Uuid;

#[tokio::test]
async fn rate_limit_is_atomic_bounded_and_resets_after_expiry() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let repository = IdentityRepository::new(pool);
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let mut subject = [0u8; 32];
    subject[..16].copy_from_slice(first.as_bytes());
    subject[16..].copy_from_slice(second.as_bytes());
    let now = Utc::now();
    assert!(
        repository
            .consume_rate_limit("test_login", &subject, 2, 60, now)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        repository
            .consume_rate_limit("test_login", &subject, 2, 60, now)
            .await
            .unwrap()
            .allowed
    );
    let denied = repository
        .consume_rate_limit("test_login", &subject, 2, 60, now)
        .await
        .unwrap();
    assert!(!denied.allowed);
    assert!((1..=60).contains(&denied.retry_after_seconds));
    assert!(
        repository
            .consume_rate_limit("test_login", &subject, 2, 60, now + Duration::seconds(61))
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn security_audit_stores_only_the_supplied_digest() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let repository = IdentityRepository::new(pool.clone());
    let actor_hash = [0x62; 32];
    repository
        .append_security_audit(IdentitySecurityAudit {
            organization_id: None,
            tenant_id: None,
            actor_hash: &actor_hash,
            action: "IDENTITY_LOGIN_REJECTED",
            result: "INVALID_CREDENTIALS",
            object_id: None,
        })
        .await
        .unwrap();
    let actor_id: String = sqlx::query_scalar(
        "SELECT actor_id FROM audit_events WHERE action = 'IDENTITY_LOGIN_REJECTED' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actor_id, "62".repeat(32).to_uppercase());
}
