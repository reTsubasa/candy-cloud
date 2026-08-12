use chrono::Utc;
use cloud_db::identity::{
    DemoAccountBootstrap, IdentityRepository, IdentityRepositoryError, RegistrationWrite,
};
use uuid::Uuid;

fn registration(email: String, password_hash: &str) -> RegistrationWrite {
    RegistrationWrite {
        user_id: Uuid::now_v7(),
        email,
        display_name: "Demo Owner".into(),
        password_hash: password_hash.into(),
        organization_id: Uuid::now_v7(),
        organization_name: "Candy Demo".into(),
        tenant_id: Uuid::now_v7(),
    }
}

#[tokio::test]
async fn development_demo_is_idempotent_and_cannot_claim_an_existing_account() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let repository = IdentityRepository::new(pool.clone());

    let unique = Uuid::new_v4();
    let demo_email = format!("demo-{unique}@candy.local");
    let first = registration(demo_email.clone(), "$argon2id$first");
    assert_eq!(
        repository
            .bootstrap_verified_demo_owner(&first, Utc::now())
            .await
            .unwrap(),
        DemoAccountBootstrap::Created
    );

    let second = registration(demo_email.clone(), "$argon2id$second");
    assert_eq!(
        repository
            .bootstrap_verified_demo_owner(&second, Utc::now())
            .await
            .unwrap(),
        DemoAccountBootstrap::Updated
    );
    let row: (String, String, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT password_hash, status, email_verified_at FROM human_users WHERE email_normalized = ?",
    )
    .bind(&demo_email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "$argon2id$second");
    assert_eq!(row.1, "ACTIVE");
    assert!(row.2.is_some());

    let existing_email = format!("owner-{unique}@example.test");
    let existing = registration(existing_email.clone(), "$argon2id$owner");
    repository
        .register_user_and_workspace(&existing)
        .await
        .unwrap();
    let takeover = registration(existing_email, "$argon2id$takeover");
    assert!(matches!(
        repository
            .bootstrap_verified_demo_owner(&takeover, Utc::now())
            .await,
        Err(IdentityRepositoryError::Conflict)
    ));
}
