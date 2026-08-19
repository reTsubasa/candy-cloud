use chrono::{Duration, Utc};
use cloud_db::{
    enrollment::{ActivationCodeWrite, EnrollmentRepository, EnrollmentWrite},
    RepositoryError,
};
use uuid::Uuid;

#[tokio::test]
async fn enrollment_rejects_missing_scope_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = EnrollmentRepository::new(pool);
    let write = EnrollmentWrite {
        device_record_id: Uuid::new_v4(),
        tenant_id: Uuid::nil(),
        device_identity: Uuid::new_v4(),
        display_name: "branch".into(),
        key_record_id: Uuid::new_v4(),
        key_id: "key-1".into(),
        public_key: [7; 32],
        assurance_level: 1,
        actor_id: "device".into(),
    };
    assert!(matches!(
        repository.insert(&write).await,
        Err(RepositoryError::InvalidEnrollmentScope)
    ));
}

#[tokio::test]
async fn activation_code_rejects_an_expired_credential_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = EnrollmentRepository::new(pool);
    let write = ActivationCodeWrite {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        site_id: None,
        requested_display_name: None,
        requested_platform: None,
        requested_architecture: None,
        replace_node_id: None,
        code_hash: [1; 32],
        expires_at: Utc::now() - Duration::seconds(1),
        created_by: "admin".into(),
    };

    assert!(matches!(
        repository.insert_activation_code(&write).await,
        Err(RepositoryError::InvalidActivationScope)
    ));
}
