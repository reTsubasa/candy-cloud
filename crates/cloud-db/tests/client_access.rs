use cloud_db::client_access::{
    ClientAccessPolicy, ClientAccessPolicyError, ClientAllowedResource,
    ClientAuthorizationSnapshot, ClientTrafficMode,
};
use cloud_db::client_control::ClientPlatform;
use uuid::Uuid;

fn policy() -> ClientAccessPolicy {
    ClientAccessPolicy {
        schema_version: 1,
        policy_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        generation: 1,
        mode_capabilities: vec![ClientTrafficMode::Policy],
        global_egress_enabled: false,
        allowed_resources: vec![ClientAllowedResource {
            name: "internal-git".into(),
            domains: vec!["git.example.test".into()],
            cidrs: vec!["10.20.0.0/16".into()],
            ports: vec![22, 443],
        }],
    }
}

#[test]
fn access_policy_requires_global_capability_for_global_egress() {
    let mut value = policy();
    value.global_egress_enabled = true;
    assert_eq!(
        value.validate(),
        Err(ClientAccessPolicyError::InvalidPolicy)
    );
}

#[test]
fn access_policy_rejects_duplicate_resources_and_ports() {
    let mut value = policy();
    value.allowed_resources[0].ports = vec![443, 443];
    assert_eq!(
        value.validate(),
        Err(ClientAccessPolicyError::InvalidResource)
    );
}

#[test]
fn access_policy_content_hash_is_stable_for_same_document() {
    let value = policy();
    assert_eq!(value.content_hash().unwrap(), value.content_hash().unwrap());
    assert_ne!(value.content_hash().unwrap(), [0; 32]);
}

fn snapshot() -> ClientAuthorizationSnapshot {
    let policy = policy();
    ClientAuthorizationSnapshot {
        organization_id: Uuid::new_v4(),
        tenant_id: policy.tenant_id,
        user_id: Uuid::new_v4(),
        client_device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        platform: ClientPlatform::Android,
        device_generation: 1,
        public_key: [7; 32],
        policy_content_hash: policy.content_hash().unwrap(),
        policy,
    }
}

#[test]
fn authorization_snapshot_validates_policy_integrity() {
    let mut value = snapshot();
    assert!(value.validate().is_ok());

    value.policy.generation = 2;
    assert_eq!(
        value.validate(),
        Err(ClientAccessPolicyError::InvalidRecord)
    );
}

#[tokio::test]
async fn authorization_snapshot_rejects_missing_scope_before_database_access() {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy("mysql://unused:unused@127.0.0.1/unused")
        .unwrap();
    let repository = cloud_db::client_access::ClientAccessPolicyRepository::new(pool);
    assert_eq!(
        repository
            .authorization_snapshot(Uuid::nil(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
            .await,
        Err(ClientAccessPolicyError::InvalidScope)
    );
}
