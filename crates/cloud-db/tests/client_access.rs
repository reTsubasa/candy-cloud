use cloud_db::client_access::{
    ClientAccessPolicy, ClientAccessPolicyError, ClientAllowedResource, ClientTrafficMode,
};
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
