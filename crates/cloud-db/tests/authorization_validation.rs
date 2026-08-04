use cloud_db::{authorization::AuthorizationLookup, RepositoryError};
use uuid::Uuid;

#[test]
fn authorization_lookup_requires_every_security_boundary() {
    let valid = AuthorizationLookup {
        tenant_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        node_pool_id: Uuid::new_v4(),
    };
    assert!(valid.validate().is_ok());
    let invalid = AuthorizationLookup {
        tenant_id: valid.tenant_id,
        device_id: valid.device_id,
        device_key_id: Uuid::nil(),
        node_pool_id: valid.node_pool_id,
    };
    assert!(matches!(
        invalid.validate(),
        Err(RepositoryError::InvalidAuthorizationScope)
    ));
}
