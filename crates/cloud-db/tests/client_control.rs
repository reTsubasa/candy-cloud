use cloud_db::client_control::{ClientControlError, ClientDeviceRegistration, ClientPlatform};
use uuid::Uuid;

fn valid_request() -> ClientDeviceRegistration {
    let user_id = Uuid::new_v4();
    ClientDeviceRegistration {
        record_id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id,
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        platform: ClientPlatform::Macos,
        display_name: "MacBook Pro".into(),
        install_id: "install-01HXYZ123".into(),
        client_version: Some("0.1.0".into()),
        public_key: [7; 32],
        request_id: Uuid::new_v4(),
        actor_id: user_id,
    }
}

#[test]
fn terminal_registration_requires_a_nonzero_scope_and_key() {
    let mut request = valid_request();
    request.tenant_id = Uuid::nil();
    assert_eq!(request.validate(), Err(ClientControlError::InvalidScope));

    let mut request = valid_request();
    request.public_key = [0; 32];
    assert_eq!(
        request.validate(),
        Err(ClientControlError::InvalidPublicKey)
    );
}

#[test]
fn terminal_registration_rejects_unbounded_install_identity() {
    let mut request = valid_request();
    request.install_id = "bad install id".into();
    assert_eq!(
        request.validate(),
        Err(ClientControlError::InvalidInstallId)
    );
}

#[test]
fn terminal_registration_binds_the_actor_to_the_session_user() {
    let mut request = valid_request();
    request.actor_id = Uuid::new_v4();
    assert_eq!(request.validate(), Err(ClientControlError::InvalidScope));
}
