use std::{fs, path::PathBuf};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use cloud_auth::runtime::{build_app, CloudAuthConfig};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use tower::ServiceExt;
use uuid::Uuid;

fn test_ca() -> (String, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Candy Runtime Test CA");
    params.distinguished_name = name;
    let certificate = params.self_signed(&key).unwrap();
    (certificate.pem(), key.serialize_pem())
}

#[cfg(unix)]
fn write_secret(path: &PathBuf, value: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, value).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_mounts_enrollment_only_after_database_and_both_key_sets_load() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let directory = std::env::temp_dir().join(format!("candy-auth-runtime-{}", Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let signing_key_path = directory.join("grant-signing.key");
    let device_ca_certificate_path = directory.join("device-ca.pem");
    let device_ca_key_path = directory.join("device-ca.key");
    let (ca_certificate, ca_key) = test_ca();
    write_secret(&signing_key_path, [1; 32]);
    fs::write(&device_ca_certificate_path, ca_certificate).unwrap();
    write_secret(&device_ca_key_path, ca_key);
    let config = CloudAuthConfig {
        database_url,
        signing_key_path,
        device_ca_certificate_path,
        device_ca_key_path: device_ca_key_path.clone(),
        device_ca_key_id: "device-ca-test".into(),
        environment: "test".into(),
    };
    let app = build_app(config).await.unwrap();

    let ready = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    fs::remove_file(device_ca_key_path).unwrap();
    let unavailable = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    fs::remove_dir_all(directory).unwrap();
}
