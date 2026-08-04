use chrono::{Duration, TimeZone, Utc};
use cloud_auth::certificates::{
    CertificateIssuanceError, DeviceCertificateIssuer, DEVICE_CERTIFICATE_TTL,
    EMERGENCY_RENEWAL_WINDOW, NORMAL_RENEWAL_WINDOW,
};
use ed25519_dalek::VerifyingKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::parse_x509_pem};

fn test_ca() -> (String, String) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Candy Test Device Intermediate");
    params.distinguished_name = name;
    let certificate = params.self_signed(&key).unwrap();
    (certificate.pem(), key.serialize_pem())
}

#[test]
fn device_certificate_binds_operational_key_and_controlled_identity_sans() {
    let (ca_certificate, ca_key) = test_ca();
    let issuer = DeviceCertificateIssuer::from_pem(
        "device-ca-2026-01",
        "production",
        &ca_certificate,
        &ca_key,
    )
    .unwrap();
    let operational_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let operational_public_key: [u8; 32] = operational_key
        .public_key_raw()
        .try_into()
        .expect("Ed25519 public key");
    let device_id = Uuid::now_v7();
    let device_key_id = Uuid::now_v7();
    let requested_not_before = Utc.timestamp_opt(1_800_000_000, 123_456_789).unwrap();
    let encoded_not_before = Utc.timestamp_opt(1_800_000_000, 0).unwrap();

    let issued = issuer
        .issue(
            device_id,
            device_key_id,
            operational_public_key,
            2,
            requested_not_before,
        )
        .unwrap();

    let (_, certificate) = parse_x509_certificate(&issued.certificate_der).unwrap();
    let (_, ca_pem) = parse_x509_pem(ca_certificate.as_bytes()).unwrap();
    let (_, ca) = parse_x509_certificate(&ca_pem.contents).unwrap();
    certificate.verify_signature(Some(ca.public_key())).unwrap();
    assert_eq!(
        certificate.public_key().subject_public_key.data.as_ref(),
        operational_public_key
    );
    let sans = certificate
        .subject_alternative_name()
        .unwrap()
        .expect("SAN extension");
    let uris: Vec<_> = sans
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect();
    assert!(uris.contains(&format!("candy:device:{device_id}").as_str()));
    assert!(uris.contains(&format!("candy:device-key:{device_key_id}").as_str()));
    assert!(uris.contains(&"candy:environment:production"));
    assert!(uris.contains(&"candy:assurance:A2"));
    assert_eq!(issued.not_after - issued.not_before, DEVICE_CERTIFICATE_TTL);
    assert_eq!(issued.not_before, encoded_not_before);
    assert_eq!(certificate.validity().not_before.timestamp(), 1_800_000_000);
    assert_eq!(issued.issuer_key_id, "device-ca-2026-01");
    assert_eq!(issued.certificate_chain_pem, ca_certificate);
}

#[test]
fn issuer_rejects_a_private_key_that_does_not_match_the_ca_certificate() {
    let (ca_certificate, _) = test_ca();
    let (_, other_ca_key) = test_ca();

    assert!(matches!(
        DeviceCertificateIssuer::from_pem(
            "device-ca-2026-01",
            "production",
            &ca_certificate,
            &other_ca_key,
        ),
        Err(CertificateIssuanceError::IssuerKeyMismatch)
    ));
}

#[test]
fn issuer_rejects_unknown_assurance_levels() {
    let (ca_certificate, ca_key) = test_ca();
    let issuer = DeviceCertificateIssuer::from_pem(
        "device-ca-2026-01",
        "production",
        &ca_certificate,
        &ca_key,
    )
    .unwrap();

    assert!(matches!(
        issuer.issue(
            Uuid::now_v7(),
            Uuid::now_v7(),
            KeyPair::generate_for(&PKCS_ED25519)
                .unwrap()
                .public_key_raw()
                .try_into()
                .unwrap(),
            4,
            Utc::now(),
        ),
        Err(CertificateIssuanceError::InvalidAssuranceLevel)
    ));
}

#[test]
fn issuer_rejects_an_invalid_ed25519_subject_key() {
    let (ca_certificate, ca_key) = test_ca();
    let issuer = DeviceCertificateIssuer::from_pem(
        "device-ca-2026-01",
        "production",
        &ca_certificate,
        &ca_key,
    )
    .unwrap();
    let invalid_key = (0_u8..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|candidate| VerifyingKey::from_bytes(candidate).is_err())
        .expect("at least one invalid compressed Ed25519 point");

    assert!(matches!(
        issuer.issue(Uuid::now_v7(), Uuid::now_v7(), invalid_key, 1, Utc::now(),),
        Err(CertificateIssuanceError::InvalidOperationalPublicKey)
    ));
}

#[test]
fn renewal_windows_match_the_product_policy() {
    assert_eq!(DEVICE_CERTIFICATE_TTL, Duration::days(7));
    assert_eq!(NORMAL_RENEWAL_WINDOW, Duration::hours(48));
    assert_eq!(EMERGENCY_RENEWAL_WINDOW, Duration::hours(12));
}

#[cfg(unix)]
#[test]
fn file_loader_requires_an_owner_only_device_ca_private_key() {
    use std::{fs, os::unix::fs::PermissionsExt};

    let directory = std::env::temp_dir().join(format!("candy-device-ca-{}", Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let certificate_path = directory.join("device-ca.pem");
    let private_key_path = directory.join("device-ca.key");
    let (certificate, private_key) = test_ca();
    fs::write(&certificate_path, certificate).unwrap();
    fs::write(&private_key_path, private_key).unwrap();
    fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o640)).unwrap();

    assert!(matches!(
        DeviceCertificateIssuer::from_files(
            "device-ca-test",
            "test",
            &certificate_path,
            &private_key_path,
        ),
        Err(CertificateIssuanceError::InsecureIssuerKeyPermissions)
    ));

    fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(DeviceCertificateIssuer::from_files(
        "device-ca-test",
        "test",
        &certificate_path,
        &private_key_path,
    )
    .is_ok());
    fs::remove_dir_all(directory).unwrap();
}
