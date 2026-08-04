use std::{fs, path::Path};

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use time::OffsetDateTime;
use uuid::Uuid;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

pub const DEVICE_CERTIFICATE_TTL: Duration = Duration::days(7);
pub const NORMAL_RENEWAL_WINDOW: Duration = Duration::hours(48);
pub const EMERGENCY_RENEWAL_WINDOW: Duration = Duration::hours(12);

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const MAX_ISSUER_KEY_ID_LEN: usize = 80;
const MAX_ENVIRONMENT_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedDeviceCertificate {
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub serial_number: [u8; 16],
    pub issuer_key_id: String,
    pub san_uri: String,
    pub environment: String,
    pub assurance_level: u64,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateIssuanceError {
    #[error("invalid device certificate issuer key id")]
    InvalidIssuerKeyId,
    #[error("invalid device certificate environment")]
    InvalidEnvironment,
    #[error("device CA certificate and private key do not match")]
    IssuerKeyMismatch,
    #[error("invalid device CA material")]
    InvalidIssuerMaterial,
    #[error("device CA file unavailable")]
    IssuerFileUnavailable,
    #[error("device CA private key must not be accessible by group or others")]
    InsecureIssuerKeyPermissions,
    #[error("invalid Ed25519 operational public key")]
    InvalidOperationalPublicKey,
    #[error("invalid device assurance level")]
    InvalidAssuranceLevel,
    #[error("device certificate generation failed")]
    GenerationFailed,
}

pub struct DeviceCertificateIssuer {
    issuer_key_id: String,
    environment: String,
    issuer: Issuer<'static, KeyPair>,
    certificate_chain_pem: String,
}

impl DeviceCertificateIssuer {
    pub fn from_files(
        issuer_key_id: impl Into<String>,
        environment: impl Into<String>,
        ca_certificate_path: &Path,
        ca_private_key_path: &Path,
    ) -> Result<Self, CertificateIssuanceError> {
        let key_metadata = fs::metadata(ca_private_key_path)
            .map_err(|_| CertificateIssuanceError::IssuerFileUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if key_metadata.permissions().mode() & 0o077 != 0 {
                return Err(CertificateIssuanceError::InsecureIssuerKeyPermissions);
            }
        }
        if !key_metadata.is_file() || key_metadata.len() > 64 * 1024 {
            return Err(CertificateIssuanceError::IssuerFileUnavailable);
        }
        let certificate_metadata = fs::metadata(ca_certificate_path)
            .map_err(|_| CertificateIssuanceError::IssuerFileUnavailable)?;
        if !certificate_metadata.is_file() || certificate_metadata.len() > 1024 * 1024 {
            return Err(CertificateIssuanceError::IssuerFileUnavailable);
        }
        let certificate = fs::read_to_string(ca_certificate_path)
            .map_err(|_| CertificateIssuanceError::IssuerFileUnavailable)?;
        let private_key = fs::read_to_string(ca_private_key_path)
            .map_err(|_| CertificateIssuanceError::IssuerFileUnavailable)?;
        Self::from_pem(issuer_key_id, environment, &certificate, &private_key)
    }

    pub fn from_pem(
        issuer_key_id: impl Into<String>,
        environment: impl Into<String>,
        ca_certificate_pem: &str,
        ca_private_key_pem: &str,
    ) -> Result<Self, CertificateIssuanceError> {
        let issuer_key_id = issuer_key_id.into();
        let environment = environment.into();
        if !bounded_label(&issuer_key_id, MAX_ISSUER_KEY_ID_LEN) {
            return Err(CertificateIssuanceError::InvalidIssuerKeyId);
        }
        if !bounded_label(&environment, MAX_ENVIRONMENT_LEN) {
            return Err(CertificateIssuanceError::InvalidEnvironment);
        }

        let signing_key = KeyPair::from_pem(ca_private_key_pem)
            .map_err(|_| CertificateIssuanceError::InvalidIssuerMaterial)?;
        verify_ca_key_matches(ca_certificate_pem, &signing_key)?;
        let issuer = Issuer::from_ca_cert_pem(ca_certificate_pem, signing_key)
            .map_err(|_| CertificateIssuanceError::InvalidIssuerMaterial)?;

        Ok(Self {
            issuer_key_id,
            environment,
            issuer,
            certificate_chain_pem: ca_certificate_pem.to_owned(),
        })
    }

    pub fn issue(
        &self,
        device_id: Uuid,
        device_key_id: Uuid,
        operational_public_key: [u8; 32],
        assurance_level: u64,
        not_before: DateTime<Utc>,
    ) -> Result<IssuedDeviceCertificate, CertificateIssuanceError> {
        if device_id.is_nil() || device_key_id.is_nil() {
            return Err(CertificateIssuanceError::GenerationFailed);
        }
        if assurance_level > 3 {
            return Err(CertificateIssuanceError::InvalidAssuranceLevel);
        }

        let not_before = DateTime::from_timestamp(not_before.timestamp(), 0)
            .ok_or(CertificateIssuanceError::GenerationFailed)?;
        let public_key = ed25519_subject_public_key(&operational_public_key)?;
        let not_after = not_before + DEVICE_CERTIFICATE_TTL;
        let san_uri = format!("candy:device:{device_id}");
        let serial_uuid = Uuid::now_v7();
        let serial_number = *serial_uuid.as_bytes();
        let mut params = CertificateParams::default();
        params.not_before = to_offset_datetime(not_before)?;
        params.not_after = to_offset_datetime(not_after)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial_number));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = vec![
            uri_san(&san_uri)?,
            uri_san(&format!("candy:device-key:{device_key_id}"))?,
            uri_san(&format!("candy:environment:{}", self.environment))?,
            uri_san(&format!("candy:assurance:A{assurance_level}"))?,
        ];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, format!("Candy Device {device_id}"));
        params.distinguished_name = name;

        let certificate = params
            .signed_by(&public_key, &self.issuer)
            .map_err(|_| CertificateIssuanceError::GenerationFailed)?;
        Ok(IssuedDeviceCertificate {
            certificate_der: certificate.der().to_vec(),
            certificate_chain_pem: self.certificate_chain_pem.clone(),
            serial_number,
            issuer_key_id: self.issuer_key_id.clone(),
            san_uri,
            environment: self.environment.clone(),
            assurance_level,
            not_before,
            not_after,
        })
    }
}

fn verify_ca_key_matches(
    ca_certificate_pem: &str,
    signing_key: &KeyPair,
) -> Result<(), CertificateIssuanceError> {
    let (_, pem) = parse_x509_pem(ca_certificate_pem.as_bytes())
        .map_err(|_| CertificateIssuanceError::InvalidIssuerMaterial)?;
    let (_, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| CertificateIssuanceError::InvalidIssuerMaterial)?;
    if certificate.public_key().subject_public_key.data.as_ref() != signing_key.public_key_raw() {
        return Err(CertificateIssuanceError::IssuerKeyMismatch);
    }
    Ok(())
}

fn ed25519_subject_public_key(
    operational_public_key: &[u8; 32],
) -> Result<SubjectPublicKeyInfo, CertificateIssuanceError> {
    VerifyingKey::from_bytes(operational_public_key)
        .map_err(|_| CertificateIssuanceError::InvalidOperationalPublicKey)?;
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + operational_public_key.len());
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(operational_public_key);
    SubjectPublicKeyInfo::from_der(&spki)
        .map_err(|_| CertificateIssuanceError::InvalidOperationalPublicKey)
}

fn uri_san(value: &str) -> Result<SanType, CertificateIssuanceError> {
    Ok(SanType::URI(
        value
            .try_into()
            .map_err(|_| CertificateIssuanceError::GenerationFailed)?,
    ))
}

fn to_offset_datetime(value: DateTime<Utc>) -> Result<OffsetDateTime, CertificateIssuanceError> {
    OffsetDateTime::from_unix_timestamp(value.timestamp())
        .map_err(|_| CertificateIssuanceError::GenerationFailed)
}

fn bounded_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
