use chrono::{DateTime, Utc};
use cloud_db::{device_identity::DeviceCertificateIdentityRepository, DbPool};
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use crate::routes::AuthenticatedDevice;

const MAX_ENVIRONMENT_LEN: usize = 40;
const ED25519_OID: &str = "1.3.101.112";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceIdentityError {
    #[error("invalid device certificate")]
    InvalidCertificate,
    #[error("device certificate is not active")]
    InactiveCertificate,
    #[error("device identity service unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct DeviceIdentityAuthenticator {
    identities: DeviceCertificateIdentityRepository,
    environment: String,
}

impl DeviceIdentityAuthenticator {
    pub fn new(pool: DbPool, environment: impl Into<String>) -> Result<Self, DeviceIdentityError> {
        let environment = environment.into();
        if environment.is_empty()
            || environment.len() > MAX_ENVIRONMENT_LEN
            || !environment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(DeviceIdentityError::InvalidCertificate);
        }
        Ok(Self {
            identities: DeviceCertificateIdentityRepository::new(pool),
            environment,
        })
    }

    pub async fn authenticate_verified_certificate(
        &self,
        certificate_der: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedDevice, DeviceIdentityError> {
        let claims = parse_claims(certificate_der, &self.environment)?;
        let record = self
            .identities
            .authenticate(
                claims.device_id,
                claims.device_key_id,
                certificate_der,
                &self.environment,
                now,
            )
            .await
            .map_err(|_| DeviceIdentityError::Unavailable)?
            .ok_or(DeviceIdentityError::InactiveCertificate)?;
        if record.assurance_level != claims.assurance_level {
            return Err(DeviceIdentityError::InvalidCertificate);
        }
        AuthenticatedDevice::new(
            record.organization_id,
            record.tenant_id,
            record.device_id,
            record.device_key_id,
            record.certificate_id,
            record.assurance_level,
        )
        .map_err(|_| DeviceIdentityError::InvalidCertificate)
    }

    pub async fn authenticate_verified_renewal_certificate(
        &self,
        certificate_der: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedDevice, DeviceIdentityError> {
        let claims = parse_claims(certificate_der, &self.environment)?;
        let record = self
            .identities
            .authenticate_for_certificate_renewal(
                claims.device_id,
                claims.device_key_id,
                certificate_der,
                &self.environment,
                now,
            )
            .await
            .map_err(|_| DeviceIdentityError::Unavailable)?
            .ok_or(DeviceIdentityError::InactiveCertificate)?;
        if record.assurance_level != claims.assurance_level {
            return Err(DeviceIdentityError::InvalidCertificate);
        }
        AuthenticatedDevice::new(
            record.organization_id,
            record.tenant_id,
            record.device_id,
            record.device_key_id,
            record.certificate_id,
            record.assurance_level,
        )
        .map_err(|_| DeviceIdentityError::InvalidCertificate)
    }
}

struct DeviceCertificateClaims {
    device_id: Uuid,
    device_key_id: Uuid,
    assurance_level: u64,
}

fn parse_claims(
    certificate_der: &[u8],
    expected_environment: &str,
) -> Result<DeviceCertificateClaims, DeviceIdentityError> {
    let (remaining, certificate) = parse_x509_certificate(certificate_der)
        .map_err(|_| DeviceIdentityError::InvalidCertificate)?;
    if !remaining.is_empty()
        || certificate.public_key().algorithm.algorithm.to_id_string() != ED25519_OID
        || certificate.public_key().subject_public_key.data.len() != 32
    {
        return Err(DeviceIdentityError::InvalidCertificate);
    }
    let sans = certificate
        .subject_alternative_name()
        .map_err(|_| DeviceIdentityError::InvalidCertificate)?
        .ok_or(DeviceIdentityError::InvalidCertificate)?;
    let mut device_id = None;
    let mut device_key_id = None;
    let mut environment = None;
    let mut assurance_level = None;
    for name in &sans.value.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };
        if let Some(value) = uri.strip_prefix("candy:device:") {
            set_once(&mut device_id, parse_uuid(value)?)?;
        } else if let Some(value) = uri.strip_prefix("candy:device-key:") {
            set_once(&mut device_key_id, parse_uuid(value)?)?;
        } else if let Some(value) = uri.strip_prefix("candy:environment:") {
            set_once(&mut environment, value.to_owned())?;
        } else if let Some(value) = uri.strip_prefix("candy:assurance:A") {
            let assurance = value
                .parse::<u64>()
                .map_err(|_| DeviceIdentityError::InvalidCertificate)?;
            if assurance > 3 {
                return Err(DeviceIdentityError::InvalidCertificate);
            }
            set_once(&mut assurance_level, assurance)?;
        }
    }
    if environment.as_deref() != Some(expected_environment) {
        return Err(DeviceIdentityError::InvalidCertificate);
    }
    Ok(DeviceCertificateClaims {
        device_id: device_id.ok_or(DeviceIdentityError::InvalidCertificate)?,
        device_key_id: device_key_id.ok_or(DeviceIdentityError::InvalidCertificate)?,
        assurance_level: assurance_level.ok_or(DeviceIdentityError::InvalidCertificate)?,
    })
}

fn parse_uuid(value: &str) -> Result<Uuid, DeviceIdentityError> {
    let parsed = Uuid::parse_str(value).map_err(|_| DeviceIdentityError::InvalidCertificate)?;
    if parsed.to_string() != value {
        return Err(DeviceIdentityError::InvalidCertificate);
    }
    Ok(parsed)
}

fn set_once<T>(target: &mut Option<T>, value: T) -> Result<(), DeviceIdentityError> {
    if target.replace(value).is_some() {
        return Err(DeviceIdentityError::InvalidCertificate);
    }
    Ok(())
}
