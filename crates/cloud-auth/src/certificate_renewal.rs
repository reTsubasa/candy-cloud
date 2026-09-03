use std::sync::Arc;

use chrono::{DateTime, Utc};
use cloud_db::certificate_renewal::{
    CertificateRenewalOutcome, CertificateRenewalRepository, CertificateRenewalWrite,
};
use uuid::Uuid;

use crate::{
    certificates::{DeviceCertificateIssuer, NORMAL_RENEWAL_WINDOW},
    routes::AuthenticatedDevice,
};

pub const MAX_RENEWAL_REQUEST_ID_LEN: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalCommand {
    pub actor: AuthenticatedDevice,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalReceipt {
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertificateRenewalError {
    #[error("invalid certificate renewal request")]
    InvalidRequest,
    #[error("device certificate is not yet renewable")]
    NotDue,
    #[error("device certificate changed during renewal")]
    IdentityChanged,
    #[error("certificate renewal service unavailable")]
    Unavailable,
}

pub struct CertificateRenewalCoordinator {
    repository: CertificateRenewalRepository,
    issuer: Arc<DeviceCertificateIssuer>,
}

impl CertificateRenewalCoordinator {
    pub fn new(pool: cloud_db::DbPool, issuer: Arc<DeviceCertificateIssuer>) -> Self {
        Self {
            repository: CertificateRenewalRepository::new(pool),
            issuer,
        }
    }

    pub async fn renew(
        &self,
        command: CertificateRenewalCommand,
    ) -> Result<CertificateRenewalReceipt, CertificateRenewalError> {
        if !valid_request_id(&command.request_id) {
            return Err(CertificateRenewalError::InvalidRequest);
        }
        let now = Utc::now();
        let actor = &command.actor;
        let identity = self
            .repository
            .load_identity(
                actor.organization_id(),
                actor.tenant_id(),
                actor.device_id(),
                actor.device_key_id(),
                actor.certificate_id(),
                now,
            )
            .await
            .map_err(|_| CertificateRenewalError::Unavailable)?
            .ok_or(CertificateRenewalError::IdentityChanged)?;
        if identity.assurance_level != actor.assurance_level() {
            return Err(CertificateRenewalError::IdentityChanged);
        }
        if now < identity.not_after - NORMAL_RENEWAL_WINDOW {
            return Err(CertificateRenewalError::NotDue);
        }
        let issued = self
            .issuer
            .issue(
                identity.device_id,
                identity.device_key_id,
                identity.operational_public_key,
                identity.assurance_level,
                now,
            )
            .map_err(|_| CertificateRenewalError::Unavailable)?;
        let certificate_id = Uuid::now_v7();
        match self
            .repository
            .renew(&CertificateRenewalWrite {
                request_id: command.request_id,
                organization_id: identity.organization_id,
                tenant_id: identity.tenant_id,
                device_id: identity.device_id,
                device_key_id: identity.device_key_id,
                operational_public_key: identity.operational_public_key,
                previous_certificate_id: identity.certificate_id,
                certificate_id,
                issuer_key_id: issued.issuer_key_id,
                serial_number: issued.serial_number,
                certificate_der: issued.certificate_der.clone(),
                certificate_chain_pem: issued.certificate_chain_pem.clone(),
                san_uri: issued.san_uri,
                environment: issued.environment,
                assurance_level: issued.assurance_level,
                not_before: issued.not_before,
                not_after: issued.not_after,
                renewed_at: issued.not_before,
            })
            .await
            .map_err(|_| CertificateRenewalError::Unavailable)?
        {
            CertificateRenewalOutcome::Renewed => Ok(CertificateRenewalReceipt {
                certificate_der: issued.certificate_der,
                certificate_chain_pem: issued.certificate_chain_pem,
                not_after: issued.not_after,
            }),
            CertificateRenewalOutcome::IdentityChanged => {
                Err(CertificateRenewalError::IdentityChanged)
            }
        }
    }
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RENEWAL_REQUEST_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}
