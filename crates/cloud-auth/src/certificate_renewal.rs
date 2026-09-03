use std::sync::Arc;

use chrono::{DateTime, Utc};
use cloud_db::certificate_renewal::{
    CertificateRenewalOutcome, CertificateRenewalRecord, CertificateRenewalRepository,
    CertificateRenewalScope, CertificateRenewalWrite,
};
use uuid::Uuid;

use crate::{
    certificates::{DeviceCertificateIssuer, NORMAL_RENEWAL_WINDOW},
    routes::AuthenticatedDevice,
};

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
    pub replayed: bool,
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
        let request_id = Uuid::parse_str(&command.request_id)
            .ok()
            .filter(|request_id| {
                !request_id.is_nil() && request_id.to_string() == command.request_id
            })
            .ok_or(CertificateRenewalError::InvalidRequest)?;
        let now = Utc::now();
        let actor = &command.actor;
        if let Some(record) = self
            .repository
            .load_replay(
                &CertificateRenewalScope {
                    organization_id: actor.organization_id(),
                    tenant_id: actor.tenant_id(),
                    device_id: actor.device_id(),
                    device_key_id: actor.device_key_id(),
                    authenticated_certificate_id: actor.certificate_id(),
                },
                request_id,
                now,
            )
            .await
            .map_err(|_| CertificateRenewalError::Unavailable)?
        {
            return Ok(receipt(record, true));
        }
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
        let replay_until = std::cmp::min(
            issued.not_before + crate::certificates::EMERGENCY_RENEWAL_WINDOW,
            identity.not_after,
        );
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
                replay_until,
            })
            .await
            .map_err(|_| CertificateRenewalError::Unavailable)?
        {
            CertificateRenewalOutcome::Renewed => Ok(CertificateRenewalReceipt {
                certificate_der: issued.certificate_der,
                certificate_chain_pem: issued.certificate_chain_pem,
                not_after: issued.not_after,
                replayed: false,
            }),
            CertificateRenewalOutcome::Replay(record) => Ok(receipt(record, true)),
            CertificateRenewalOutcome::IdentityChanged => {
                Err(CertificateRenewalError::IdentityChanged)
            }
        }
    }
}

fn receipt(record: CertificateRenewalRecord, replayed: bool) -> CertificateRenewalReceipt {
    CertificateRenewalReceipt {
        certificate_der: record.certificate_der,
        certificate_chain_pem: record.certificate_chain_pem,
        not_after: record.not_after,
        replayed,
    }
}
