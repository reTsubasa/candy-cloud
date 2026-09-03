use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{DbPool, RepositoryError};

const MAX_CERTIFICATE_DER_LEN: usize = 64 * 1024;
const MAX_ENVIRONMENT_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificateIdentityRecord {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub certificate_id: Uuid,
    pub assurance_level: u64,
}

#[derive(Clone)]
pub struct DeviceCertificateIdentityRepository {
    pool: DbPool,
}

impl DeviceCertificateIdentityRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn authenticate(
        &self,
        device_id: Uuid,
        device_key_id: Uuid,
        certificate_der: &[u8],
        environment: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceCertificateIdentityRecord>, RepositoryError> {
        if device_id.is_nil()
            || device_key_id.is_nil()
            || certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_DER_LEN
            || environment.is_empty()
            || environment.len() > MAX_ENVIRONMENT_LEN
        {
            return Err(RepositoryError::InvalidDeviceCertificateScope);
        }
        let row = sqlx::query(
            "SELECT dc.organization_id, dc.tenant_id, d.id AS device_id, dk.id AS device_key_id, dc.id AS certificate_id, dc.assurance_level FROM device_certificates dc JOIN organizations org ON org.id = dc.organization_id AND org.status = 'ACTIVE' JOIN tenants t ON t.id = dc.tenant_id AND t.organization_id = org.id AND t.status = 'ACTIVE' JOIN devices d ON d.id = dc.device_id AND d.tenant_id = dc.tenant_id JOIN device_keys dk ON dk.id = dc.device_key_id AND dk.device_id = d.id AND dk.tenant_id = dc.tenant_id WHERE d.id = ? AND dk.id = ? AND dc.certificate_der = ? AND dc.environment = ? AND d.status = 'ACTIVE' AND dk.status = 'ACTIVE' AND dc.status = 'ACTIVE' AND dc.not_before <= ? AND dc.not_after > ?",
        )
        .bind(device_id)
        .bind(device_key_id)
        .bind(certificate_der)
        .bind(environment)
        .bind(now)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(record_from_row).transpose()
    }

    pub async fn authenticate_for_certificate_renewal(
        &self,
        device_id: Uuid,
        device_key_id: Uuid,
        certificate_der: &[u8],
        environment: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<DeviceCertificateIdentityRecord>, RepositoryError> {
        if device_id.is_nil()
            || device_key_id.is_nil()
            || certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_DER_LEN
            || environment.is_empty()
            || environment.len() > MAX_ENVIRONMENT_LEN
        {
            return Err(RepositoryError::InvalidDeviceCertificateScope);
        }
        let row = sqlx::query(
            "SELECT dc.organization_id, dc.tenant_id, d.id AS device_id, dk.id AS device_key_id, dc.id AS certificate_id, dc.assurance_level FROM device_certificates dc JOIN organizations org ON org.id = dc.organization_id AND org.status = 'ACTIVE' JOIN tenants t ON t.id = dc.tenant_id AND t.organization_id = org.id AND t.status = 'ACTIVE' JOIN devices d ON d.id = dc.device_id AND d.tenant_id = dc.tenant_id JOIN device_keys dk ON dk.id = dc.device_key_id AND dk.device_id = d.id AND dk.tenant_id = dc.tenant_id WHERE d.id = ? AND dk.id = ? AND dc.certificate_der = ? AND dc.environment = ? AND d.status = 'ACTIVE' AND dk.status = 'ACTIVE' AND dc.not_before <= ? AND dc.not_after > ? AND (dc.status = 'ACTIVE' OR (dc.status = 'SUPERSEDED' AND EXISTS(SELECT 1 FROM device_certificate_renewals renewal WHERE renewal.previous_certificate_id = dc.id AND renewal.organization_id = dc.organization_id AND renewal.tenant_id = dc.tenant_id AND renewal.device_id = dc.device_id AND renewal.device_key_id = dc.device_key_id AND renewal.replay_until > ?)))",
        )
        .bind(device_id)
        .bind(device_key_id)
        .bind(certificate_der)
        .bind(environment)
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(record_from_row).transpose()
    }
}

fn record_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<DeviceCertificateIdentityRecord, RepositoryError> {
    let record = DeviceCertificateIdentityRecord {
        organization_id: row.try_get("organization_id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        device_key_id: row.try_get("device_key_id")?,
        certificate_id: row.try_get("certificate_id")?,
        assurance_level: row.try_get("assurance_level")?,
    };
    if record.organization_id.is_nil()
        || record.tenant_id.is_nil()
        || record.device_id.is_nil()
        || record.device_key_id.is_nil()
        || record.certificate_id.is_nil()
        || record.assurance_level > 3
    {
        return Err(RepositoryError::InvalidDeviceCertificateRecord);
    }
    Ok(record)
}
