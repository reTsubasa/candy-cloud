use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{DbPool, RepositoryError};

const MAX_REQUEST_ID_LEN: usize = 120;
const MAX_CERTIFICATE_DER_LEN: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_LEN: usize = 1024 * 1024;
const MAX_ISSUER_KEY_ID_LEN: usize = 80;
const MAX_ENVIRONMENT_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalIdentity {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub certificate_id: Uuid,
    pub operational_public_key: [u8; 32],
    pub assurance_level: u64,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalScope {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub authenticated_certificate_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalWrite {
    pub request_id: String,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub operational_public_key: [u8; 32],
    pub previous_certificate_id: Uuid,
    pub certificate_id: Uuid,
    pub issuer_key_id: String,
    pub serial_number: [u8; 16],
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub san_uri: String,
    pub environment: String,
    pub assurance_level: u64,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub renewed_at: DateTime<Utc>,
    pub replay_until: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewalRecord {
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRenewalOutcome {
    Renewed,
    Replay(CertificateRenewalRecord),
    IdentityChanged,
}

#[derive(Clone)]
pub struct CertificateRenewalRepository {
    pool: DbPool,
}

impl CertificateRenewalRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn load_identity(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
        certificate_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<CertificateRenewalIdentity>, RepositoryError> {
        if [
            organization_id,
            tenant_id,
            device_id,
            device_key_id,
            certificate_id,
        ]
        .iter()
        .any(Uuid::is_nil)
        {
            return Err(RepositoryError::InvalidDeviceCertificateScope);
        }
        let row = sqlx::query(
            "SELECT dc.organization_id, dc.tenant_id, dc.device_id, dc.device_key_id, dc.id AS certificate_id, dk.public_key, dc.assurance_level, dc.not_after FROM device_certificates dc JOIN organizations org ON org.id = dc.organization_id AND org.status = 'ACTIVE' JOIN tenants t ON t.id = dc.tenant_id AND t.organization_id = org.id AND t.status = 'ACTIVE' JOIN devices d ON d.id = dc.device_id AND d.tenant_id = dc.tenant_id AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.id = dc.device_key_id AND dk.device_id = d.id AND dk.tenant_id = dc.tenant_id AND dk.status = 'ACTIVE' WHERE dc.organization_id = ? AND dc.tenant_id = ? AND dc.device_id = ? AND dc.device_key_id = ? AND dc.id = ? AND dc.status = 'ACTIVE' AND dc.not_before <= ? AND dc.not_after > ?",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id)
        .bind(certificate_id)
        .bind(now)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(identity_from_row).transpose()
    }

    pub async fn load_replay(
        &self,
        scope: &CertificateRenewalScope,
        request_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<CertificateRenewalRecord>, RepositoryError> {
        if [
            scope.organization_id,
            scope.tenant_id,
            scope.device_id,
            scope.device_key_id,
            scope.authenticated_certificate_id,
            request_id,
        ]
        .iter()
        .any(Uuid::is_nil)
        {
            return Err(RepositoryError::InvalidDeviceCertificateScope);
        }
        let row = sqlx::query(
            "SELECT dc.certificate_der, dc.certificate_chain_pem, dc.not_after FROM device_certificate_renewals renewal JOIN device_certificates dc ON dc.id = renewal.certificate_id AND dc.organization_id = renewal.organization_id AND dc.tenant_id = renewal.tenant_id AND dc.device_id = renewal.device_id AND dc.device_key_id = renewal.device_key_id WHERE renewal.organization_id = ? AND renewal.tenant_id = ? AND renewal.device_id = ? AND renewal.device_key_id = ? AND renewal.request_id = ? AND (renewal.previous_certificate_id = ? OR renewal.certificate_id = ?) AND renewal.replay_until > ?",
        )
        .bind(scope.organization_id)
        .bind(scope.tenant_id)
        .bind(scope.device_id)
        .bind(scope.device_key_id)
        .bind(request_id.to_string())
        .bind(scope.authenticated_certificate_id)
        .bind(scope.authenticated_certificate_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(renewal_record_from_row).transpose()
    }

    pub async fn renew(
        &self,
        write: &CertificateRenewalWrite,
    ) -> Result<CertificateRenewalOutcome, RepositoryError> {
        validate_write(write)?;
        let mut transaction = self.pool.begin().await?;
        let replay = sqlx::query(
            "SELECT renewal.previous_certificate_id, renewal.replay_until, dc.certificate_der, dc.certificate_chain_pem, dc.not_after FROM device_certificate_renewals renewal JOIN device_certificates dc ON dc.id = renewal.certificate_id WHERE renewal.organization_id = ? AND renewal.tenant_id = ? AND renewal.device_id = ? AND renewal.device_key_id = ? AND renewal.request_id = ? FOR UPDATE",
        )
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(write.device_key_id)
        .bind(&write.request_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(replay) = replay {
            if replay.try_get::<Uuid, _>("previous_certificate_id")?
                != write.previous_certificate_id
                || replay.try_get::<DateTime<Utc>, _>("replay_until")? <= write.renewed_at
            {
                transaction.rollback().await?;
                return Ok(CertificateRenewalOutcome::IdentityChanged);
            }
            let record = renewal_record_from_row(replay)?;
            transaction.commit().await?;
            return Ok(CertificateRenewalOutcome::Replay(record));
        }
        let current = sqlx::query(
            "SELECT dc.id FROM device_certificates dc JOIN organizations org ON org.id = dc.organization_id AND org.status = 'ACTIVE' JOIN tenants t ON t.id = dc.tenant_id AND t.organization_id = org.id AND t.status = 'ACTIVE' JOIN devices d ON d.id = dc.device_id AND d.tenant_id = dc.tenant_id AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.id = dc.device_key_id AND dk.device_id = d.id AND dk.tenant_id = dc.tenant_id AND dk.status = 'ACTIVE' WHERE dc.organization_id = ? AND dc.tenant_id = ? AND dc.device_id = ? AND dc.device_key_id = ? AND dk.public_key = ? AND dk.assurance_level = ? AND dc.assurance_level = ? AND dc.id = ? AND dc.status = 'ACTIVE' AND dc.not_before <= ? AND dc.not_after > ? FOR UPDATE",
        )
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(write.device_key_id)
        .bind(write.operational_public_key.as_slice())
        .bind(write.assurance_level)
        .bind(write.assurance_level)
        .bind(write.previous_certificate_id)
        .bind(write.renewed_at)
        .bind(write.renewed_at)
        .fetch_optional(&mut *transaction)
        .await?;
        if current.is_none() {
            let replay = sqlx::query(
                "SELECT renewal.previous_certificate_id, renewal.replay_until, dc.certificate_der, dc.certificate_chain_pem, dc.not_after FROM device_certificate_renewals renewal JOIN device_certificates dc ON dc.id = renewal.certificate_id WHERE renewal.organization_id = ? AND renewal.tenant_id = ? AND renewal.device_id = ? AND renewal.device_key_id = ? AND renewal.request_id = ? FOR UPDATE",
            )
            .bind(write.organization_id)
            .bind(write.tenant_id)
            .bind(write.device_id)
            .bind(write.device_key_id)
            .bind(&write.request_id)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(replay) = replay {
                if replay.try_get::<Uuid, _>("previous_certificate_id")?
                    == write.previous_certificate_id
                    && replay.try_get::<DateTime<Utc>, _>("replay_until")? > write.renewed_at
                {
                    let record = renewal_record_from_row(replay)?;
                    transaction.commit().await?;
                    return Ok(CertificateRenewalOutcome::Replay(record));
                }
            }
            transaction.rollback().await?;
            return Ok(CertificateRenewalOutcome::IdentityChanged);
        }

        let superseded = sqlx::query(
            "UPDATE device_certificates SET status = 'SUPERSEDED', revoked_at = ? WHERE id = ? AND organization_id = ? AND tenant_id = ? AND device_id = ? AND device_key_id = ? AND status = 'ACTIVE'",
        )
        .bind(write.renewed_at)
        .bind(write.previous_certificate_id)
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(write.device_key_id)
        .execute(&mut *transaction)
        .await?;
        if superseded.rows_affected() != 1 {
            transaction.rollback().await?;
            return Ok(CertificateRenewalOutcome::IdentityChanged);
        }
        sqlx::query(
            "INSERT INTO device_certificates (id, organization_id, tenant_id, device_id, device_key_id, issuer_key_id, serial_number, certificate_der, certificate_chain_pem, san_uri, environment, assurance_level, not_before, not_after, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(write.certificate_id)
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(write.device_key_id)
        .bind(&write.issuer_key_id)
        .bind(write.serial_number.as_slice())
        .bind(&write.certificate_der)
        .bind(&write.certificate_chain_pem)
        .bind(&write.san_uri)
        .bind(&write.environment)
        .bind(write.assurance_level)
        .bind(write.not_before)
        .bind(write.not_after)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO device_certificate_renewals (id, organization_id, tenant_id, device_id, device_key_id, previous_certificate_id, certificate_id, request_id, replay_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7())
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(write.device_key_id)
        .bind(write.previous_certificate_id)
        .bind(write.certificate_id)
        .bind(&write.request_id)
        .bind(write.replay_until)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'DEVICE', ?, 'DEVICE_CERTIFICATE_RENEWED', 'DEVICE_CERTIFICATE', ?, JSON_OBJECT('request_id', ?, 'previous_certificate_id', ?, 'device_key_id', ?, 'status', 'ACTIVE'))",
        )
        .bind(Uuid::new_v4())
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.device_id.to_string())
        .bind(write.certificate_id.to_string())
        .bind(&write.request_id)
        .bind(write.previous_certificate_id.to_string())
        .bind(write.device_key_id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(CertificateRenewalOutcome::Renewed)
    }
}

fn identity_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<CertificateRenewalIdentity, RepositoryError> {
    let public_key: Vec<u8> = row.try_get("public_key")?;
    let identity = CertificateRenewalIdentity {
        organization_id: row.try_get("organization_id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_id: row.try_get("device_id")?,
        device_key_id: row.try_get("device_key_id")?,
        certificate_id: row.try_get("certificate_id")?,
        operational_public_key: public_key
            .try_into()
            .map_err(|_| RepositoryError::InvalidDeviceCertificateRecord)?,
        assurance_level: row.try_get("assurance_level")?,
        not_after: row.try_get("not_after")?,
    };
    if identity.assurance_level > 3 {
        return Err(RepositoryError::InvalidDeviceCertificateRecord);
    }
    Ok(identity)
}

fn renewal_record_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<CertificateRenewalRecord, RepositoryError> {
    let record = CertificateRenewalRecord {
        certificate_der: row.try_get("certificate_der")?,
        certificate_chain_pem: row.try_get("certificate_chain_pem")?,
        not_after: row.try_get("not_after")?,
    };
    if record.certificate_der.is_empty()
        || record.certificate_der.len() > MAX_CERTIFICATE_DER_LEN
        || record.certificate_chain_pem.is_empty()
        || record.certificate_chain_pem.len() > MAX_CERTIFICATE_CHAIN_LEN
    {
        return Err(RepositoryError::InvalidDeviceCertificateRecord);
    }
    Ok(record)
}

fn validate_write(write: &CertificateRenewalWrite) -> Result<(), RepositoryError> {
    if !bounded(&write.request_id, MAX_REQUEST_ID_LEN)
        || Uuid::parse_str(&write.request_id)
            .map(|request_id| !request_id.is_nil() && request_id.to_string() == write.request_id)
            != Ok(true)
        || [
            write.organization_id,
            write.tenant_id,
            write.device_id,
            write.device_key_id,
            write.previous_certificate_id,
            write.certificate_id,
        ]
        .iter()
        .any(Uuid::is_nil)
        || write.certificate_id.get_version_num() != 7
        || write.previous_certificate_id == write.certificate_id
        || !bounded(&write.issuer_key_id, MAX_ISSUER_KEY_ID_LEN)
        || write.serial_number == [0; 16]
        || write.certificate_der.is_empty()
        || write.certificate_der.len() > MAX_CERTIFICATE_DER_LEN
        || write.certificate_chain_pem.is_empty()
        || write.certificate_chain_pem.len() > MAX_CERTIFICATE_CHAIN_LEN
        || write.san_uri != format!("candy:device:{}", write.device_id)
        || !bounded(&write.environment, MAX_ENVIRONMENT_LEN)
        || write.assurance_level > 3
        || write.not_before != write.renewed_at
        || write.not_after <= write.not_before
        || write.replay_until <= write.renewed_at
        || write.replay_until > write.not_after
    {
        return Err(RepositoryError::InvalidDeviceCertificateScope);
    }
    Ok(())
}

fn bounded(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}
