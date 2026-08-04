use chrono::{DateTime, Utc};
use sqlx::{Row, Transaction};
use uuid::Uuid;

use crate::{DbPool, MySql};

pub const MAX_DEVICE_IDENTITY_LEN: usize = 36;
pub const MAX_WORKER_LEASE_FIELD_LEN: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepositoryValidationError {
    #[error("invalid tenant id")]
    InvalidTenantId,
    #[error("invalid device identity")]
    InvalidDeviceIdentity,
    #[error("invalid lease name")]
    InvalidLeaseName,
    #[error("invalid lease owner")]
    InvalidLeaseOwner,
    #[error("invalid lease expiry")]
    InvalidLeaseExpiry,
}

impl RepositoryValidationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTenantId => "invalid_tenant_id",
            Self::InvalidDeviceIdentity => "invalid_device_identity",
            Self::InvalidLeaseName => "invalid_lease_name",
            Self::InvalidLeaseOwner => "invalid_lease_owner",
            Self::InvalidLeaseExpiry => "invalid_lease_expiry",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("invalid device status in database")]
    InvalidDeviceStatus,
    #[error("audit events require organization and tenant scope")]
    InvalidAuditScope,
    #[error("grant issuance requires tenant, device and request scope")]
    InvalidGrantScope,
    #[error("authorization snapshot requires tenant, device, key and node pool scope")]
    InvalidAuthorizationScope,
    #[error("invalid persisted Grant record")]
    InvalidGrantRecord,
    #[error("enrollment requires tenant, device, key and actor scope")]
    InvalidEnrollmentScope,
    #[error("activation code requires organization, tenant, hash, expiry and actor scope")]
    InvalidActivationScope,
    #[error("enrollment challenge requires bounded identity, key, request and expiry fields")]
    InvalidChallengeScope,
    #[error("invalid persisted enrollment challenge")]
    InvalidChallengeRecord,
    #[error("enrollment completion requires bounded challenge, identity and certificate fields")]
    InvalidCompletionScope,
    #[error("invalid persisted enrollment completion")]
    InvalidCompletionRecord,
    #[error("device certificate authentication requires bounded identity and certificate fields")]
    InvalidDeviceCertificateScope,
    #[error("invalid persisted device certificate identity")]
    InvalidDeviceCertificateRecord,
    #[error("tenant not found")]
    TenantNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLookup {
    tenant_id: Uuid,
    device_identity: String,
}

impl DeviceLookup {
    pub fn new(
        tenant_id: Uuid,
        device_identity: impl Into<String>,
    ) -> Result<Self, RepositoryValidationError> {
        let device_identity = device_identity.into();
        if tenant_id.is_nil() {
            return Err(RepositoryValidationError::InvalidTenantId);
        }
        if device_identity.len() != MAX_DEVICE_IDENTITY_LEN
            || Uuid::parse_str(&device_identity).map(|parsed| parsed.to_string() == device_identity)
                != Ok(true)
        {
            return Err(RepositoryValidationError::InvalidDeviceIdentity);
        }
        Ok(Self {
            tenant_id,
            device_identity,
        })
    }

    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn device_identity(&self) -> &str {
        &self.device_identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

impl TryFrom<&str> for DeviceStatus {
    type Error = RepositoryError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "ACTIVE" => Ok(Self::Active),
            "SUSPENDED" => Ok(Self::Suspended),
            "REVOKED" => Ok(Self::Revoked),
            _ => Err(RepositoryError::InvalidDeviceStatus),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_identity: String,
    pub display_name: String,
    pub status: DeviceStatus,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct DeviceRepository {
    pool: DbPool,
}

impl DeviceRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Finds a device only within its explicit tenant boundary.
    pub async fn find_by_identity(
        &self,
        lookup: &DeviceLookup,
    ) -> Result<Option<DeviceRecord>, RepositoryError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, device_id, display_name, status, created_at, last_seen_at \
             FROM devices WHERE tenant_id = ? AND device_id = ?",
        )
        .bind(lookup.tenant_id)
        .bind(&lookup.device_identity)
        .fetch_optional(&self.pool)
        .await?;

        row.map(device_from_row).transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseAcquireRequest {
    lease_name: String,
    owner_id: String,
    acquired_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl LeaseAcquireRequest {
    pub fn new(
        lease_name: impl Into<String>,
        owner_id: impl Into<String>,
        acquired_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, RepositoryValidationError> {
        let lease_name = lease_name.into();
        let owner_id = owner_id.into();
        if !bounded_non_empty(&lease_name, MAX_WORKER_LEASE_FIELD_LEN) {
            return Err(RepositoryValidationError::InvalidLeaseName);
        }
        if !bounded_non_empty(&owner_id, MAX_WORKER_LEASE_FIELD_LEN) {
            return Err(RepositoryValidationError::InvalidLeaseOwner);
        }
        if expires_at <= acquired_at {
            return Err(RepositoryValidationError::InvalidLeaseExpiry);
        }
        Ok(Self {
            lease_name,
            owner_id,
            acquired_at,
            expires_at,
        })
    }

    pub fn lease_name(&self) -> &str {
        &self.lease_name
    }

    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAcquireOutcome {
    Acquired,
    HeldByOther,
}

#[derive(Clone)]
pub struct WorkerLeaseRepository {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub object_type: String,
    pub object_id: String,
    pub metadata_json: String,
}

#[derive(Clone)]
pub struct AuditRepository {
    pool: DbPool,
}

impl AuditRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn append(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        if event.organization_id.is_nil() || event.tenant_id.is_nil() {
            return Err(RepositoryError::InvalidAuditScope);
        }
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.id)
        .bind(event.organization_id)
        .bind(event.tenant_id)
        .bind(&event.actor_type)
        .bind(&event.actor_id)
        .bind(&event.action)
        .bind(&event.object_type)
        .bind(&event.object_id)
        .bind(&event.metadata_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantIssuanceWrite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub request_id: String,
    pub authorization_generation: u64,
    pub request_fingerprint: [u8; 32],
    pub key_id: String,
    pub grant_digest: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGrantRecord {
    pub grant_id: Uuid,
    pub request_fingerprint: [u8; 32],
    pub key_id: String,
    pub grant_digest: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRecordOutcome {
    Inserted(StoredGrantRecord),
    Replayed(StoredGrantRecord),
    Conflict,
}

#[derive(Clone)]
pub struct GrantIssuanceRepository {
    pool: DbPool,
}

impl GrantIssuanceRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn record(
        &self,
        write: &GrantIssuanceWrite,
    ) -> Result<GrantRecordOutcome, RepositoryError> {
        if write.tenant_id.is_nil() || write.device_id.is_nil() || write.request_id.is_empty() {
            return Err(RepositoryError::InvalidGrantScope);
        }
        let inserted = sqlx::query(
            "INSERT IGNORE INTO grant_issuance_records (id, tenant_id, device_id, request_id, authorization_generation, request_fingerprint, key_id, grant_digest, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(write.id)
        .bind(write.tenant_id)
        .bind(write.device_id)
        .bind(&write.request_id)
        .bind(write.authorization_generation)
        .bind(write.request_fingerprint.as_slice())
        .bind(&write.key_id)
        .bind(write.grant_digest.as_slice())
        .bind(write.expires_at)
        .execute(&self.pool)
        .await?
        .rows_affected() == 1;
        if inserted {
            return Ok(GrantRecordOutcome::Inserted(StoredGrantRecord {
                grant_id: write.id,
                request_fingerprint: write.request_fingerprint,
                key_id: write.key_id.clone(),
                grant_digest: write.grant_digest,
                expires_at: write.expires_at,
            }));
        }

        let row = sqlx::query(
            "SELECT id, request_fingerprint, key_id, grant_digest, expires_at FROM grant_issuance_records WHERE device_id = ? AND authorization_generation = ? AND request_id = ? AND tenant_id = ?",
        )
        .bind(write.device_id)
        .bind(write.authorization_generation)
        .bind(&write.request_id)
        .bind(write.tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let fingerprint: Vec<u8> = row.try_get("request_fingerprint")?;
        Ok(if fingerprint.as_slice() == write.request_fingerprint {
            GrantRecordOutcome::Replayed(stored_grant_from_row(row, fingerprint)?)
        } else {
            GrantRecordOutcome::Conflict
        })
    }
}

fn stored_grant_from_row(
    row: sqlx::mysql::MySqlRow,
    fingerprint: Vec<u8>,
) -> Result<StoredGrantRecord, RepositoryError> {
    let request_fingerprint = fingerprint
        .try_into()
        .map_err(|_| RepositoryError::InvalidGrantRecord)?;
    let digest: Vec<u8> = row.try_get("grant_digest")?;
    let grant_digest = digest
        .try_into()
        .map_err(|_| RepositoryError::InvalidGrantRecord)?;
    Ok(StoredGrantRecord {
        grant_id: row.try_get("id")?,
        request_fingerprint,
        key_id: row.try_get("key_id")?,
        grant_digest,
        expires_at: row.try_get("expires_at")?,
    })
}

impl WorkerLeaseRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Acquires or renews a named lease. The conditional update prevents an active foreign owner
    /// from being replaced, and the transaction makes the outcome safe for duplicate workers.
    pub async fn acquire(
        &self,
        request: &LeaseAcquireRequest,
    ) -> Result<LeaseAcquireOutcome, RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO worker_leases (lease_name, owner_id, lease_until) VALUES (?, ?, ?)",
        )
        .bind(&request.lease_name)
        .bind(&request.owner_id)
        .bind(request.expires_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;

        if !inserted {
            sqlx::query(
                "UPDATE worker_leases SET owner_id = ?, lease_until = ? \
                 WHERE lease_name = ? AND (lease_until <= ? OR owner_id = ?)",
            )
            .bind(&request.owner_id)
            .bind(request.expires_at)
            .bind(&request.lease_name)
            .bind(request.acquired_at)
            .bind(&request.owner_id)
            .execute(&mut *transaction)
            .await?;
        }

        let outcome = lease_outcome(&mut transaction, request).await?;
        transaction.commit().await?;
        Ok(outcome)
    }
}

fn device_from_row(row: sqlx::mysql::MySqlRow) -> Result<DeviceRecord, RepositoryError> {
    let status: String = row.try_get("status")?;
    Ok(DeviceRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        device_identity: row.try_get("device_id")?,
        display_name: row.try_get("display_name")?,
        status: DeviceStatus::try_from(status.as_str())?,
        created_at: row.try_get("created_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}

async fn lease_outcome(
    transaction: &mut Transaction<'_, MySql>,
    request: &LeaseAcquireRequest,
) -> Result<LeaseAcquireOutcome, RepositoryError> {
    let row = sqlx::query("SELECT owner_id FROM worker_leases WHERE lease_name = ? FOR UPDATE")
        .bind(&request.lease_name)
        .fetch_one(&mut **transaction)
        .await?;
    let owner_id: String = row.try_get("owner_id")?;
    Ok(if owner_id == request.owner_id {
        LeaseAcquireOutcome::Acquired
    } else {
        LeaseAcquireOutcome::HeldByOther
    })
}

fn bounded_non_empty(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum
}
