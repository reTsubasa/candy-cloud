use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{DbPool, RepositoryError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentWrite {
    pub device_record_id: Uuid,
    pub tenant_id: Uuid,
    pub device_identity: Uuid,
    pub display_name: String,
    pub key_record_id: Uuid,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub assurance_level: u64,
    pub actor_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    Inserted,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCodeWrite {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub code_hash: [u8; 32],
    pub expires_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCodeOutcome {
    Inserted,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallengeWrite {
    pub id: Uuid,
    pub request_id: String,
    pub request_fingerprint: [u8; 32],
    pub enrollment_instance_id: String,
    pub display_name: String,
    pub root_public_key: [u8; 32],
    pub operational_public_key: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub attestation_hash: [u8; 32],
    pub server_nonce: [u8; 32],
    pub assurance_level: u64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentChallengeStatus {
    Pending,
    Challenged,
    Proved,
    Issued,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentChallengeRecord {
    pub id: Uuid,
    pub activation_code_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub request_id: String,
    pub request_fingerprint: [u8; 32],
    pub operational_public_key: [u8; 32],
    pub server_nonce: [u8; 32],
    pub status: EnrollmentChallengeStatus,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentProofChallengeRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub enrollment_instance_id: String,
    pub display_name: String,
    pub root_public_key: [u8; 32],
    pub operational_public_key: [u8; 32],
    pub metadata_hash: [u8; 32],
    pub attestation_hash: [u8; 32],
    pub server_nonce: [u8; 32],
    pub assurance_level: u64,
    pub status: EnrollmentChallengeStatus,
    pub expires_at: DateTime<Utc>,
    pub completion_request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeCreationOutcome {
    Created(EnrollmentChallengeRecord),
    Replay(EnrollmentChallengeRecord),
    Conflict,
    ActivationUnavailable,
}

#[derive(Clone)]
pub struct EnrollmentRepository {
    pool: DbPool,
}

impl EnrollmentRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        write: &EnrollmentWrite,
    ) -> Result<EnrollmentOutcome, RepositoryError> {
        if write.tenant_id.is_nil()
            || write.device_record_id.is_nil()
            || write.key_record_id.is_nil()
            || write.actor_id.is_empty()
        {
            return Err(RepositoryError::InvalidEnrollmentScope);
        }
        let mut transaction = self.pool.begin().await?;
        let organization_id: Uuid =
            sqlx::query("SELECT organization_id FROM tenants WHERE id = ? FOR SHARE")
                .bind(write.tenant_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(RepositoryError::TenantNotFound)?
                .try_get("organization_id")?;
        let inserted = sqlx::query(
            "INSERT IGNORE INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'PENDING')",
        )
        .bind(write.device_record_id)
        .bind(write.tenant_id)
        .bind(write.device_identity.to_string())
        .bind(&write.display_name)
        .execute(&mut *transaction)
        .await?
        .rows_affected() == 1;
        if !inserted {
            transaction.rollback().await?;
            return Ok(EnrollmentOutcome::Conflict);
        }
        sqlx::query(
            "INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, assurance_level, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(write.key_record_id)
        .bind(write.tenant_id)
        .bind(write.device_record_id)
        .bind(&write.key_id)
        .bind(write.public_key.as_slice())
        .bind(write.assurance_level)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'DEVICE', ?, 'DEVICE_ENROLLMENT_REQUESTED', 'DEVICE', ?, JSON_OBJECT('status', 'PENDING'))",
        )
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind(write.tenant_id)
        .bind(&write.actor_id)
        .bind(write.device_record_id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(EnrollmentOutcome::Inserted)
    }

    pub async fn insert_activation_code(
        &self,
        write: &ActivationCodeWrite,
    ) -> Result<ActivationCodeOutcome, RepositoryError> {
        if write.id.is_nil()
            || write.organization_id.is_nil()
            || write.tenant_id.is_nil()
            || write.code_hash == [0; 32]
            || write.created_by.is_empty()
            || write.created_by.len() > 120
            || write.expires_at <= Utc::now()
        {
            return Err(RepositoryError::InvalidActivationScope);
        }

        let mut transaction = self.pool.begin().await?;
        let tenant_organization: Option<Uuid> =
            sqlx::query_scalar("SELECT organization_id FROM tenants WHERE id = ? FOR SHARE")
                .bind(write.tenant_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if tenant_organization != Some(write.organization_id) {
            transaction.rollback().await?;
            return Err(RepositoryError::InvalidActivationScope);
        }

        let inserted = sqlx::query(
            "INSERT INTO enrollment_activation_codes (id, organization_id, tenant_id, code_hash, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(write.id)
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.code_hash.as_slice())
        .bind(write.expires_at)
        .bind(&write.created_by)
        .execute(&mut *transaction)
        .await;
        if let Err(sqlx::Error::Database(error)) = &inserted {
            if error.is_unique_violation() {
                transaction.rollback().await?;
                return Ok(ActivationCodeOutcome::Conflict);
            }
        }
        inserted?;

        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'USER', ?, 'ENROLLMENT_ACTIVATION_CREATED', 'ENROLLMENT_ACTIVATION', ?, JSON_OBJECT('expires_at', ?))",
        )
        .bind(Uuid::new_v4())
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(&write.created_by)
        .bind(write.id.to_string())
        .bind(write.expires_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ActivationCodeOutcome::Inserted)
    }

    pub async fn reserve_challenge(
        &self,
        activation_code_hash: &[u8; 32],
        write: &EnrollmentChallengeWrite,
        now: DateTime<Utc>,
    ) -> Result<ChallengeCreationOutcome, RepositoryError> {
        validate_challenge(write, now)?;
        if *activation_code_hash == [0; 32] {
            return Err(RepositoryError::InvalidChallengeScope);
        }

        let mut transaction = self.pool.begin().await?;
        let activation = sqlx::query(
            "SELECT id, organization_id, tenant_id, status, expires_at FROM enrollment_activation_codes WHERE code_hash = ? FOR UPDATE",
        )
        .bind(activation_code_hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(activation) = activation else {
            transaction.rollback().await?;
            return Ok(ChallengeCreationOutcome::ActivationUnavailable);
        };
        let activation_id: Uuid = activation.try_get("id")?;
        let organization_id: Uuid = activation.try_get("organization_id")?;
        let tenant_id: Uuid = activation.try_get("tenant_id")?;
        let activation_status: String = activation.try_get("status")?;
        let activation_expires_at: DateTime<Utc> = activation.try_get("expires_at")?;

        if let Some(existing) = sqlx::query(
            "SELECT ec.id, ec.activation_code_id, ec.organization_id, ec.tenant_id, ec.request_id, ec.request_fingerprint, ec.operational_public_key, ec.server_nonce, ec.status, ec.expires_at FROM enrollment_challenges ec WHERE ec.tenant_id = ? AND ec.request_id = ?",
        )
        .bind(tenant_id)
        .bind(&write.request_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let record = challenge_from_row(existing)?;
            transaction.commit().await?;
            return Ok(classify_existing_challenge(
                record,
                activation_id,
                &activation_status,
                activation_expires_at,
                write,
                now,
            ));
        }

        if activation_status != "ACTIVE"
            || activation_expires_at <= now
            || write.expires_at > activation_expires_at
        {
            transaction.rollback().await?;
            return Ok(ChallengeCreationOutcome::ActivationUnavailable);
        }

        let inserted = sqlx::query(
            "INSERT INTO enrollment_challenges (id, activation_code_id, organization_id, tenant_id, request_id, request_fingerprint, enrollment_instance_id, display_name, root_public_key, operational_public_key, metadata_hash, attestation_hash, server_nonce, assurance_level, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CHALLENGED', ?)",
        )
        .bind(write.id)
        .bind(activation_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(&write.request_id)
        .bind(write.request_fingerprint.as_slice())
        .bind(&write.enrollment_instance_id)
        .bind(&write.display_name)
        .bind(write.root_public_key.as_slice())
        .bind(write.operational_public_key.as_slice())
        .bind(write.metadata_hash.as_slice())
        .bind(write.attestation_hash.as_slice())
        .bind(write.server_nonce.as_slice())
        .bind(write.assurance_level)
        .bind(write.expires_at)
        .execute(&mut *transaction)
        .await;
        if let Err(sqlx::Error::Database(error)) = &inserted {
            if error.is_unique_violation() {
                let existing = sqlx::query(
                    "SELECT ec.id, ec.activation_code_id, ec.organization_id, ec.tenant_id, ec.request_id, ec.request_fingerprint, ec.operational_public_key, ec.server_nonce, ec.status, ec.expires_at FROM enrollment_challenges ec WHERE ec.tenant_id = ? AND ec.request_id = ? FOR SHARE",
                )
                .bind(tenant_id)
                .bind(&write.request_id)
                .fetch_optional(&mut *transaction)
                .await?;
                transaction.commit().await?;
                return Ok(existing.map_or(
                    ChallengeCreationOutcome::ActivationUnavailable,
                    |row| {
                        challenge_from_row(row).map_or(
                            ChallengeCreationOutcome::ActivationUnavailable,
                            |record| {
                                classify_existing_challenge(
                                    record,
                                    activation_id,
                                    &activation_status,
                                    activation_expires_at,
                                    write,
                                    now,
                                )
                            },
                        )
                    },
                ));
            }
        }
        inserted?;
        sqlx::query(
            "UPDATE enrollment_activation_codes SET status = 'RESERVED', reserved_at = ? WHERE id = ? AND status = 'ACTIVE'",
        )
        .bind(now)
        .bind(activation_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'DEVICE', ?, 'ENROLLMENT_CHALLENGE_CREATED', 'ENROLLMENT_CHALLENGE', ?, JSON_OBJECT('status', 'CHALLENGED'))",
        )
        .bind(Uuid::new_v4())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(&write.enrollment_instance_id)
        .bind(write.id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        Ok(ChallengeCreationOutcome::Created(
            EnrollmentChallengeRecord {
                id: write.id,
                activation_code_id: activation_id,
                organization_id,
                tenant_id,
                request_id: write.request_id.clone(),
                request_fingerprint: write.request_fingerprint,
                operational_public_key: write.operational_public_key,
                server_nonce: write.server_nonce,
                status: EnrollmentChallengeStatus::Challenged,
                expires_at: write.expires_at,
            },
        ))
    }

    pub async fn load_challenge_for_proof(
        &self,
        challenge_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<EnrollmentProofChallengeRecord>, RepositoryError> {
        if challenge_id.is_nil() {
            return Err(RepositoryError::InvalidChallengeScope);
        }
        let row = sqlx::query(
            "SELECT ec.id, ec.organization_id, ec.tenant_id, ec.enrollment_instance_id, ec.display_name, ec.root_public_key, ec.operational_public_key, ec.metadata_hash, ec.attestation_hash, ec.server_nonce, ec.assurance_level, ec.status, ec.expires_at, ec.completion_request_id FROM enrollment_challenges ec JOIN enrollment_activation_codes ac ON ac.id = ec.activation_code_id WHERE ec.id = ? AND ((ec.status = 'CHALLENGED' AND ec.expires_at > ? AND ac.status = 'RESERVED') OR (ec.status = 'ISSUED' AND ac.status = 'CONSUMED'))",
        )
        .bind(challenge_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        row.map(proof_challenge_from_row).transpose()
    }
}

fn classify_existing_challenge(
    record: EnrollmentChallengeRecord,
    activation_id: Uuid,
    activation_status: &str,
    activation_expires_at: DateTime<Utc>,
    write: &EnrollmentChallengeWrite,
    now: DateTime<Utc>,
) -> ChallengeCreationOutcome {
    if record.activation_code_id != activation_id
        || activation_status != "RESERVED"
        || activation_expires_at <= now
        || record.status != EnrollmentChallengeStatus::Challenged
        || record.expires_at <= now
    {
        ChallengeCreationOutcome::ActivationUnavailable
    } else if record.request_fingerprint == write.request_fingerprint {
        ChallengeCreationOutcome::Replay(record)
    } else {
        ChallengeCreationOutcome::Conflict
    }
}

fn validate_challenge(
    write: &EnrollmentChallengeWrite,
    now: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    if write.id.is_nil()
        || write.request_id.is_empty()
        || write.request_id.len() > 120
        || write.enrollment_instance_id.is_empty()
        || write.enrollment_instance_id.len() > 120
        || write.display_name.is_empty()
        || write.display_name.len() > 200
        || write.request_fingerprint == [0; 32]
        || write.server_nonce == [0; 32]
        || write.expires_at <= now
    {
        return Err(RepositoryError::InvalidChallengeScope);
    }
    Ok(())
}

fn challenge_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<EnrollmentChallengeRecord, RepositoryError> {
    let request_fingerprint = fixed_32(row.try_get("request_fingerprint")?)?;
    let operational_public_key = fixed_32(row.try_get("operational_public_key")?)?;
    let server_nonce = fixed_32(row.try_get("server_nonce")?)?;
    let status: String = row.try_get("status")?;
    let status = match status.as_str() {
        "PENDING" => EnrollmentChallengeStatus::Pending,
        "CHALLENGED" => EnrollmentChallengeStatus::Challenged,
        "PROVED" => EnrollmentChallengeStatus::Proved,
        "ISSUED" => EnrollmentChallengeStatus::Issued,
        "EXPIRED" => EnrollmentChallengeStatus::Expired,
        _ => return Err(RepositoryError::InvalidChallengeRecord),
    };
    Ok(EnrollmentChallengeRecord {
        id: row.try_get("id")?,
        activation_code_id: row.try_get("activation_code_id")?,
        organization_id: row.try_get("organization_id")?,
        tenant_id: row.try_get("tenant_id")?,
        request_id: row.try_get("request_id")?,
        request_fingerprint,
        operational_public_key,
        server_nonce,
        status,
        expires_at: row.try_get("expires_at")?,
    })
}

fn proof_challenge_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<EnrollmentProofChallengeRecord, RepositoryError> {
    let status: String = row.try_get("status")?;
    let status = match status.as_str() {
        "CHALLENGED" => EnrollmentChallengeStatus::Challenged,
        "ISSUED" => EnrollmentChallengeStatus::Issued,
        _ => return Err(RepositoryError::InvalidChallengeRecord),
    };
    Ok(EnrollmentProofChallengeRecord {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        tenant_id: row.try_get("tenant_id")?,
        enrollment_instance_id: row.try_get("enrollment_instance_id")?,
        display_name: row.try_get("display_name")?,
        root_public_key: fixed_32(row.try_get("root_public_key")?)?,
        operational_public_key: fixed_32(row.try_get("operational_public_key")?)?,
        metadata_hash: fixed_32(row.try_get("metadata_hash")?)?,
        attestation_hash: fixed_32(row.try_get("attestation_hash")?)?,
        server_nonce: fixed_32(row.try_get("server_nonce")?)?,
        assurance_level: row.try_get("assurance_level")?,
        status,
        expires_at: row.try_get("expires_at")?,
        completion_request_id: row.try_get("completion_request_id")?,
    })
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32], RepositoryError> {
    value
        .try_into()
        .map_err(|_| RepositoryError::InvalidChallengeRecord)
}
