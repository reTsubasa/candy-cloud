use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
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
    pub site_id: Option<Uuid>,
    pub requested_display_name: Option<String>,
    pub requested_platform: Option<String>,
    pub requested_architecture: Option<String>,
    pub replace_node_id: Option<Uuid>,
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
pub struct ActivationCodeRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub site_id: Option<Uuid>,
    pub requested_display_name: Option<String>,
    pub requested_platform: Option<String>,
    pub requested_architecture: Option<String>,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub reserved_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub display_name: Option<String>,
    pub device_id: Option<Uuid>,
    pub device_key_id: Option<Uuid>,
    pub replace_node_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapManifestRecord {
    pub activation_id: Uuid,
    pub tenant_id: Uuid,
    pub site_id: Uuid,
    pub display_name: String,
    pub platform: String,
    pub architecture: String,
    pub expires_at: DateTime<Utc>,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapManifestOutcome {
    Issued,
    Replay,
    Unavailable,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapExchangeWrite {
    pub installation_instance_id: String,
    pub enrollment_credential_hash: [u8; 32],
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

pub fn hash_activation_credential(credential: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/enrollment-activation/v1");
    hash.update(credential);
    hash.finalize().into()
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
            || write
                .requested_display_name
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 200)
            || write
                .requested_platform
                .as_ref()
                .is_some_and(|value| !matches!(value.as_str(), "OPEN_WRT" | "LINUX"))
            || write.requested_architecture.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 80
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
            })
            || write.site_id.is_some() != write.requested_display_name.is_some()
            || write.site_id.is_some() != write.requested_platform.is_some()
            || write.site_id.is_some() != write.requested_architecture.is_some()
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

        if let Some(site_id) = write.site_id {
            let site_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'SITE' AND id = ? AND state = 'ACTIVE')")
                .bind(write.tenant_id)
                .bind(site_id)
                .fetch_one(&mut *transaction)
                .await?;
            if !site_exists {
                transaction.rollback().await?;
                return Err(RepositoryError::InvalidActivationScope);
            }
        }
        if let Some(node_id) = write.replace_node_id {
            let node_exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND id = ? AND state = 'ACTIVE' FOR UPDATE")
                .bind(write.tenant_id)
                .bind(node_id)
                .fetch_optional(&mut *transaction)
                .await?;
            if node_exists.is_none() || write.site_id.is_none() {
                transaction.rollback().await?;
                return Err(RepositoryError::InvalidActivationScope);
            }
            sqlx::query("UPDATE enrollment_activation_codes SET status = 'REVOKED' WHERE tenant_id = ? AND replace_node_id = ? AND status IN ('ACTIVE', 'RESERVED')")
                .bind(write.tenant_id)
                .bind(node_id)
                .execute(&mut *transaction)
                .await?;
        }

        let inserted = sqlx::query(
            "INSERT INTO enrollment_activation_codes (id, organization_id, tenant_id, site_id, requested_display_name, requested_platform, requested_architecture, replace_node_id, code_hash, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(write.id)
        .bind(write.organization_id)
        .bind(write.tenant_id)
        .bind(write.site_id)
        .bind(&write.requested_display_name)
        .bind(&write.requested_platform)
        .bind(&write.requested_architecture)
        .bind(write.replace_node_id)
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

    pub async fn exchange_bootstrap_code(
        &self,
        code_hash: &[u8; 32],
        write: &BootstrapExchangeWrite,
        now: DateTime<Utc>,
    ) -> Result<(BootstrapManifestOutcome, Option<BootstrapManifestRecord>), RepositoryError> {
        if *code_hash == [0; 32]
            || write.installation_instance_id.is_empty()
            || write.installation_instance_id.len() > 120
            || !write.installation_instance_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
            || write.enrollment_credential_hash == [0; 32]
        {
            return Err(RepositoryError::InvalidActivationScope);
        }
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("SELECT id, tenant_id, site_id, requested_display_name, requested_platform, requested_architecture, status, expires_at, bootstrap_instance_id, enrollment_credential_hash FROM enrollment_activation_codes WHERE code_hash = ? FOR UPDATE")
            .bind(code_hash.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok((BootstrapManifestOutcome::Unavailable, None));
        };
        let status: String = row.try_get("status")?;
        let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
        let bound: Option<String> = row.try_get("bootstrap_instance_id")?;
        let site_id: Option<Uuid> = row.try_get("site_id")?;
        let display_name: Option<String> = row.try_get("requested_display_name")?;
        let platform: Option<String> = row.try_get("requested_platform")?;
        let architecture: Option<String> = row.try_get("requested_architecture")?;
        if site_id.is_none()
            || display_name.is_none()
            || platform.is_none()
            || architecture.is_none()
        {
            transaction.rollback().await?;
            return Ok((BootstrapManifestOutcome::Unavailable, None));
        }
        if expires_at <= now || !matches!(status.as_str(), "ACTIVE" | "RESERVED") {
            transaction.rollback().await?;
            return Ok((BootstrapManifestOutcome::Unavailable, None));
        }
        if let Some(existing) = &bound {
            if existing != &write.installation_instance_id {
                transaction.rollback().await?;
                return Ok((BootstrapManifestOutcome::Conflict, None));
            }
        } else {
            sqlx::query("UPDATE enrollment_activation_codes SET bootstrap_instance_id = ?, bootstrap_reserved_at = ?, enrollment_credential_hash = ?, status = 'RESERVED', reserved_at = COALESCE(reserved_at, ?) WHERE id = ? AND status = 'ACTIVE'")
                .bind(&write.installation_instance_id)
                .bind(now)
                .bind(write.enrollment_credential_hash.as_slice())
                .bind(now)
                .bind(row.try_get::<Uuid, _>("id")?)
                .execute(&mut *transaction)
                .await?;
        }
        let stored_enrollment_hash: Option<Vec<u8>> = row.try_get("enrollment_credential_hash")?;
        if bound.is_some()
            && stored_enrollment_hash.as_deref()
                != Some(write.enrollment_credential_hash.as_slice())
        {
            transaction.rollback().await?;
            return Ok((BootstrapManifestOutcome::Conflict, None));
        }
        let record = BootstrapManifestRecord {
            activation_id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            site_id: site_id.expect("validated site intent"),
            display_name: display_name.expect("validated display name intent"),
            platform: platform.expect("validated platform intent"),
            architecture: architecture.expect("validated architecture intent"),
            expires_at,
            replayed: bound.is_some(),
        };
        transaction.commit().await?;
        Ok((
            if record.replayed {
                BootstrapManifestOutcome::Replay
            } else {
                BootstrapManifestOutcome::Issued
            },
            Some(record),
        ))
    }

    pub async fn list_activation_codes(
        &self,
        tenant_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<ActivationCodeRecord>, RepositoryError> {
        if tenant_id.is_nil() {
            return Err(RepositoryError::InvalidActivationScope);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "UPDATE enrollment_challenges SET status = 'EXPIRED' WHERE tenant_id = ? AND status IN ('PENDING', 'CHALLENGED') AND expires_at <= ?",
        )
        .bind(tenant_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE enrollment_activation_codes SET status = 'EXPIRED' WHERE tenant_id = ? AND status IN ('ACTIVE', 'RESERVED') AND expires_at <= ?",
        )
        .bind(tenant_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let rows = sqlx::query(
            "SELECT ac.id, ac.tenant_id, ac.site_id, ac.requested_display_name, ac.requested_platform, ac.requested_architecture, ac.replace_node_id, ac.status, ac.expires_at, ac.created_at, ac.reserved_at, ac.consumed_at, COALESCE(ec.display_name, ac.requested_display_name) AS display_name, ec.device_id, dc.device_key_id FROM enrollment_activation_codes ac LEFT JOIN enrollment_challenges ec ON ec.activation_code_id = ac.id LEFT JOIN device_certificates dc ON dc.id = ec.certificate_id WHERE ac.tenant_id = ? ORDER BY ac.created_at DESC, ac.id DESC LIMIT 100",
        )
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        rows.into_iter().map(activation_from_row).collect()
    }

    pub async fn revoke_activation_code(
        &self,
        tenant_id: Uuid,
        activation_id: Uuid,
        actor_id: &str,
    ) -> Result<bool, RepositoryError> {
        if tenant_id.is_nil()
            || activation_id.is_nil()
            || actor_id.is_empty()
            || actor_id.len() > 120
        {
            return Err(RepositoryError::InvalidActivationScope);
        }
        let mut transaction = self.pool.begin().await?;
        let organization_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT organization_id FROM enrollment_activation_codes WHERE tenant_id = ? AND id = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(activation_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(organization_id) = organization_id else {
            transaction.rollback().await?;
            return Ok(false);
        };
        let changed = sqlx::query(
            "UPDATE enrollment_activation_codes SET status = 'REVOKED' WHERE tenant_id = ? AND id = ? AND status IN ('ACTIVE', 'RESERVED')",
        )
        .bind(tenant_id)
        .bind(activation_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if changed {
            sqlx::query(
                "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'USER', ?, 'ENROLLMENT_ACTIVATION_REVOKED', 'ENROLLMENT_ACTIVATION', ?, JSON_OBJECT('status', 'REVOKED'))",
            )
            .bind(Uuid::new_v4())
            .bind(organization_id)
            .bind(tenant_id)
            .bind(actor_id)
            .bind(activation_id.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(changed)
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
            "SELECT id, organization_id, tenant_id, status, expires_at, bootstrap_instance_id FROM enrollment_activation_codes WHERE (bootstrap_instance_id IS NULL AND code_hash = ?) OR (bootstrap_instance_id IS NOT NULL AND enrollment_credential_hash = ?) FOR UPDATE",
        )
        .bind(activation_code_hash.as_slice())
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
        let bootstrap_instance_id: Option<String> = activation.try_get("bootstrap_instance_id")?;

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

        let usable_status = if bootstrap_instance_id.is_some() {
            activation_status == "RESERVED"
        } else {
            activation_status == "ACTIVE"
        };
        if !usable_status
            || bootstrap_instance_id
                .as_deref()
                .is_some_and(|value| value != write.enrollment_instance_id)
            || activation_expires_at <= now
        {
            transaction.rollback().await?;
            return Ok(ChallengeCreationOutcome::ActivationUnavailable);
        }
        let challenge_expires_at = write.expires_at.min(activation_expires_at);

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
        .bind(challenge_expires_at)
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
            "UPDATE enrollment_activation_codes SET status = 'RESERVED', reserved_at = COALESCE(reserved_at, ?) WHERE id = ? AND status IN ('ACTIVE', 'RESERVED')",
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
                expires_at: challenge_expires_at,
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

fn activation_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ActivationCodeRecord, RepositoryError> {
    Ok(ActivationCodeRecord {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        site_id: row.try_get("site_id")?,
        requested_display_name: row.try_get("requested_display_name")?,
        requested_platform: row.try_get("requested_platform")?,
        requested_architecture: row.try_get("requested_architecture")?,
        status: row.try_get("status")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        reserved_at: row.try_get("reserved_at")?,
        consumed_at: row.try_get("consumed_at")?,
        display_name: row.try_get("display_name")?,
        device_id: row.try_get("device_id")?,
        device_key_id: row.try_get("device_key_id")?,
        replace_node_id: row.try_get("replace_node_id")?,
    })
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
