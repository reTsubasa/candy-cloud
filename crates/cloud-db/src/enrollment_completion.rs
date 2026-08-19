use chrono::{DateTime, Utc};
use cloud_control::{ControlResourceV1, ResourceSpecV1};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{DbPool, RepositoryError};

const MAX_REQUEST_ID_LEN: usize = 120;
const MAX_KEY_ID_LEN: usize = 80;
const MAX_ENVIRONMENT_LEN: usize = 40;
const MAX_CERTIFICATE_DER_LEN: usize = 64 * 1024;
const MAX_CERTIFICATE_CHAIN_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCompletionWrite {
    pub challenge_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub completion_request_id: String,
    pub device_record_id: Uuid,
    pub device_identity: Uuid,
    pub key_record_id: Uuid,
    pub key_id: String,
    pub certificate_id: Uuid,
    pub issuer_key_id: String,
    pub serial_number: [u8; 16],
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub environment: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCompletionRecord {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub certificate_id: Uuid,
    pub certificate_der: Vec<u8>,
    pub certificate_chain_pem: String,
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentCompletionOutcome {
    Issued(EnrollmentCompletionRecord),
    Replay(EnrollmentCompletionRecord),
    Conflict,
    ChallengeUnavailable,
}

#[derive(Clone)]
pub struct EnrollmentCompletionRepository {
    pool: DbPool,
}

impl EnrollmentCompletionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn complete(
        &self,
        write: &EnrollmentCompletionWrite,
    ) -> Result<EnrollmentCompletionOutcome, RepositoryError> {
        validate_completion(write)?;
        let fingerprint = completion_fingerprint(write);
        let mut transaction = self.pool.begin().await?;

        // Serialize completion by a concrete tenant row. Locking a missing
        // completion_request_id range creates MySQL next-key locks that can
        // deadlock otherwise independent enrollment transactions.
        let tenant_lock: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM tenants WHERE id = ? FOR UPDATE")
                .bind(write.tenant_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if tenant_lock.is_none() {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        }
        let existing_request: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM enrollment_challenges WHERE tenant_id = ? AND completion_request_id = ?",
        )
        .bind(write.tenant_id)
        .bind(&write.completion_request_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if existing_request.is_some_and(|challenge_id| challenge_id != write.challenge_id) {
            transaction.commit().await?;
            return Ok(EnrollmentCompletionOutcome::Conflict);
        }
        let challenge = sqlx::query(
            "SELECT ec.organization_id, ec.tenant_id, ec.enrollment_instance_id, ec.display_name, ec.operational_public_key, ec.assurance_level, ec.status, ec.expires_at, ec.completion_request_id, ec.completion_fingerprint, ec.device_id, ec.certificate_id, ac.id AS activation_code_id, ac.status AS activation_status, ac.replace_node_id FROM enrollment_challenges ec JOIN enrollment_activation_codes ac ON ac.id = ec.activation_code_id WHERE ec.id = ? FOR UPDATE",
        )
        .bind(write.challenge_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(challenge) = challenge else {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        };
        let organization_id: Uuid = challenge.try_get("organization_id")?;
        let tenant_id: Uuid = challenge.try_get("tenant_id")?;
        let status: String = challenge.try_get("status")?;
        let expires_at: DateTime<Utc> = challenge.try_get("expires_at")?;
        let activation_status: String = challenge.try_get("activation_status")?;
        if organization_id != write.organization_id || tenant_id != write.tenant_id {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        }

        if status == "ISSUED" {
            let request_id: Option<String> = challenge.try_get("completion_request_id")?;
            let persisted_fingerprint: Option<Vec<u8>> =
                challenge.try_get("completion_fingerprint")?;
            let matches = request_id.as_deref() == Some(&write.completion_request_id)
                && persisted_fingerprint
                    .as_deref()
                    .and_then(|value| <&[u8; 32]>::try_from(value).ok())
                    == Some(&fingerprint);
            if !matches || activation_status != "CONSUMED" {
                transaction.commit().await?;
                return Ok(EnrollmentCompletionOutcome::Conflict);
            }
            let record = load_completion_record(
                &mut transaction,
                challenge.try_get("device_id")?,
                challenge.try_get("certificate_id")?,
            )
            .await?;
            transaction.commit().await?;
            return Ok(EnrollmentCompletionOutcome::Replay(record));
        }

        if status != "CHALLENGED"
            || activation_status != "RESERVED"
            || expires_at <= write.issued_at
        {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        }

        let display_name: String = challenge.try_get("display_name")?;
        let enrollment_instance_id: String = challenge.try_get("enrollment_instance_id")?;
        let audit_context = EnrollmentAuditContext {
            organization_id,
            tenant_id,
            actor_id: &enrollment_instance_id,
        };
        let operational_public_key: Vec<u8> = challenge.try_get("operational_public_key")?;
        if operational_public_key.len() != 32 {
            return Err(RepositoryError::InvalidCompletionRecord);
        }
        let assurance_level: u64 = challenge.try_get("assurance_level")?;
        let activation_code_id: Uuid = challenge.try_get("activation_code_id")?;
        let replace_node_id: Option<Uuid> = challenge.try_get("replace_node_id")?;

        let proved = sqlx::query(
            "UPDATE enrollment_challenges SET status = 'PROVED', proved_at = ? WHERE id = ? AND status = 'CHALLENGED'",
        )
        .bind(write.issued_at)
        .bind(write.challenge_id)
        .execute(&mut *transaction)
        .await?;
        if proved.rows_affected() != 1 {
            return Err(RepositoryError::InvalidCompletionRecord);
        }
        append_audit(
            &mut transaction,
            &audit_context,
            "ENROLLMENT_PROOF_VERIFIED",
            "ENROLLMENT_CHALLENGE",
            write.challenge_id,
            "PROVED",
        )
        .await?;

        sqlx::query(
            "INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(write.device_record_id)
        .bind(tenant_id)
        .bind(write.device_identity.to_string())
        .bind(display_name)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, assurance_level, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(write.key_record_id)
        .bind(tenant_id)
        .bind(write.device_record_id)
        .bind(&write.key_id)
        .bind(operational_public_key)
        .bind(assurance_level)
        .execute(&mut *transaction)
        .await?;
        let san_uri = format!("candy:device:{}", write.device_identity);
        sqlx::query(
            "INSERT INTO device_certificates (id, organization_id, tenant_id, device_id, device_key_id, issuer_key_id, serial_number, certificate_der, certificate_chain_pem, san_uri, environment, assurance_level, not_before, not_after, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(write.certificate_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(write.device_record_id)
        .bind(write.key_record_id)
        .bind(&write.issuer_key_id)
        .bind(write.serial_number.as_slice())
        .bind(&write.certificate_der)
        .bind(&write.certificate_chain_pem)
        .bind(san_uri)
        .bind(&write.environment)
        .bind(assurance_level)
        .bind(write.not_before)
        .bind(write.not_after)
        .execute(&mut *transaction)
        .await?;

        if let Some(control_node_id) = replace_node_id {
            replace_control_node_identity(
                &mut transaction,
                &audit_context,
                control_node_id,
                write.device_record_id,
                write.key_record_id,
                write.issued_at,
            )
            .await?;
        }

        let consumed = sqlx::query(
            "UPDATE enrollment_activation_codes SET status = 'CONSUMED', consumed_at = ? WHERE id = ? AND status = 'RESERVED'",
        )
        .bind(write.issued_at)
        .bind(activation_code_id)
        .execute(&mut *transaction)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(RepositoryError::InvalidCompletionRecord);
        }
        let issued = sqlx::query(
            "UPDATE enrollment_challenges SET status = 'ISSUED', issued_at = ?, completion_request_id = ?, completion_fingerprint = ?, device_id = ?, certificate_id = ? WHERE id = ? AND status = 'PROVED'",
        )
        .bind(write.issued_at)
        .bind(&write.completion_request_id)
        .bind(fingerprint.as_slice())
        .bind(write.device_record_id)
        .bind(write.certificate_id)
        .bind(write.challenge_id)
        .execute(&mut *transaction)
        .await?;
        if issued.rows_affected() != 1 {
            return Err(RepositoryError::InvalidCompletionRecord);
        }
        append_audit(
            &mut transaction,
            &audit_context,
            "DEVICE_IDENTITY_ISSUED",
            "DEVICE",
            write.device_record_id,
            "ACTIVE",
        )
        .await?;
        transaction.commit().await?;

        Ok(EnrollmentCompletionOutcome::Issued(
            EnrollmentCompletionRecord {
                device_id: write.device_identity,
                device_key_id: write.key_record_id,
                certificate_id: write.certificate_id,
                certificate_der: write.certificate_der.clone(),
                certificate_chain_pem: write.certificate_chain_pem.clone(),
                not_after: write.not_after,
            },
        ))
    }

    pub async fn load_issued(
        &self,
        challenge_id: Uuid,
        completion_request_id: &str,
    ) -> Result<EnrollmentCompletionOutcome, RepositoryError> {
        if challenge_id.is_nil() || !bounded(completion_request_id, MAX_REQUEST_ID_LEN) {
            return Err(RepositoryError::InvalidCompletionScope);
        }
        let mut transaction = self.pool.begin().await?;
        let challenge = sqlx::query(
            "SELECT ec.status, ec.completion_request_id, ec.device_id, ec.certificate_id, ac.status AS activation_status FROM enrollment_challenges ec JOIN enrollment_activation_codes ac ON ac.id = ec.activation_code_id WHERE ec.id = ? FOR SHARE",
        )
        .bind(challenge_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(challenge) = challenge else {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        };
        let status: String = challenge.try_get("status")?;
        let activation_status: String = challenge.try_get("activation_status")?;
        if status != "ISSUED" || activation_status != "CONSUMED" {
            transaction.rollback().await?;
            return Ok(EnrollmentCompletionOutcome::ChallengeUnavailable);
        }
        let persisted_request_id: Option<String> = challenge.try_get("completion_request_id")?;
        if persisted_request_id.as_deref() != Some(completion_request_id) {
            transaction.commit().await?;
            return Ok(EnrollmentCompletionOutcome::Conflict);
        }
        let record = load_completion_record(
            &mut transaction,
            challenge.try_get("device_id")?,
            challenge.try_get("certificate_id")?,
        )
        .await?;
        transaction.commit().await?;
        Ok(EnrollmentCompletionOutcome::Replay(record))
    }
}

async fn replace_control_node_identity(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    audit: &EnrollmentAuditContext<'_>,
    control_node_id: Uuid,
    new_device_id: Uuid,
    new_device_key_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    let row = sqlx::query(
        "SELECT revision, CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND id = ? AND state = 'ACTIVE' FOR UPDATE",
    )
    .bind(audit.tenant_id)
    .bind(control_node_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RepositoryError::InvalidCompletionRecord)?;
    let mut resource: ControlResourceV1 =
        serde_json::from_str(&row.try_get::<String, _>("document_json")?)
            .map_err(|_| RepositoryError::InvalidCompletionRecord)?;
    let ResourceSpecV1::Node(node) = &mut resource.resource else {
        return Err(RepositoryError::InvalidCompletionRecord);
    };
    let old_device_id = node.device_id;
    let old_device_key_id = node.device_key_id;
    let old_identity_active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices d JOIN device_keys dk ON dk.id = ? AND dk.device_id = d.id AND dk.tenant_id = d.tenant_id WHERE d.id = ? AND d.tenant_id = ? AND d.status = 'ACTIVE' AND dk.status = 'ACTIVE')",
    )
    .bind(old_device_key_id)
    .bind(old_device_id)
    .bind(audit.tenant_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !old_identity_active {
        return Err(RepositoryError::InvalidCompletionRecord);
    }

    node.device_id = new_device_id;
    node.device_key_id = new_device_key_id;
    resource.metadata.revision = resource
        .metadata
        .revision
        .checked_add(1)
        .ok_or(RepositoryError::InvalidCompletionRecord)?;
    let document =
        serde_json::to_string(&resource).map_err(|_| RepositoryError::InvalidCompletionRecord)?;
    let document_hash = resource
        .resource
        .document_hash()
        .map_err(|_| RepositoryError::InvalidCompletionRecord)?;
    let changed = sqlx::query(
        "UPDATE sdwan_control_resources SET revision = ?, document_hash = ?, document_json = CAST(? AS JSON), updated_by = ? WHERE tenant_id = ? AND resource_kind = 'NODE' AND id = ? AND revision = ? AND state = 'ACTIVE'",
    )
    .bind(resource.metadata.revision)
    .bind(document_hash.as_slice())
    .bind(document)
    .bind(audit.actor_id)
    .bind(audit.tenant_id)
    .bind(control_node_id)
    .bind(row.try_get::<u64, _>("revision")?)
    .execute(&mut **transaction)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(RepositoryError::InvalidCompletionRecord);
    }

    let service_nodes = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM nodes WHERE tenant_id = ? AND device_id = ? AND device_key_id = ? FOR UPDATE",
    )
    .bind(audit.tenant_id)
    .bind(old_device_id)
    .bind(old_device_key_id)
    .fetch_all(&mut **transaction)
    .await?;
    for service_node_id in service_nodes {
        sqlx::query("DELETE FROM runtime_projection_transport_catalog WHERE transport_node_id = ?")
            .bind(service_node_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("UPDATE node_endpoints SET status = 'DISABLED' WHERE node_id = ?")
            .bind(service_node_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("UPDATE nodes SET device_id = ?, device_key_id = ?, node_id = ? WHERE id = ?")
            .bind(new_device_id)
            .bind(new_device_key_id)
            .bind(format!("candy:device:{new_device_id}"))
            .bind(service_node_id)
            .execute(&mut **transaction)
            .await?;
    }

    sqlx::query("UPDATE device_certificates SET status = 'SUPERSEDED', revoked_at = ? WHERE tenant_id = ? AND device_id = ? AND status = 'ACTIVE'")
        .bind(now)
        .bind(audit.tenant_id)
        .bind(old_device_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("UPDATE device_keys SET status = 'REVOKED', revoked_at = ? WHERE tenant_id = ? AND id = ? AND status = 'ACTIVE'")
        .bind(now)
        .bind(audit.tenant_id)
        .bind(old_device_key_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("UPDATE devices SET status = 'REVOKED' WHERE tenant_id = ? AND id = ? AND status = 'ACTIVE'")
        .bind(audit.tenant_id)
        .bind(old_device_id)
        .execute(&mut **transaction)
        .await?;

    let segment_ids = sqlx::query_scalar::<_, Uuid>(
        "WITH RECURSIVE dependents (resource_kind, resource_id) AS (SELECT CAST('NODE' AS CHAR(32)), CAST(? AS BINARY(16)) UNION DISTINCT SELECT CAST(refs.source_kind AS CHAR(32)), refs.source_id FROM sdwan_control_resource_references refs JOIN dependents current ON refs.tenant_id = ? AND CAST(refs.target_kind AS CHAR(32)) = current.resource_kind AND refs.target_id = current.resource_id) SELECT DISTINCT resources.segment_id FROM dependents JOIN sdwan_control_resources resources ON resources.tenant_id = ? AND CAST(resources.resource_kind AS CHAR(32)) = dependents.resource_kind AND resources.id = dependents.resource_id WHERE resources.state <> 'DELETED' AND resources.segment_id IS NOT NULL",
    )
    .bind(control_node_id)
    .bind(audit.tenant_id)
    .bind(audit.tenant_id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut hash = Sha256::new();
    hash.update(b"candy/node-reenrollment/v1\0");
    hash.update(control_node_id.as_bytes());
    hash.update(new_device_id.as_bytes());
    let request_hash: [u8; 32] = hash.finalize().into();
    for segment_id in segment_ids {
        enqueue_reenrollment_generation(transaction, audit.tenant_id, segment_id, request_hash)
            .await?;
    }
    append_audit(
        transaction,
        audit,
        "CONTROL_NODE_IDENTITY_REPLACED",
        "SDWAN_CONTROL_NODE",
        control_node_id,
        "ACTIVE",
    )
    .await?;
    Ok(())
}

async fn enqueue_reenrollment_generation(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    tenant_id: Uuid,
    segment_id: Uuid,
    request_hash: [u8; 32],
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT IGNORE INTO segment_generation_heads (tenant_id, segment_id, desired_revision) VALUES (?, ?, 0)")
        .bind(tenant_id)
        .bind(segment_id)
        .execute(&mut **transaction)
        .await?;
    let current: u64 = sqlx::query_scalar("SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ? FOR UPDATE")
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_one(&mut **transaction)
        .await?;
    let desired = current
        .checked_add(1)
        .ok_or(RepositoryError::InvalidCompletionRecord)?;
    sqlx::query("UPDATE segment_generation_heads SET desired_revision = ? WHERE tenant_id = ? AND segment_id = ? AND desired_revision = ?")
        .bind(desired)
        .bind(tenant_id)
        .bind(segment_id)
        .bind(current)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("INSERT INTO segment_generation_jobs (id, tenant_id, segment_id, desired_revision, idempotency_hash) VALUES (?, ?, ?, ?, ?)")
        .bind(Uuid::now_v7())
        .bind(tenant_id)
        .bind(segment_id)
        .bind(desired)
        .bind(request_hash.as_slice())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn load_completion_record(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    device_record_id: Option<Uuid>,
    certificate_id: Option<Uuid>,
) -> Result<EnrollmentCompletionRecord, RepositoryError> {
    let (Some(device_record_id), Some(certificate_id)) = (device_record_id, certificate_id) else {
        return Err(RepositoryError::InvalidCompletionRecord);
    };
    let row = sqlx::query(
        "SELECT d.device_id, dc.device_key_id, dc.id AS certificate_id, dc.certificate_der, dc.certificate_chain_pem, dc.not_after FROM devices d JOIN device_certificates dc ON dc.device_id = d.id WHERE d.id = ? AND dc.id = ?",
    )
    .bind(device_record_id)
    .bind(certificate_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(RepositoryError::InvalidCompletionRecord)?;
    let device_identity: String = row.try_get("device_id")?;
    Ok(EnrollmentCompletionRecord {
        device_id: Uuid::parse_str(&device_identity)
            .map_err(|_| RepositoryError::InvalidCompletionRecord)?,
        device_key_id: row.try_get("device_key_id")?,
        certificate_id: row.try_get("certificate_id")?,
        certificate_der: row.try_get("certificate_der")?,
        certificate_chain_pem: row.try_get("certificate_chain_pem")?,
        not_after: row.try_get("not_after")?,
    })
}

struct EnrollmentAuditContext<'a> {
    organization_id: Uuid,
    tenant_id: Uuid,
    actor_id: &'a str,
}

async fn append_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    context: &EnrollmentAuditContext<'_>,
    action: &str,
    object_type: &str,
    object_id: Uuid,
    status: &str,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'DEVICE', ?, ?, ?, ?, JSON_OBJECT('status', ?))",
    )
    .bind(Uuid::new_v4())
    .bind(context.organization_id)
    .bind(context.tenant_id)
    .bind(context.actor_id)
    .bind(action)
    .bind(object_type)
    .bind(object_id.to_string())
    .bind(status)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_completion(write: &EnrollmentCompletionWrite) -> Result<(), RepositoryError> {
    let valid_v7 = |id: Uuid| id.get_version_num() == 7;
    if write.challenge_id.is_nil()
        || write.organization_id.is_nil()
        || write.tenant_id.is_nil()
        || !bounded(&write.completion_request_id, MAX_REQUEST_ID_LEN)
        || !valid_v7(write.device_record_id)
        || write.device_identity != write.device_record_id
        || !valid_v7(write.key_record_id)
        || write.key_id != write.key_record_id.to_string()
        || !valid_v7(write.certificate_id)
        || !bounded(&write.issuer_key_id, MAX_KEY_ID_LEN)
        || !bounded(&write.environment, MAX_ENVIRONMENT_LEN)
        || write.certificate_der.is_empty()
        || write.certificate_der.len() > MAX_CERTIFICATE_DER_LEN
        || write.certificate_chain_pem.is_empty()
        || write.certificate_chain_pem.len() > MAX_CERTIFICATE_CHAIN_LEN
        || write.not_after <= write.not_before
        || write.issued_at < write.not_before
        || write.issued_at >= write.not_after
    {
        return Err(RepositoryError::InvalidCompletionScope);
    }
    Ok(())
}

fn completion_fingerprint(write: &EnrollmentCompletionWrite) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/enrollment-completion/v1");
    for field in [
        write.challenge_id.as_bytes().as_slice(),
        write.organization_id.as_bytes().as_slice(),
        write.tenant_id.as_bytes().as_slice(),
        write.completion_request_id.as_bytes(),
        write.device_record_id.as_bytes().as_slice(),
        write.key_record_id.as_bytes().as_slice(),
        write.key_id.as_bytes(),
        write.certificate_id.as_bytes().as_slice(),
        write.issuer_key_id.as_bytes(),
        write.serial_number.as_slice(),
        write.certificate_der.as_slice(),
        write.certificate_chain_pem.as_bytes(),
        write.environment.as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(write.not_before.timestamp().to_be_bytes());
    hash.update(write.not_after.timestamp().to_be_bytes());
    hash.update(write.issued_at.timestamp().to_be_bytes());
    hash.finalize().into()
}

fn bounded(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}
