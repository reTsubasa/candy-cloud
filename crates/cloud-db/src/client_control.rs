use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::DbPool;

const MAX_DISPLAY_NAME_LEN: usize = 200;
const MAX_INSTALL_ID_LEN: usize = 128;
const MAX_CLIENT_VERSION_LEN: usize = 64;
const MAX_GRANT_ENVELOPE_LEN: usize = 1024 * 1024;
/// Upper bound for Cloud-allocated Grant generations. The column is
/// `BIGINT UNSIGNED`; refusing to allocate past this keeps the value safely
/// inside every downstream representation instead of silently wrapping.
const MAX_GRANT_GENERATION: u64 = i64::MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPlatform {
    Windows,
    Macos,
    Android,
}

impl ClientPlatform {
    pub const fn database_value(self) -> &'static str {
        match self {
            Self::Windows => "WINDOWS",
            Self::Macos => "MACOS",
            Self::Android => "ANDROID",
        }
    }

    pub fn from_database_value(value: &str) -> Option<Self> {
        match value {
            "WINDOWS" => Some(Self::Windows),
            "MACOS" => Some(Self::Macos),
            "ANDROID" => Some(Self::Android),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeviceRegistration {
    pub record_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub platform: ClientPlatform,
    pub display_name: String,
    pub install_id: String,
    pub client_version: Option<String>,
    pub public_key: [u8; 32],
    pub request_id: Uuid,
    pub actor_id: Uuid,
}

impl ClientDeviceRegistration {
    pub fn validate(&self) -> Result<(), ClientControlError> {
        for id in [
            self.record_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.device_key_id,
            self.request_id,
            self.actor_id,
        ] {
            if id.is_nil() {
                return Err(ClientControlError::InvalidScope);
            }
        }
        if self.display_name.trim().is_empty() || self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(ClientControlError::InvalidDisplayName);
        }
        if self.actor_id != self.user_id {
            return Err(ClientControlError::InvalidScope);
        }
        if self.install_id.len() < 8
            || self.install_id.len() > MAX_INSTALL_ID_LEN
            || !self
                .install_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(ClientControlError::InvalidInstallId);
        }
        if self
            .client_version
            .as_ref()
            .is_some_and(|version| version.is_empty() || version.len() > MAX_CLIENT_VERSION_LEN)
        {
            return Err(ClientControlError::InvalidClientVersion);
        }
        if self.public_key == [0; 32] {
            return Err(ClientControlError::InvalidPublicKey);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientControlError {
    #[error("invalid terminal client scope")]
    InvalidScope,
    #[error("invalid terminal client display name")]
    InvalidDisplayName,
    #[error("invalid terminal client install id")]
    InvalidInstallId,
    #[error("invalid terminal client version")]
    InvalidClientVersion,
    #[error("invalid terminal client public key")]
    InvalidPublicKey,
    #[error("terminal client binding conflict")]
    BindingConflict,
    #[error("terminal client grant generation changed concurrently")]
    GenerationConflict,
    #[error("terminal client database record is invalid")]
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceRegistrationOutcome {
    /// First registration of this device key, or an idempotent replay of it.
    Registered { device_id: Uuid, replayed: bool },
    /// The device was already revoked. A revoked device is never silently
    /// re-registered: Cloud requires an explicit re-enrollment decision.
    Revoked {
        device_id: Uuid,
        device_key_id: Uuid,
    },
}

/// Lifecycle state of a registered terminal device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceStatus {
    Active,
    Suspended,
    Revoked,
}

impl ClientDeviceStatus {
    pub fn from_database_value(value: &str) -> Option<Self> {
        match value {
            "ACTIVE" => Some(Self::Active),
            "SUSPENDED" => Some(Self::Suspended),
            "REVOKED" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Internal binding for one registered terminal device.
///
/// The wire contract uses the client-chosen `device_id` while Cloud persistence
/// uses an internal `record_id`. Every Grant and Projection path must translate
/// through this lookup so a handler can never accept a caller-supplied internal
/// identifier, and so the *active* device key is Cloud-chosen rather than
/// caller-chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDeviceRecord {
    pub record_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub platform: ClientPlatform,
    pub generation: u64,
}

/// Result of resolving a wire `device_id` with the caller's session scope.
///
/// Suspended and revoked are distinct outcomes rather than one "not found",
/// because Cloud must tell a client that its credential was revoked (`410`)
/// instead of letting it retry forever against a device that no longer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceLookup {
    Active(ClientDeviceRecord),
    /// The device row exists but Cloud has no active key for it, so it is not an
    /// issuable target. Reported separately from `Revoked` because it is
    /// recoverable: re-registering the device key restores service.
    Suspended {
        record_id: Uuid,
        device_id: Uuid,
    },
    Revoked {
        record_id: Uuid,
        device_id: Uuid,
    },
}

impl ClientDeviceRecord {
    /// Public so the "a row read back from storage is still a valid binding"
    /// invariant can be tested without a database.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.record_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
        {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrantWrite {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    /// Generation the signed envelope claims. Cloud reads the next free value
    /// with `next_grant_generation` *before* signing, because the generation is
    /// part of the signed payload, and `write_grant` re-checks it atomically so a
    /// concurrent issuance can never store an envelope whose claim is stale.
    pub generation: u64,
    pub request_id: Uuid,
    pub request_hash: [u8; 32],
    pub signing_key_id: String,
    pub grant_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ClientGrantWrite {
    /// Public so the invariants that `write_grant` refuses *before* opening a
    /// transaction can be pinned by tests without a database, the same way
    /// `ClientDeviceRegistration::validate` is.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.grant_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_GRANT_GENERATION
            || self.request_hash == [0; 32]
            || self.grant_envelope.is_empty()
            || self.grant_envelope.len() > MAX_GRANT_ENVELOPE_LEN
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.expires_at <= self.issued_at
        {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(())
    }
}

/// Grant generation is allocated by Cloud, never by the caller: a client that
/// could choose its own generation could present an older Grant as the newest
/// one. `write_grant` re-validates the claimed generation against the device's
/// current maximum inside the inserting transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientGrantWriteOutcome {
    Issued {
        grant_id: Uuid,
        generation: u64,
        replayed: bool,
    },
}

/// A persisted terminal Client Grant envelope.
///
/// Replay must return the exact bytes Cloud signed the first time. Re-signing on
/// replay would silently re-stamp `issued_at`/`expires_at` and let a client widen
/// its own authorization window by retrying a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrantRecord {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub generation: u64,
    /// Fingerprint of the issuance request that produced this envelope. A replay
    /// compares its own fingerprint against this value, so reusing one idempotency
    /// key for a materially different request is a conflict instead of a silent
    /// hand-back of the old authorization.
    pub request_hash: [u8; 32],
    pub signing_key_id: String,
    pub grant_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ClientGrantRecord {
    /// Public for the same reason as `ClientGrantWrite::validate`: a Grant read
    /// back from storage must satisfy exactly the same invariants Cloud enforced
    /// when it wrote it, and that has to be checkable without a live database.
    pub fn validate(&self) -> Result<(), ClientControlError> {
        if [
            self.grant_id,
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.generation == 0
            || self.generation > MAX_GRANT_GENERATION
            || self.request_hash == [0; 32]
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > 128
            || self.grant_envelope.is_empty()
            || self.grant_envelope.len() > MAX_GRANT_ENVELOPE_LEN
            || self.expires_at <= self.issued_at
        {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ClientControlRepository {
    pool: DbPool,
}

impl ClientControlRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Registers a terminal public key under the already-authenticated human session scope.
    /// The transaction deliberately does not touch node enrollment tables.
    pub async fn register_device(
        &self,
        request: &ClientDeviceRegistration,
    ) -> Result<ClientDeviceRegistrationOutcome, ClientControlError> {
        request.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let organization: Uuid = sqlx::query_scalar(
            "SELECT tenant.organization_id FROM tenants tenant JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' JOIN human_users user ON user.id = ? AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = tenant.organization_id AND membership.user_id = user.id AND membership.status = 'ACTIVE' WHERE tenant.id = ? AND tenant.status = 'ACTIVE' FOR SHARE",
        )
                .bind(request.user_id)
                .bind(request.tenant_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?
                .ok_or(ClientControlError::InvalidScope)?;
        if organization != request.organization_id {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::InvalidScope);
        }

        let request_hash = request_fingerprint(request);
        let request_replay = sqlx::query(
            "SELECT device_id, request_hash FROM client_devices WHERE tenant_id = ? AND user_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = request_replay {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_device: Uuid = row
                .try_get("device_id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash && stored_device == request.device_id {
                Ok(ClientDeviceRegistrationOutcome::Registered {
                    device_id: request.device_id,
                    replayed: true,
                })
            } else {
                Err(ClientControlError::BindingConflict)
            };
        }

        let existing = sqlx::query(
            "SELECT id, status, install_id, (SELECT device_key.device_key_id FROM client_device_keys device_key WHERE device_key.client_device_id = client_devices.id ORDER BY device_key.created_at DESC, device_key.device_key_id DESC LIMIT 1) AS device_key_id FROM client_devices WHERE tenant_id = ? AND device_id = ? FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(request.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = existing {
            let status: String = row
                .try_get("status")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let status = ClientDeviceStatus::from_database_value(&status)
                .ok_or(ClientControlError::InvalidRecord)?;
            let stored_key: Option<Uuid> = row
                .try_get("device_key_id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return match status {
                ClientDeviceStatus::Revoked => Ok(ClientDeviceRegistrationOutcome::Revoked {
                    device_id: request.device_id,
                    device_key_id: stored_key.unwrap_or(request.device_key_id),
                }),
                // Re-registering the same device with a *new* key is key rotation,
                // which needs its own Cloud decision. Treating it as a plain
                // conflict keeps a client from swapping its own key silently.
                ClientDeviceStatus::Active | ClientDeviceStatus::Suspended => {
                    Err(ClientControlError::BindingConflict)
                }
            };
        }

        // `install_id` is unique per tenant. A different device claiming an
        // install identity that already exists is a caller error, not a storage
        // fault, so it must surface as a conflict rather than a 503.
        let install_taken: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_devices WHERE tenant_id = ? AND install_id = ?)",
        )
        .bind(request.tenant_id)
        .bind(&request.install_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if install_taken {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }

        sqlx::query(
            "INSERT INTO client_devices (id, organization_id, tenant_id, user_id, device_id, platform, display_name, install_id, request_id, request_hash, client_version, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(request.record_id)
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.device_id)
        .bind(request.platform.database_value())
        .bind(&request.display_name)
        .bind(&request.install_id)
        .bind(request.request_id)
        .bind(request_hash.as_slice())
        .bind(&request.client_version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO client_device_keys (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, public_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(Uuid::now_v7())
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.user_id)
        .bind(request.record_id)
        .bind(request.device_key_id)
        .bind(request.public_key.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_DEVICE_REGISTERED', 'CLIENT_DEVICE', ?, JSON_OBJECT('device_key_id', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(request.organization_id)
        .bind(request.tenant_id)
        .bind(request.actor_id.to_string())
        .bind(request.device_id.to_string())
        .bind(request.device_key_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(ClientDeviceRegistrationOutcome::Registered {
            device_id: request.device_id,
            replayed: false,
        })
    }

    /// Resolves the client-supplied `device_id` to Cloud's internal binding while
    /// requiring the caller's session scope.
    ///
    /// Returns `Ok(None)` only when the device is unknown or belongs to another
    /// user/tenant. A revoked device is reported as `Revoked` so callers can answer
    /// `410` instead of a misleading `404`, and a device with no active key is
    /// reported as `Suspended` rather than silently appearing authorized.
    pub async fn device_by_wire_id(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<ClientDeviceLookup>, ClientControlError> {
        if [organization_id, tenant_id, user_id, device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT device.id AS record_id, device.organization_id, device.tenant_id, device.user_id, device.device_id, device.platform, device.status AS device_status, device.generation AS device_generation, device_key.device_key_id FROM client_devices device LEFT JOIN client_device_keys device_key ON device_key.client_device_id = device.id AND device_key.organization_id = device.organization_id AND device_key.tenant_id = device.tenant_id AND device_key.user_id = device.user_id AND device_key.status = 'ACTIVE' WHERE device.organization_id = ? AND device.tenant_id = ? AND device.user_id = ? AND device.device_id = ?",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: String = row
            .try_get("device_status")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let status = ClientDeviceStatus::from_database_value(&status)
            .ok_or(ClientControlError::InvalidRecord)?;
        if status == ClientDeviceStatus::Revoked {
            return Ok(Some(revoked_lookup(&row)?));
        }
        let platform: String = row
            .try_get("platform")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let active_key: Option<Uuid> = row
            .try_get("device_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?;
        // A device whose key was retired or revoked has no Cloud-authorized key,
        // so it cannot be treated as an issuable target even though the device row
        // is still ACTIVE.
        let Some(device_key_id) = active_key else {
            return Ok(Some(ClientDeviceLookup::Suspended {
                record_id: row
                    .try_get("record_id")
                    .map_err(|_| ClientControlError::InvalidRecord)?,
                device_id: row
                    .try_get("device_id")
                    .map_err(|_| ClientControlError::InvalidRecord)?,
            }));
        };
        let record = ClientDeviceRecord {
            record_id: row
                .try_get("record_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            organization_id: row
                .try_get("organization_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            user_id: row
                .try_get("user_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            device_id: row
                .try_get("device_id")
                .map_err(|_| ClientControlError::InvalidRecord)?,
            device_key_id,
            platform: ClientPlatform::from_database_value(&platform)
                .ok_or(ClientControlError::InvalidRecord)?,
            generation: row
                .try_get("device_generation")
                .map_err(|_| ClientControlError::InvalidRecord)?,
        };
        record.validate()?;
        Ok(Some(match status {
            ClientDeviceStatus::Active => ClientDeviceLookup::Active(record),
            ClientDeviceStatus::Suspended => ClientDeviceLookup::Suspended {
                record_id: record.record_id,
                device_id: record.device_id,
            },
            ClientDeviceStatus::Revoked => unreachable!("revoked devices return above"),
        }))
    }

    pub async fn touch_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
    ) -> Result<bool, ClientControlError> {
        if [tenant_id, user_id, device_id, device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let result = sqlx::query(
            "UPDATE client_devices d JOIN client_device_keys k ON k.client_device_id = d.id AND k.tenant_id = d.tenant_id SET d.last_seen_at = ? WHERE d.tenant_id = ? AND d.user_id = ? AND d.device_id = ? AND k.device_key_id = ? AND d.status = 'ACTIVE' AND k.status = 'ACTIVE'",
        )
        .bind(Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .bind(device_key_id)
        .execute(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn write_grant(
        &self,
        grant: &ClientGrantWrite,
    ) -> Result<ClientGrantWriteOutcome, ClientControlError> {
        grant.validate()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        let device_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_devices WHERE id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND status = 'ACTIVE')",
        )
        .bind(grant.client_device_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if !device_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }
        let key_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_device_keys WHERE client_device_id = ? AND organization_id = ? AND tenant_id = ? AND user_id = ? AND device_key_id = ? AND status = 'ACTIVE')",
        )
        .bind(grant.client_device_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .bind(grant.device_key_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if !key_exists {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::BindingConflict);
        }

        let existing = sqlx::query(
            "SELECT id, request_hash, generation FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(grant.tenant_id)
        .bind(grant.client_device_id)
        .bind(grant.request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            let stored_generation: u64 = row
                .try_get("generation")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return if stored_hash.as_slice() == grant.request_hash {
                Ok(ClientGrantWriteOutcome::Issued {
                    grant_id: stored_id,
                    generation: stored_generation,
                    replayed: true,
                })
            } else {
                Err(ClientControlError::BindingConflict)
            };
        }

        // The signed envelope already claims a generation, so this is a
        // compare-and-set rather than an allocation: the row is accepted only if
        // it is exactly the next free generation for this device. A concurrent
        // issuance that signed the same claim loses here and the caller re-signs.
        // The `FOR UPDATE` read also serializes concurrent issuances.
        let current_generation: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_grants WHERE tenant_id = ? AND client_device_id = ? FOR UPDATE",
        )
        .bind(grant.tenant_id)
        .bind(grant.client_device_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let expected_generation = current_generation.unwrap_or(0).saturating_add(1);
        if grant.generation != expected_generation
            || expected_generation == 0
            || expected_generation > MAX_GRANT_GENERATION
        {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return Err(ClientControlError::GenerationConflict);
        }
        let next_generation = expected_generation;

        let digest: [u8; 32] = Sha256::digest(&grant.grant_envelope).into();
        sqlx::query(
            "INSERT INTO client_grants (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_id, request_hash, signing_key_id, grant_digest, grant_envelope, issued_at, expires_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(grant.grant_id)
        .bind(grant.organization_id)
        .bind(grant.tenant_id)
        .bind(grant.user_id)
        .bind(grant.client_device_id)
        .bind(grant.device_key_id)
        .bind(next_generation)
        .bind(grant.request_id)
        .bind(grant.request_hash.as_slice())
        .bind(&grant.signing_key_id)
        .bind(digest.as_slice())
        .bind(&grant.grant_envelope)
        .bind(grant.issued_at)
        .bind(grant.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientControlError::InvalidRecord)?;
        Ok(ClientGrantWriteOutcome::Issued {
            grant_id: grant.grant_id,
            generation: next_generation,
            replayed: false,
        })
    }

    /// Reads back the Grant stored for one idempotent issuance request. Used to
    /// return byte-identical envelopes on replay.
    pub async fn grant_by_request(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<ClientGrantRecord>, ClientControlError> {
        if [tenant_id, client_device_id, request_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_hash, signing_key_id, grant_envelope, issued_at, expires_at FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND request_id = ?",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        row.map(grant_record_from_row).transpose()
    }

    /// Reads the generation Cloud must sign next for this device.
    ///
    /// The value is a hint until `write_grant` confirms it: signing needs the
    /// generation inside the envelope, so it must be read before the signature
    /// exists. A lost race surfaces as `GenerationConflict` and the caller re-signs
    /// with the newly read value rather than storing a stale claim.
    pub async fn next_grant_generation(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
    ) -> Result<u64, ClientControlError> {
        if [tenant_id, client_device_id].into_iter().any(|id| id.is_nil()) {
            return Err(ClientControlError::InvalidScope);
        }
        let current: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_grants WHERE tenant_id = ? AND client_device_id = ?",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        let next = current.unwrap_or(0).saturating_add(1);
        if next == 0 || next > MAX_GRANT_GENERATION {
            return Err(ClientControlError::InvalidRecord);
        }
        Ok(next)
    }

    /// Returns the newest unexpired Grant for a device key, if any.
    ///
    /// Device registration replays this so a client that lost its local Grant can
    /// recover the Cloud-issued one without triggering a new signature and without
    /// being handed an expired credential.
    ///
    /// This is a convenience read only. Issuance must not rely on it to decide
    /// whether a Grant may be written, because the row can change between the
    /// read and the insert; `write_grant` owns that decision.
    pub async fn active_grant(
        &self,
        tenant_id: Uuid,
        client_device_id: Uuid,
        device_key_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ClientGrantRecord>, ClientControlError> {
        if [tenant_id, client_device_id, device_key_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientControlError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT id, organization_id, tenant_id, user_id, client_device_id, device_key_id, generation, request_hash, signing_key_id, grant_envelope, issued_at, expires_at FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND device_key_id = ? AND status = 'ACTIVE' AND expires_at > ? ORDER BY generation DESC, issued_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(device_key_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        row.map(grant_record_from_row).transpose()
    }
}

fn revoked_lookup(row: &sqlx::mysql::MySqlRow) -> Result<ClientDeviceLookup, ClientControlError> {
    Ok(ClientDeviceLookup::Revoked {
        record_id: row
            .try_get("record_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        device_id: row
            .try_get("device_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
    })
}

fn grant_record_from_row(
    row: sqlx::mysql::MySqlRow,
) -> Result<ClientGrantRecord, ClientControlError> {
    let record = ClientGrantRecord {
        grant_id: row
            .try_get("id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        organization_id: row
            .try_get("organization_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        user_id: row
            .try_get("user_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        client_device_id: row
            .try_get("client_device_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        device_key_id: row
            .try_get("device_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        generation: row
            .try_get("generation")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        request_hash: {
            let stored: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientControlError::InvalidRecord)?;
            stored
                .as_slice()
                .try_into()
                .map_err(|_| ClientControlError::InvalidRecord)?
        },
        signing_key_id: row
            .try_get("signing_key_id")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        grant_envelope: row
            .try_get("grant_envelope")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| ClientControlError::InvalidRecord)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| ClientControlError::InvalidRecord)?,
    };
    record.validate()?;
    Ok(record)
}

fn request_fingerprint(request: &ClientDeviceRegistration) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-registration/v1\0");
    for value in [
        request.organization_id.as_bytes().as_slice(),
        request.tenant_id.as_bytes().as_slice(),
        request.user_id.as_bytes().as_slice(),
        request.device_id.as_bytes().as_slice(),
        request.device_key_id.as_bytes().as_slice(),
        request.platform.database_value().as_bytes(),
        request.display_name.as_bytes(),
        request.install_id.as_bytes(),
        request.public_key.as_slice(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    if let Some(version) = &request.client_version {
        hash.update((version.len() as u32).to_be_bytes());
        hash.update(version.as_bytes());
    } else {
        hash.update(0_u32.to_be_bytes());
    }
    hash.finalize().into()
}
