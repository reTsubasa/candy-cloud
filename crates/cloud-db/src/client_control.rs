use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::DbPool;

const MAX_DISPLAY_NAME_LEN: usize = 200;
const MAX_INSTALL_ID_LEN: usize = 128;
const MAX_CLIENT_VERSION_LEN: usize = 64;
const MAX_GRANT_ENVELOPE_LEN: usize = 1024 * 1024;

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
    #[error("terminal client database record is invalid")]
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDeviceRegistrationOutcome {
    Registered { device_id: Uuid, replayed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrantWrite {
    pub grant_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub generation: u64,
    pub request_id: Uuid,
    pub request_hash: [u8; 32],
    pub signing_key_id: String,
    pub grant_envelope: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl ClientGrantWrite {
    fn validate(&self) -> Result<(), ClientControlError> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientGrantWriteOutcome {
    Issued { grant_id: Uuid, replayed: bool },
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
            "SELECT id FROM client_devices WHERE tenant_id = ? AND device_id = ? FOR UPDATE",
        )
        .bind(request.tenant_id)
        .bind(request.device_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientControlError::InvalidRecord)?;
        if existing.is_some() {
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
            "SELECT id, request_hash FROM client_grants WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
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
            transaction
                .rollback()
                .await
                .map_err(|_| ClientControlError::InvalidRecord)?;
            return if stored_hash.as_slice() == grant.request_hash {
                Ok(ClientGrantWriteOutcome::Issued {
                    grant_id: stored_id,
                    replayed: true,
                })
            } else {
                Err(ClientControlError::BindingConflict)
            };
        }

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
        .bind(grant.generation)
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
            replayed: false,
        })
    }
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
