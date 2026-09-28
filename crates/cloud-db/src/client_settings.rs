//! Storage for the tenant-level inputs a signed terminal PolicyProjection needs
//! but that are neither policy resources nor node routing: DNS resolvers and
//! search domains, the underlay exclusion set, and the degraded-mode behaviour.
//!
//! These live in their own versioned document rather than being derived at
//! signing time. The Client installs exactly what Cloud signed, so a value that
//! Cloud invented — an underlay exclusion set in particular — would be a silent
//! routing decision nobody reviewed. When no settings document is active Cloud
//! refuses to sign a Projection at all.
//!
//! The effective traffic mode lives on the device row. It is never taken from a
//! request body: a Client asks Cloud to change mode and Cloud records the
//! decision here, then signs a Projection that reflects it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::client_access::ClientTrafficMode;
use crate::DbPool;

const MAX_DNS_SERVERS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 32;
const MAX_UNDERLAY_EXCLUSIONS: usize = 256;
const MAX_DNS_SERVER_LEN: usize = 128;
const MAX_SEARCH_DOMAIN_LEN: usize = 253;
const MAX_UNDERLAY_EXCLUSION_LEN: usize = 128;
const MAX_GENERATION: u64 = i64::MAX as u64;

/// What the Client does with a resource that is still under policy protection
/// once the Projection is past `stale_until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientDegradedBehavior {
    /// Protected destinations stop working; nothing else changes.
    ProtectedFailClosed,
    /// Protected destinations stop working, and non-protected traffic is allowed
    /// to leave over the local underlay so the device stays usable.
    ProtectedFailClosedDirectNonprotected,
    /// All traffic stops, including traffic that would otherwise be local.
    StopAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientProjectionSettings {
    pub schema_version: u16,
    pub tenant_id: Uuid,
    pub generation: u64,
    pub dns_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub underlay_exclusions: Vec<String>,
    pub degraded_behavior: ClientDegradedBehavior,
}

impl ClientProjectionSettings {
    pub fn validate(&self) -> Result<(), ClientProjectionSettingsError> {
        if self.schema_version != 1 || self.tenant_id.is_nil() || self.generation == 0 {
            return Err(ClientProjectionSettingsError::InvalidSettings);
        }
        if self.dns_servers.len() > MAX_DNS_SERVERS
            || self.search_domains.len() > MAX_SEARCH_DOMAINS
            // `minItems: 1` in the frozen Client schema: an empty exclusion set
            // would have the Client tunnel the transport it depends on.
            || self.underlay_exclusions.is_empty()
            || self.underlay_exclusions.len() > MAX_UNDERLAY_EXCLUSIONS
        {
            return Err(ClientProjectionSettingsError::InvalidSettings);
        }
        if !bounded_unique(&self.dns_servers, MAX_DNS_SERVER_LEN)
            || !bounded_unique(&self.search_domains, MAX_SEARCH_DOMAIN_LEN)
            || !bounded_unique(&self.underlay_exclusions, MAX_UNDERLAY_EXCLUSION_LEN)
        {
            return Err(ClientProjectionSettingsError::InvalidSettings);
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<[u8; 32], ClientProjectionSettingsError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| ClientProjectionSettingsError::InvalidSettings)?;
        Ok(Sha256::digest(bytes).into())
    }
}

/// Every value must be non-empty, bounded, free of control characters, and
/// unique. Duplicates would make the Projection hash depend on input order while
/// the Client treats the set as unordered.
fn bounded_unique(values: &[String], max_len: usize) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().all(|value| {
        !value.is_empty()
            && value.len() <= max_len
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && seen.insert(value.as_str())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientProjectionSettingsError {
    #[error("invalid terminal client projection settings")]
    InvalidSettings,
    #[error("invalid terminal client projection settings scope")]
    InvalidScope,
    #[error("terminal client projection settings conflict")]
    Conflict,
    #[error("terminal client projection settings record is invalid")]
    InvalidRecord,
    /// The device asked for global mode but Cloud has not granted it.
    #[error("global traffic mode is not permitted for this device")]
    ModeNotPermitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientProjectionSettingsPublishOutcome {
    Published { settings_id: Uuid, replayed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTrafficModeOutcome {
    pub previous: ClientTrafficMode,
    pub current: ClientTrafficMode,
    pub replayed: bool,
}

/// A device-requested traffic mode change.
///
/// `global_permitted` is resolved by the caller from the device's bound access
/// policy, so the permission decision lives with the rest of authorization and
/// the refusal can be tested without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTrafficModeRequest {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub request_id: Uuid,
    pub requested: ClientTrafficMode,
    pub global_permitted: bool,
}

impl ClientTrafficModeRequest {
    pub fn validate(&self) -> Result<(), ClientProjectionSettingsError> {
        if [
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
            self.request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(ClientProjectionSettingsError::InvalidScope);
        }
        if self.requested == ClientTrafficMode::Global && !self.global_permitted {
            return Err(ClientProjectionSettingsError::ModeNotPermitted);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct ClientProjectionSettingsRepository {
    pool: DbPool,
}

impl ClientProjectionSettingsRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Publishes a new settings generation. Generations are tenant-scoped and
    /// monotonically increasing, mirroring the access policy repository: the
    /// previous row is superseded inside the same transaction so a Projection can
    /// never be signed against two live settings documents.
    pub async fn publish(
        &self,
        settings: &ClientProjectionSettings,
        organization_id: Uuid,
        actor_id: Uuid,
        request_id: Uuid,
    ) -> Result<ClientProjectionSettingsPublishOutcome, ClientProjectionSettingsError> {
        settings.validate()?;
        if organization_id.is_nil() || actor_id.is_nil() || request_id.is_nil() {
            return Err(ClientProjectionSettingsError::InvalidScope);
        }
        let content_hash = settings.content_hash()?;
        let request_hash = request_fingerprint(settings, organization_id, actor_id);
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let tenant_exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT tenant.id FROM tenants tenant JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' WHERE tenant.id = ? AND tenant.organization_id = ? AND tenant.status = 'ACTIVE' FOR UPDATE",
        )
        .bind(settings.tenant_id)
        .bind(organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        if tenant_exists.is_none() {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return Err(ClientProjectionSettingsError::InvalidScope);
        }
        if let Some(row) = sqlx::query(
            "SELECT id, request_hash FROM client_projection_settings WHERE tenant_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(settings.tenant_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?
        {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            let stored_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash {
                Ok(ClientProjectionSettingsPublishOutcome::Published {
                    settings_id: stored_id,
                    replayed: true,
                })
            } else {
                Err(ClientProjectionSettingsError::Conflict)
            };
        }
        let current_generation: Option<u64> = sqlx::query_scalar(
            "SELECT MAX(generation) FROM client_projection_settings WHERE tenant_id = ? FOR UPDATE",
        )
        .bind(settings.tenant_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let expected_generation = current_generation.unwrap_or(0).saturating_add(1);
        if settings.generation != expected_generation || expected_generation > MAX_GENERATION {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return Err(ClientProjectionSettingsError::Conflict);
        }
        sqlx::query(
            "UPDATE client_projection_settings SET status = 'SUPERSEDED' WHERE tenant_id = ? AND status = 'ACTIVE'",
        )
        .bind(settings.tenant_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let settings_id = Uuid::now_v7();
        let document = serde_json::to_vec(settings)
            .map_err(|_| ClientProjectionSettingsError::InvalidSettings)?;
        sqlx::query(
            "INSERT INTO client_projection_settings (id, organization_id, tenant_id, generation, request_id, request_hash, content_hash, settings_json, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), 'ACTIVE', ?)",
        )
        .bind(settings_id)
        .bind(organization_id)
        .bind(settings.tenant_id)
        .bind(expected_generation)
        .bind(request_id)
        .bind(request_hash.as_slice())
        .bind(content_hash.as_slice())
        .bind(document)
        .bind(actor_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        Ok(ClientProjectionSettingsPublishOutcome::Published {
            settings_id,
            replayed: false,
        })
    }

    /// The active settings document, if Cloud has published one.
    pub async fn current(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<ClientProjectionSettings>, ClientProjectionSettingsError> {
        if tenant_id.is_nil() {
            return Err(ClientProjectionSettingsError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT CAST(settings_json AS CHAR) AS settings_json FROM client_projection_settings WHERE tenant_id = ? AND status = 'ACTIVE' ORDER BY generation DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let document: String = row
            .try_get("settings_json")
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let settings: ClientProjectionSettings = serde_json::from_str(&document)
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        settings.validate()?;
        if settings.tenant_id != tenant_id {
            return Err(ClientProjectionSettingsError::InvalidRecord);
        }
        Ok(Some(settings))
    }

    /// Records a device-requested traffic mode change and applies it atomically.
    pub async fn set_traffic_mode(
        &self,
        request: &ClientTrafficModeRequest,
    ) -> Result<ClientTrafficModeOutcome, ClientProjectionSettingsError> {
        request.validate()?;
        let ClientTrafficModeRequest {
            organization_id,
            tenant_id,
            user_id,
            client_device_id,
            device_key_id,
            request_id,
            requested,
            ..
        } = *request;
        let request_hash = mode_request_fingerprint(
            organization_id,
            tenant_id,
            user_id,
            client_device_id,
            device_key_id,
            requested,
        );
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let row = sqlx::query(
            "SELECT device.status, device.traffic_mode FROM client_devices device WHERE device.id = ? AND device.organization_id = ? AND device.tenant_id = ? AND device.user_id = ? FOR UPDATE",
        )
        .bind(client_device_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        let Some(row) = row else {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return Err(ClientProjectionSettingsError::InvalidScope);
        };
        let status: String = row
            .try_get("status")
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        if status != "ACTIVE" {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return Err(ClientProjectionSettingsError::InvalidScope);
        }
        let current = mode_from_database(
            &row.try_get::<String, _>("traffic_mode")
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?,
        )?;
        // Idempotent replay: the same request id returns the recorded decision
        // instead of applying the flip a second time.
        if let Some(existing) = sqlx::query(
            "SELECT request_hash, previous_mode, requested_mode FROM client_traffic_mode_requests WHERE tenant_id = ? AND client_device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(client_device_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?
        {
            let stored_hash: Vec<u8> = existing
                .try_get("request_hash")
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            let previous = mode_from_database(
                &existing
                    .try_get::<String, _>("previous_mode")
                    .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?,
            )?;
            let recorded = mode_from_database(
                &existing
                    .try_get::<String, _>("requested_mode")
                    .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?,
            )?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash {
                Ok(ClientTrafficModeOutcome {
                    previous,
                    current: recorded,
                    replayed: true,
                })
            } else {
                Err(ClientProjectionSettingsError::Conflict)
            };
        }
        sqlx::query(
            "UPDATE client_devices SET traffic_mode = ? WHERE id = ? AND tenant_id = ? AND organization_id = ? AND user_id = ?",
        )
        .bind(mode_to_database(requested))
        .bind(client_device_id)
        .bind(tenant_id)
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO client_traffic_mode_requests (id, organization_id, tenant_id, user_id, client_device_id, device_key_id, request_id, request_hash, previous_mode, requested_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(client_device_id)
        .bind(device_key_id)
        .bind(request_id)
        .bind(request_hash.as_slice())
        .bind(mode_to_database(current))
        .bind(mode_to_database(requested))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientProjectionSettingsError::InvalidRecord)?;
        Ok(ClientTrafficModeOutcome {
            previous: current,
            current: requested,
            replayed: false,
        })
    }
}

/// A `POLICY`/`GLOBAL` column value. Unknown values are a storage error rather
/// than a default, so a corrupt row cannot silently downgrade a device to policy
/// mode without anyone noticing.
fn mode_from_database(value: &str) -> Result<ClientTrafficMode, ClientProjectionSettingsError> {
    ClientTrafficMode::from_database_value(value)
        .ok_or(ClientProjectionSettingsError::InvalidRecord)
}

pub(crate) fn mode_to_database(mode: ClientTrafficMode) -> &'static str {
    mode.to_database_value()
}

fn request_fingerprint(
    settings: &ClientProjectionSettings,
    organization_id: Uuid,
    actor_id: Uuid,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-projection-settings/v1\0");
    for value in [
        organization_id.as_bytes().as_slice(),
        settings.tenant_id.as_bytes().as_slice(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    let document = serde_json::to_vec(settings).unwrap_or_default();
    hash.update((document.len() as u32).to_be_bytes());
    hash.update(&document);
    hash.update(actor_id.as_bytes());
    hash.finalize().into()
}

fn mode_request_fingerprint(
    organization_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    client_device_id: Uuid,
    device_key_id: Uuid,
    requested: ClientTrafficMode,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-traffic-mode/v1\0");
    for value in [
        organization_id.as_bytes().as_slice(),
        tenant_id.as_bytes().as_slice(),
        user_id.as_bytes().as_slice(),
        client_device_id.as_bytes().as_slice(),
        device_key_id.as_bytes().as_slice(),
        mode_to_database(requested).as_bytes(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}
