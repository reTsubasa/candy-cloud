use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    time::Duration as StdDuration,
};

use chrono::{DateTime, Utc};
use cloud_control::{
    ControlResourceV1, Ipv4PrefixV1, PathCandidateKindV1, PathCandidateV1, PeerPathPolicyV1,
    PolicyActionV1, ResourceKind, ResourceSpecV1, ResourceState,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::DbPool;

const MAX_ACTOR_LEN: usize = 120;
const MAX_IDEMPOTENCY_KEY_LEN: usize = 160;
const MAX_REQUEST_PATH_LEN: usize = 500;
const MAX_PAGE_SIZE: u16 = 200;
const MAX_LEASE_TTL: StdDuration = StdDuration::from_secs(5 * 60);
const MAX_ERROR_CODE_LEN: usize = 80;

#[derive(Debug, Error)]
pub enum ControlStoreError {
    #[error("invalid control resource: {0}")]
    InvalidResource(String),
    #[error("invalid management request")]
    InvalidRequest,
    #[error("resource was not found")]
    NotFound,
    #[error("resource revision does not match If-Match")]
    RevisionConflict,
    #[error("resource reference is missing, inconsistent, or still in use")]
    ReferenceConflict,
    #[error("idempotency key was reused with a different request")]
    IdempotencyConflict,
    #[error("idempotency replay window has expired")]
    IdempotencyReplayExpired,
    #[error("generation job lease is no longer owned")]
    LeaseLost,
    #[error("invalid generation job state transition")]
    InvalidTransition,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for ControlStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationContext {
    pub actor_id: String,
    pub idempotency_key: String,
    pub request_method: String,
    pub request_path: String,
    pub request_hash: [u8; 32],
    pub idempotency_replay_until: DateTime<Utc>,
}

impl MutationContext {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), ControlStoreError> {
        if self.actor_id.is_empty()
            || self.actor_id.len() > MAX_ACTOR_LEN
            || self.idempotency_key.is_empty()
            || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN
            || self.request_method.is_empty()
            || self.request_method.len() > 12
            || self.request_path.is_empty()
            || self.request_path.len() > MAX_REQUEST_PATH_LEN
            || self.request_hash == [0; 32]
            || self.idempotency_replay_until <= now
        {
            return Err(ControlStoreError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ResourceMutation {
    pub context: MutationContext,
    pub resource: ControlResourceV1,
    pub expected_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationStatusRecord {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub projection_publication_id: Uuid,
    pub apply_state: String,
    pub error_code: Option<String>,
    pub reported_at: DateTime<Utc>,
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTelemetryRecord {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub boot_id: Uuid,
    pub sequence: u64,
    pub lifecycle: String,
    pub configured_peers: u32,
    pub active_peers: u32,
    pub required_route_owners: u32,
    pub ready_route_owners: u32,
    pub fail_open_required: bool,
    pub last_error_code: Option<String>,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_ppm: Option<u32>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub reconnects: Option<u64>,
    pub path_changes: Option<u64>,
    pub reported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationOutcome {
    Applied(ControlResourceV1),
    Replayed(ControlResourceV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourcePageRequest {
    pub limit: u16,
    pub after_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePage {
    pub items: Vec<ControlResourceV1>,
    pub next_cursor: Option<Uuid>,
}

impl ResourcePageRequest {
    pub fn new(limit: u16, after_id: Option<Uuid>) -> Result<Self, ControlStoreError> {
        if limit == 0 || limit > MAX_PAGE_SIZE || after_id.is_some_and(|id| id.is_nil()) {
            return Err(ControlStoreError::InvalidRequest);
        }
        Ok(Self { limit, after_id })
    }
}

#[derive(Clone)]
pub struct ControlRepository {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentControlSnapshot {
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub desired_revision: u64,
    pub resources: Vec<ControlResourceV1>,
    pub transport_bindings: HashMap<Uuid, Vec<RuntimeTransportBinding>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTransportBinding {
    pub candidate_id: Uuid,
    pub endpoint_id: Uuid,
    pub service_node_id: Uuid,
    pub service_node_key_id: Uuid,
    pub service_device_id: Uuid,
    pub service_device_key_id: Uuid,
    pub node_pool_id: Uuid,
    pub endpoint: SocketAddr,
    pub server_name: String,
    pub server_cert_sha256: [u8; 32],
    pub transport_preset: RuntimeTransportPreset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTransportPreset {
    Current,
    BbrV1,
    Aggressive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentityProvision {
    pub endpoint: SocketAddr,
    pub server_cert_sha256: [u8; 32],
    pub transport_preset: RuntimeTransportPreset,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvisionedTransportIdentity {
    pub node_id: Uuid,
    pub endpoints: Vec<ProvisionedTransportEndpoint>,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvisionedTransportEndpoint {
    pub endpoint: SocketAddr,
    pub server_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeActivationReadiness {
    pub segment_id: Uuid,
    pub candidate_count: usize,
    pub ready_candidate_count: usize,
    pub missing_candidate_ids: Vec<Uuid>,
    pub reason_codes: Vec<&'static str>,
}

impl ControlRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn readiness_check(&self) -> Result<(), ControlStoreError> {
        let migration_ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = 16 AND success = TRUE)",
        )
        .fetch_one(&self.pool)
        .await?;
        if !migration_ready {
            return Err(ControlStoreError::InvalidTransition);
        }
        sqlx::query("SELECT tenant_id FROM sdwan_control_resources LIMIT 0")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn runtime_activation_readiness(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> Result<RuntimeActivationReadiness, ControlStoreError> {
        validate_scope(tenant_id, segment_id)?;
        let desired_revision = sqlx::query_scalar::<_, u64>(
            "SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ?",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ControlStoreError::NotFound)?;
        let snapshot = self
            .segment_snapshot(tenant_id, segment_id, desired_revision)
            .await?;
        let mut candidate_ids = snapshot
            .resources
            .iter()
            .filter_map(|resource| {
                matches!(resource.resource, ResourceSpecV1::PathCandidate(_))
                    .then_some(resource.metadata.id)
            })
            .collect::<Vec<_>>();
        candidate_ids.sort_unstable();
        let missing_candidate_ids = candidate_ids
            .iter()
            .copied()
            .filter(|id| !snapshot.transport_bindings.contains_key(id))
            .collect::<Vec<_>>();
        let mut reason_codes = Vec::new();
        let service_enabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM entitlements e JOIN subscriptions s ON s.id = e.subscription_id AND s.tenant_id = e.tenant_id AND s.status IN ('TRIAL','ACTIVE') JOIN node_pools np ON np.id = e.node_pool_id AND np.tenant_id = e.tenant_id AND np.status = 'ACTIVE' WHERE e.tenant_id = ? AND e.service_permission = 'private.tun.connect' AND e.status = 'ACTIVE')",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        if !service_enabled {
            reason_codes.push("service_not_enabled");
        } else if candidate_ids.is_empty() || !missing_candidate_ids.is_empty() {
            reason_codes.push("node_offline");
        }
        let published: Option<(u64, Vec<u8>)> = sqlx::query_as(
            "SELECT current_generation, current_content_hash FROM segments WHERE tenant_id = ? AND id = ? AND state = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_optional(&self.pool)
        .await?;
        let publication_current = published
            .as_ref()
            .is_some_and(|(generation, hash)| *generation == desired_revision && hash.len() == 32);
        if !publication_current {
            reason_codes.push("config_pending");
        } else if !snapshot.transport_bindings.is_empty() {
            let generation = published.as_ref().map(|value| value.0).unwrap_or_default();
            for binding in snapshot.transport_bindings.values().flatten() {
                let catalog_count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM runtime_projection_transport_catalog WHERE tenant_id = ? AND segment_id = ? AND segment_generation = ? AND transport_node_id = ? AND transport_node_key_id = ?",
                )
                .bind(tenant_id)
                .bind(segment_id)
                .bind(generation)
                .bind(binding.service_node_id)
                .bind(binding.service_node_key_id)
                .fetch_one(&self.pool)
                .await?;
                if catalog_count == 0 {
                    reason_codes.push("config_pending");
                    break;
                }
            }
        }
        reason_codes.sort_unstable();
        reason_codes.dedup();
        Ok(RuntimeActivationReadiness {
            segment_id,
            candidate_count: candidate_ids.len(),
            ready_candidate_count: candidate_ids.len() - missing_candidate_ids.len(),
            missing_candidate_ids,
            reason_codes,
        })
    }

    pub async fn runtime_configuration_statuses(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<RuntimeConfigurationStatusRecord>, ControlStoreError> {
        if tenant_id.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let rows = sqlx::query(
            "SELECT status.device_id, status.device_key_id, status.projection_publication_id, status.apply_state, status.error_code, status.reported_at, EXISTS(SELECT 1 FROM segment_attachments attachment JOIN segments segment ON segment.id = attachment.segment_id AND segment.tenant_id = attachment.tenant_id AND segment.state = 'ACTIVE' JOIN site_route_projection_publications projection ON projection.id = status.projection_publication_id AND projection.tenant_id = attachment.tenant_id AND projection.attachment_id = attachment.id AND projection.device_id = attachment.device_id AND projection.device_key_id = attachment.device_key_id AND projection.segment_generation = segment.current_generation AND projection.segment_content_hash = segment.current_content_hash WHERE attachment.tenant_id = status.tenant_id AND attachment.device_id = status.device_id AND attachment.device_key_id = status.device_key_id AND attachment.principal_kind = 'DEVICE' AND attachment.state IN ('ACTIVE','STANDBY')) AS current_configuration FROM runtime_configuration_status status WHERE status.tenant_id = ? ORDER BY status.reported_at DESC, status.device_id LIMIT 4096",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let apply_state: String = row.try_get("apply_state")?;
                if !matches!(apply_state.as_str(), "ACTIVE" | "REJECTED") {
                    return Err(ControlStoreError::InvalidTransition);
                }
                Ok(RuntimeConfigurationStatusRecord {
                    device_id: row.try_get("device_id")?,
                    device_key_id: row.try_get("device_key_id")?,
                    projection_publication_id: row.try_get("projection_publication_id")?,
                    apply_state,
                    error_code: row.try_get("error_code")?,
                    reported_at: row.try_get("reported_at")?,
                    current: row.try_get("current_configuration")?,
                })
            })
            .collect()
    }

    pub async fn runtime_telemetry(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<RuntimeTelemetryRecord>, ControlStoreError> {
        if tenant_id.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let rows = sqlx::query(
            "SELECT device_id, device_key_id, boot_id, sequence, lifecycle, configured_peers, active_peers, required_route_owners, ready_route_owners, fail_open_required, last_error_code, rtt_ms, jitter_ms, packet_loss_ppm, rx_bps, tx_bps, reconnects, path_changes, reported_at FROM runtime_telemetry_latest WHERE tenant_id = ? ORDER BY reported_at DESC, device_id LIMIT 4096",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let lifecycle: String = row.try_get("lifecycle")?;
                if !matches!(
                    lifecycle.as_str(),
                    "STARTING" | "ACTIVE" | "DEGRADED" | "FAIL_OPEN" | "STOPPED" | "UNKNOWN"
                ) {
                    return Err(ControlStoreError::InvalidTransition);
                }
                Ok(RuntimeTelemetryRecord {
                    device_id: row.try_get("device_id")?,
                    device_key_id: row.try_get("device_key_id")?,
                    boot_id: row.try_get("boot_id")?,
                    sequence: row.try_get("sequence")?,
                    lifecycle: lifecycle.to_ascii_lowercase(),
                    configured_peers: row.try_get("configured_peers")?,
                    active_peers: row.try_get("active_peers")?,
                    required_route_owners: row.try_get("required_route_owners")?,
                    ready_route_owners: row.try_get("ready_route_owners")?,
                    fail_open_required: row.try_get("fail_open_required")?,
                    last_error_code: row.try_get("last_error_code")?,
                    rtt_ms: row.try_get("rtt_ms")?,
                    jitter_ms: row.try_get("jitter_ms")?,
                    packet_loss_ppm: row.try_get("packet_loss_ppm")?,
                    rx_bps: row.try_get("rx_bps")?,
                    tx_bps: row.try_get("tx_bps")?,
                    reconnects: row.try_get("reconnects")?,
                    path_changes: row.try_get("path_changes")?,
                    reported_at: row.try_get("reported_at")?,
                })
            })
            .collect()
    }

    pub async fn segment_snapshot(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        desired_revision: u64,
    ) -> Result<SegmentControlSnapshot, ControlStoreError> {
        if tenant_id.is_nil() || segment_id.is_nil() || desired_revision == 0 {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await?;
        let current_revision: u64 = sqlx::query_scalar(
            "SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ? FOR SHARE",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ControlStoreError::NotFound)?;
        if current_revision < desired_revision {
            return Err(ControlStoreError::InvalidTransition);
        }
        let rows = sqlx::query(
            "WITH RECURSIVE graph (resource_kind, resource_id) AS (SELECT resource_kind, id FROM sdwan_control_resources WHERE tenant_id = ? AND state = 'ACTIVE' AND ((resource_kind = 'SEGMENT' AND id = ?) OR segment_id = ?) UNION DISTINCT SELECT refs.target_kind, refs.target_id FROM sdwan_control_resource_references refs JOIN graph current ON refs.tenant_id = ? AND refs.source_kind = current.resource_kind AND refs.source_id = current.resource_id) SELECT DISTINCT resources.resource_kind, resources.id, CAST(resources.document_json AS CHAR) AS document_json FROM graph JOIN sdwan_control_resources resources ON resources.tenant_id = ? AND resources.resource_kind = graph.resource_kind AND resources.id = graph.resource_id WHERE resources.state = 'ACTIVE' ORDER BY resources.resource_kind, resources.id",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .bind(segment_id)
        .bind(tenant_id)
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await?;
        let resources = rows
            .into_iter()
            .map(|row| decode_resource(row.try_get("document_json")?))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await?;
        crate::sdwan::SdwanRepository::new(self.pool.clone())
            .ensure_control_topology(tenant_id, segment_id, &resources)
            .await
            .map_err(|error| ControlStoreError::Database(error.to_string()))?;
        let mut transaction = self.pool.begin().await?;
        let transport_bindings =
            load_transport_bindings(&mut transaction, tenant_id, &resources).await?;
        transaction.commit().await?;
        if !resources.iter().any(|resource| {
            resource.metadata.id == segment_id
                && matches!(resource.resource, ResourceSpecV1::Segment(_))
        }) {
            return Err(ControlStoreError::NotFound);
        }
        Ok(SegmentControlSnapshot {
            tenant_id,
            segment_id,
            desired_revision,
            resources,
            transport_bindings,
        })
    }

    pub async fn provision_private_transport_identity(
        &self,
        tenant_id: Uuid,
        control_node_id: Uuid,
        request_id: &str,
        provisions: &[TransportIdentityProvision],
    ) -> Result<ProvisionedTransportIdentity, ControlStoreError> {
        if tenant_id.is_nil()
            || control_node_id.is_nil()
            || request_id.is_empty()
            || request_id.len() > 120
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || provisions.is_empty()
            || provisions.len() > 8
            || provisions.iter().any(|provision| {
                provision.endpoint.port() == 0 || provision.server_cert_sha256 == [0; 32]
            })
        {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut canonical = provisions.to_vec();
        canonical.sort_unstable_by_key(|item| item.endpoint);
        if canonical
            .windows(2)
            .any(|items| items[0].endpoint == items[1].endpoint)
        {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await?;
        let resource = load_control_resource(
            &mut transaction,
            tenant_id,
            ResourceKind::Node,
            control_node_id,
        )
        .await?;
        let ResourceSpecV1::Node(control_node) = resource.resource else {
            return Err(ControlStoreError::ReferenceConflict);
        };
        let server_name = format!("device-{}.sdwan.candy.internal", control_node.device_id);
        if !valid_server_name(&server_name) {
            return Err(ControlStoreError::InvalidTransition);
        }
        let mut request_digest = Sha256::new();
        request_digest.update(b"candy/runtime-transport-identity-v1\0");
        request_digest.update((canonical.len() as u64).to_be_bytes());
        for provision in &canonical {
            let endpoint = provision.endpoint.to_string();
            request_digest.update((endpoint.len() as u64).to_be_bytes());
            request_digest.update(endpoint.as_bytes());
            request_digest.update(provision.server_cert_sha256);
            request_digest.update(transport_preset_value(provision.transport_preset).as_bytes());
        }
        let request_hash: [u8; 32] = request_digest.finalize().into();
        if let Some(row) = sqlx::query(
            "SELECT request_hash, CAST(response_json AS CHAR) AS response_json FROM runtime_transport_identity_requests WHERE tenant_id = ? AND device_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(control_node.device_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            if row.try_get::<Vec<u8>, _>("request_hash")?.as_slice() != request_hash {
                return Err(ControlStoreError::IdempotencyConflict);
            }
            let mut response: ProvisionedTransportIdentity =
                serde_json::from_str(&row.try_get::<String, _>("response_json")?)
                .map_err(|_| ControlStoreError::InvalidTransition)?;
            response.replayed = true;
            transaction.commit().await?;
            return Ok(response);
        }
        let valid_device: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices d JOIN device_keys dk ON dk.id = ? AND dk.device_id = d.id AND dk.tenant_id = d.tenant_id WHERE d.id = ? AND d.tenant_id = ? AND d.status = 'ACTIVE' AND dk.status = 'ACTIVE')",
        )
        .bind(control_node.device_key_id)
        .bind(control_node.device_id)
        .bind(tenant_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !valid_device {
            return Err(ControlStoreError::ReferenceConflict);
        }

        let node_pools = sqlx::query_scalar::<_, Uuid>(
            "SELECT np.id FROM node_pools np JOIN entitlements e ON e.node_pool_id = np.id AND e.tenant_id = ? AND e.service_permission = 'private.tun.connect' AND e.status = 'ACTIVE' JOIN subscriptions s ON s.id = e.subscription_id AND s.tenant_id = e.tenant_id AND s.status IN ('TRIAL','ACTIVE') WHERE np.tenant_id = ? AND np.service_class = 'PRIVATE' AND np.status = 'ACTIVE' FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(tenant_id)
        .fetch_all(&mut *transaction)
        .await?;
        if node_pools.len() != 1 {
            return Err(ControlStoreError::ReferenceConflict);
        }
        let node_pool_id = node_pools[0];
        let service_node_id = match sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM nodes WHERE tenant_id = ? AND device_id = ? AND device_key_id = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(control_node.device_id)
        .bind(control_node.device_key_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            Some(id) => {
                sqlx::query("UPDATE nodes SET node_pool_id = ?, status = 'ACTIVE' WHERE id = ?")
                    .bind(node_pool_id)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await?;
                id
            }
            None => {
                let id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO nodes (id, tenant_id, device_id, device_key_id, node_pool_id, node_id, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
                )
                .bind(id)
                .bind(tenant_id)
                .bind(control_node.device_id)
                .bind(control_node.device_key_id)
                .bind(node_pool_id)
                .bind(format!("candy:device:{}", control_node.device_id))
                .execute(&mut *transaction)
                .await?;
                id
            }
        };
        sqlx::query("UPDATE node_endpoints SET status = 'DISABLED' WHERE node_id = ?")
            .bind(service_node_id)
            .execute(&mut *transaction)
            .await?;
        let mut effective_endpoints = Vec::with_capacity(canonical.len());
        for provision in &canonical {
            let endpoint = provision.endpoint.to_string();
            if let Some(endpoint_id) = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM node_endpoints WHERE node_id = ? AND endpoint = ? FOR UPDATE",
            )
            .bind(service_node_id)
            .bind(&endpoint)
            .fetch_optional(&mut *transaction)
            .await?
            {
                sqlx::query(
                "UPDATE node_endpoints SET transport = 'CANDY_QUIC_UDP', server_name = ?, server_cert_sha256 = ?, transport_preset = ?, status = 'ACTIVE' WHERE id = ?",
            )
            .bind(&server_name)
            .bind(provision.server_cert_sha256.as_slice())
            .bind(transport_preset_value(provision.transport_preset))
            .bind(endpoint_id)
            .execute(&mut *transaction)
            .await?;
            } else {
                sqlx::query(
                "INSERT INTO node_endpoints (id, node_id, endpoint, transport, server_name, server_cert_sha256, transport_preset, status, region) VALUES (?, ?, ?, 'CANDY_QUIC_UDP', ?, ?, ?, 'ACTIVE', 'tenant-managed')",
            )
            .bind(Uuid::now_v7())
            .bind(service_node_id)
            .bind(&endpoint)
            .bind(&server_name)
            .bind(provision.server_cert_sha256.as_slice())
            .bind(transport_preset_value(provision.transport_preset))
            .execute(&mut *transaction)
            .await?;
            }
            effective_endpoints.push(ProvisionedTransportEndpoint {
                endpoint: provision.endpoint,
                server_name: server_name.clone(),
            });
        }
        let response = ProvisionedTransportIdentity {
            node_id: control_node_id,
            endpoints: effective_endpoints,
            replayed: false,
        };
        let response_json =
            serde_json::to_string(&response).map_err(|_| ControlStoreError::InvalidTransition)?;
        sqlx::query(
            "INSERT INTO runtime_transport_identity_requests (tenant_id, device_id, request_id, request_hash, response_json) VALUES (?, ?, ?, ?, CAST(? AS JSON))",
        )
        .bind(tenant_id)
        .bind(control_node.device_id)
        .bind(request_id)
        .bind(request_hash.as_slice())
        .bind(response_json)
        .execute(&mut *transaction)
        .await?;
        for segment_id in dependent_segments(
            &mut transaction,
            tenant_id,
            ResourceKind::Node,
            control_node_id,
        )
        .await?
        {
            enqueue_generation(&mut transaction, tenant_id, segment_id, request_hash).await?;
        }
        transaction.commit().await?;
        Ok(response)
    }

    pub async fn provision_private_transport_identity_for_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
        request_id: &str,
        provisions: &[TransportIdentityProvision],
    ) -> Result<ProvisionedTransportIdentity, ControlStoreError> {
        if tenant_id.is_nil() || device_id.is_nil() || device_key_id.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let node_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND state = 'ACTIVE' AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_id')) = ? AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_key_id')) = ?",
        )
        .bind(tenant_id)
        .bind(device_id.to_string())
        .bind(device_key_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ControlStoreError::NotFound)?;
        self.provision_private_transport_identity(tenant_id, node_id, request_id, provisions)
            .await
    }

    pub async fn withdraw_private_transport_identity_for_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
    ) -> Result<(), ControlStoreError> {
        if tenant_id.is_nil() || device_id.is_nil() || device_key_id.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut transaction = self.pool.begin().await?;
        let control_node_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND state = 'ACTIVE' AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_id')) = ? AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_key_id')) = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(device_id.to_string())
        .bind(device_key_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(ControlStoreError::NotFound)?;
        sqlx::query(
            "UPDATE node_endpoints ne JOIN nodes n ON n.id = ne.node_id SET ne.status = 'DISABLED' WHERE n.tenant_id = ? AND n.device_id = ? AND n.device_key_id = ?",
        )
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id)
        .execute(&mut *transaction)
        .await?;
        let mut digest = Sha256::new();
        digest.update(b"candy/runtime-transport-withdraw-v1\0");
        digest.update(device_id.as_bytes());
        let request_hash: [u8; 32] = digest.finalize().into();
        for segment_id in dependent_segments(
            &mut transaction,
            tenant_id,
            ResourceKind::Node,
            control_node_id,
        )
        .await?
        {
            enqueue_generation(&mut transaction, tenant_id, segment_id, request_hash).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        kind: ResourceKind,
        id: Uuid,
    ) -> Result<ControlResourceV1, ControlStoreError> {
        validate_scope(tenant_id, id)?;
        let row = sqlx::query(
            "SELECT CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = ? AND id = ? AND state <> 'DELETED'",
        )
        .bind(tenant_id)
        .bind(kind.database_value())
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ControlStoreError::NotFound)?;
        decode_resource(row.try_get("document_json")?)
    }

    pub async fn list(
        &self,
        tenant_id: Uuid,
        kind: ResourceKind,
        page: ResourcePageRequest,
    ) -> Result<ResourcePage, ControlStoreError> {
        if tenant_id.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let rows = sqlx::query(
            "SELECT CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = ? AND state <> 'DELETED' AND (? IS NULL OR id > ?) ORDER BY id LIMIT ?",
        )
        .bind(tenant_id)
        .bind(kind.database_value())
        .bind(page.after_id)
        .bind(page.after_id)
        .bind(u32::from(page.limit) + 1)
        .fetch_all(&self.pool)
        .await?;
        let mut items: Vec<ControlResourceV1> = rows
            .into_iter()
            .map(|row| decode_resource(row.try_get("document_json")?))
            .collect::<Result<_, _>>()?;
        let next_cursor = if items.len() > usize::from(page.limit) {
            items.truncate(usize::from(page.limit));
            items.last().map(|item| item.metadata.id)
        } else {
            None
        };
        Ok(ResourcePage { items, next_cursor })
    }

    pub async fn mutate(
        &self,
        mutation: &ResourceMutation,
        now: DateTime<Utc>,
    ) -> Result<MutationOutcome, ControlStoreError> {
        mutation.context.validate(now)?;
        mutation
            .resource
            .validate()
            .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
        let metadata = &mutation.resource.metadata;
        let expected = mutation.expected_revision;
        if (expected.is_none() && metadata.revision != 1)
            || expected.is_some_and(|value| value == 0 || metadata.revision != value + 1)
        {
            return Err(ControlStoreError::RevisionConflict);
        }

        let mut transaction = self.pool.begin().await?;
        if let Some(replayed) = replay_idempotency(&mut transaction, mutation, now).await? {
            transaction.commit().await?;
            return Ok(MutationOutcome::Replayed(replayed));
        }
        let mut affected_segments = dependent_segments(
            &mut transaction,
            metadata.tenant_id,
            mutation.resource.resource.kind(),
            metadata.id,
        )
        .await?;
        validate_cross_resource(&mut transaction, &mutation.resource).await?;

        let document = serde_json::to_string(&mutation.resource)
            .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
        let document_hash = mutation
            .resource
            .resource
            .document_hash()
            .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
        let segment_id = affected_segment_id(&mutation.resource);
        let rows = if let Some(expected_revision) = expected {
            sqlx::query(
                "UPDATE sdwan_control_resources SET revision = ?, state = ?, segment_id = ?, document_hash = ?, document_json = CAST(? AS JSON), updated_by = ? WHERE tenant_id = ? AND resource_kind = ? AND id = ? AND revision = ?",
            )
            .bind(metadata.revision)
            .bind(resource_state(metadata.state))
            .bind(segment_id)
            .bind(document_hash.as_slice())
            .bind(&document)
            .bind(&mutation.context.actor_id)
            .bind(metadata.tenant_id)
            .bind(mutation.resource.resource.kind().database_value())
            .bind(metadata.id)
            .bind(expected_revision)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        } else {
            sqlx::query(
                "INSERT INTO sdwan_control_resources (tenant_id, resource_kind, id, revision, state, segment_id, document_hash, document_json, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?)",
            )
            .bind(metadata.tenant_id)
            .bind(mutation.resource.resource.kind().database_value())
            .bind(metadata.id)
            .bind(metadata.revision)
            .bind(resource_state(metadata.state))
            .bind(segment_id)
            .bind(document_hash.as_slice())
            .bind(&document)
            .bind(&mutation.context.actor_id)
            .bind(&mutation.context.actor_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected()
        };
        if rows != 1 {
            transaction.rollback().await?;
            return Err(ControlStoreError::RevisionConflict);
        }

        replace_resource_references(&mut transaction, &mutation.resource).await?;
        affected_segments.extend(
            dependent_segments(
                &mut transaction,
                metadata.tenant_id,
                mutation.resource.resource.kind(),
                metadata.id,
            )
            .await?,
        );
        if let Some(segment_id) = segment_id {
            affected_segments.insert(segment_id);
        }
        for segment_id in affected_segments {
            enqueue_generation(
                &mut transaction,
                metadata.tenant_id,
                segment_id,
                mutation.context.request_hash,
            )
            .await?;
        }
        insert_idempotency(&mut transaction, mutation).await?;
        transaction.commit().await?;
        Ok(MutationOutcome::Applied(mutation.resource.clone()))
    }
}

async fn load_transport_bindings(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    resources: &[ControlResourceV1],
) -> Result<HashMap<Uuid, Vec<RuntimeTransportBinding>>, ControlStoreError> {
    let nodes: HashMap<Uuid, &cloud_control::NodeV1> = resources
        .iter()
        .filter_map(|resource| match &resource.resource {
            ResourceSpecV1::Node(node) => Some((resource.metadata.id, node)),
            _ => None,
        })
        .collect();
    let relays: HashMap<Uuid, &cloud_control::RelayV1> = resources
        .iter()
        .filter_map(|resource| match &resource.resource {
            ResourceSpecV1::Relay(relay) => Some((resource.metadata.id, relay)),
            _ => None,
        })
        .collect();
    let mut result = HashMap::new();
    for resource in resources {
        let ResourceSpecV1::PathCandidate(candidate) = &resource.resource else {
            continue;
        };
        let expected_transport_node = nodes
            .get(&candidate.transport_node_id)
            .ok_or(ControlStoreError::ReferenceConflict)?;
        let rows = sqlx::query(
            "SELECT ne.id AS endpoint_id, n.id AS service_node_id, n.device_key_id AS service_node_key_id, n.device_id AS service_device_id, n.device_key_id AS service_device_key_id, n.node_pool_id, ne.endpoint, ne.server_name, ne.server_cert_sha256, ne.transport_preset FROM nodes n JOIN devices d ON d.id = n.device_id AND d.tenant_id = n.tenant_id AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.id = n.device_key_id AND dk.device_id = d.id AND dk.tenant_id = d.tenant_id AND dk.status = 'ACTIVE' JOIN node_pools np ON np.id = n.node_pool_id AND np.tenant_id = n.tenant_id AND np.status = 'ACTIVE' JOIN entitlements entitlement ON entitlement.tenant_id = n.tenant_id AND entitlement.node_pool_id = np.id AND entitlement.service_permission = 'private.tun.connect' AND entitlement.status = 'ACTIVE' JOIN subscriptions subscription ON subscription.id = entitlement.subscription_id AND subscription.tenant_id = entitlement.tenant_id AND subscription.status IN ('TRIAL','ACTIVE') JOIN node_endpoints ne ON ne.node_id = n.id AND ne.status = 'ACTIVE' AND ne.transport = 'CANDY_QUIC_UDP' WHERE n.tenant_id = ? AND n.device_id = ? AND n.device_key_id = ? AND n.status = 'ACTIVE' ORDER BY ne.id",
        )
        .bind(tenant_id)
        .bind(expected_transport_node.device_id)
        .bind(expected_transport_node.device_key_id)
        .fetch_all(&mut **transaction)
        .await?;
        if rows.len() > 8 {
            return Err(ControlStoreError::InvalidTransition);
        }
        if rows.is_empty() {
            continue;
        }
        if candidate.kind == PathCandidateKindV1::Relay {
            let expected_relay_node = candidate
                .relay_id
                .and_then(|relay_id| relays.get(&relay_id))
                .and_then(|relay| nodes.get(&relay.service_node_id))
                .ok_or(ControlStoreError::ReferenceConflict)?;
            if expected_relay_node.device_id != expected_transport_node.device_id
                || expected_relay_node.device_key_id != expected_transport_node.device_key_id
            {
                return Err(ControlStoreError::ReferenceConflict);
            }
        }
        let mut bindings = Vec::with_capacity(rows.len());
        for row in rows {
            let endpoint: String = row.try_get("endpoint")?;
            let pin: Vec<u8> = row.try_get("server_cert_sha256")?;
            bindings.push(RuntimeTransportBinding {
                candidate_id: resource.metadata.id,
                endpoint_id: row.try_get("endpoint_id")?,
                service_node_id: row.try_get("service_node_id")?,
                service_node_key_id: row.try_get("service_node_key_id")?,
                service_device_id: row.try_get("service_device_id")?,
                service_device_key_id: row.try_get("service_device_key_id")?,
                node_pool_id: row.try_get("node_pool_id")?,
                endpoint: endpoint
                    .parse()
                    .map_err(|_| ControlStoreError::InvalidTransition)?,
                server_name: row.try_get("server_name")?,
                server_cert_sha256: pin
                    .try_into()
                    .map_err(|_| ControlStoreError::InvalidTransition)?,
                transport_preset: parse_transport_preset(row.try_get("transport_preset")?)?,
            });
        }
        result.insert(resource.metadata.id, bindings);
    }
    Ok(result)
}

fn valid_server_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && lower != "localhost"
        && !lower.ends_with(".localhost")
        && !lower.ends_with(".invalid")
        && !lower.ends_with(".example")
        && !lower.ends_with(".test")
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn transport_preset_value(value: RuntimeTransportPreset) -> &'static str {
    match value {
        RuntimeTransportPreset::Current => "CURRENT",
        RuntimeTransportPreset::BbrV1 => "BBR_V1",
        RuntimeTransportPreset::Aggressive => "AGGRESSIVE",
    }
}

fn parse_transport_preset(value: String) -> Result<RuntimeTransportPreset, ControlStoreError> {
    match value.as_str() {
        "CURRENT" => Ok(RuntimeTransportPreset::Current),
        "BBR_V1" => Ok(RuntimeTransportPreset::BbrV1),
        "AGGRESSIVE" => Ok(RuntimeTransportPreset::Aggressive),
        _ => Err(ControlStoreError::InvalidTransition),
    }
}

fn affected_segment_id(resource: &ControlResourceV1) -> Option<Uuid> {
    match &resource.resource {
        ResourceSpecV1::Segment(_) => Some(resource.metadata.id),
        other => other.segment_id(),
    }
}

fn resource_references(resource: &ControlResourceV1) -> HashSet<(ResourceKind, Uuid)> {
    let mut references = HashSet::new();
    let mut insert = |kind, id| {
        references.insert((kind, id));
    };
    match &resource.resource {
        ResourceSpecV1::Node(value) => insert(ResourceKind::Site, value.site_id),
        ResourceSpecV1::Site(_) | ResourceSpecV1::Segment(_) => {}
        ResourceSpecV1::Attachment(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            insert(ResourceKind::Site, value.site_id);
            insert(ResourceKind::Node, value.node_id);
        }
        ResourceSpecV1::Prefix(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            insert(ResourceKind::Site, value.site_id);
        }
        ResourceSpecV1::Peer(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            insert(ResourceKind::Site, value.site_a_id);
            insert(ResourceKind::Site, value.site_b_id);
        }
        ResourceSpecV1::Relay(value) => insert(ResourceKind::Node, value.service_node_id),
        ResourceSpecV1::PathCandidate(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            insert(ResourceKind::Peer, value.peer_id);
            insert(ResourceKind::Attachment, value.source_attachment_id);
            insert(ResourceKind::Attachment, value.destination_attachment_id);
            insert(ResourceKind::Node, value.transport_node_id);
            if let Some(relay_id) = value.relay_id {
                insert(ResourceKind::Relay, relay_id);
            }
        }
        ResourceSpecV1::Egress(value) => {
            insert(ResourceKind::Site, value.site_id);
            insert(ResourceKind::Attachment, value.attachment_id);
        }
        ResourceSpecV1::ServicePolicy(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            for rule in &value.rules {
                for site_id in &rule.source_site_ids {
                    insert(ResourceKind::Site, *site_id);
                }
                if let PolicyActionV1::RemoteEgress(egress_id) = rule.action {
                    insert(ResourceKind::Egress, egress_id);
                }
            }
        }
        ResourceSpecV1::DnsIntent(value) => {
            insert(ResourceKind::Segment, value.segment_id);
            insert(ResourceKind::Site, value.site_id);
            for prefix_id in value
                .records
                .iter()
                .filter_map(|record| record.required_prefix_id)
            {
                insert(ResourceKind::Prefix, prefix_id);
            }
        }
    }
    references
}

async fn validate_cross_resource(
    transaction: &mut Transaction<'_, MySql>,
    resource: &ControlResourceV1,
) -> Result<(), ControlStoreError> {
    if resource.metadata.state == ResourceState::Deleted {
        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sdwan_control_resource_references refs JOIN sdwan_control_resources source ON source.tenant_id = refs.tenant_id AND source.resource_kind = refs.source_kind AND source.id = refs.source_id WHERE refs.tenant_id = ? AND refs.target_kind = ? AND refs.target_id = ? AND source.state <> 'DELETED')",
        )
        .bind(resource.metadata.tenant_id)
        .bind(resource.resource.kind().database_value())
        .bind(resource.metadata.id)
        .fetch_one(&mut **transaction)
        .await?;
        return if referenced {
            Err(ControlStoreError::ReferenceConflict)
        } else {
            Ok(())
        };
    }

    for (kind, id) in resource_references(resource) {
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = ? AND id = ? FOR SHARE",
        )
        .bind(resource.metadata.tenant_id)
        .bind(kind.database_value())
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;
        if state.as_deref() != Some("ACTIVE") {
            return Err(ControlStoreError::ReferenceConflict);
        }
    }

    match &resource.resource {
        ResourceSpecV1::Node(value) => {
            let identity_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM devices d JOIN device_keys dk ON dk.tenant_id = d.tenant_id AND dk.device_id = d.id WHERE d.tenant_id = ? AND d.id = ? AND dk.id = ? AND d.status = 'ACTIVE' AND dk.status = 'ACTIVE')",
            )
            .bind(resource.metadata.tenant_id)
            .bind(value.device_id)
            .bind(value.device_key_id)
            .fetch_one(&mut **transaction)
            .await?;
            if !identity_exists {
                return Err(ControlStoreError::ReferenceConflict);
            }
            let identity_already_configured: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'NODE' AND id <> ? AND state <> 'DELETED' AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_id')) = ?)",
            )
            .bind(resource.metadata.tenant_id)
            .bind(resource.metadata.id)
            .bind(value.device_id.to_string())
            .fetch_one(&mut **transaction)
            .await?;
            if identity_already_configured {
                return Err(ControlStoreError::ReferenceConflict);
            }
        }
        ResourceSpecV1::Segment(value) => {
            validate_segment_overlay(
                transaction,
                resource.metadata.tenant_id,
                resource.metadata.id,
                value.overlay_prefix,
            )
            .await?;
        }
        ResourceSpecV1::Attachment(value) => {
            let node = load_control_resource(
                transaction,
                resource.metadata.tenant_id,
                ResourceKind::Node,
                value.node_id,
            )
            .await?;
            let segment = load_control_resource(
                transaction,
                resource.metadata.tenant_id,
                ResourceKind::Segment,
                value.segment_id,
            )
            .await?;
            let (ResourceSpecV1::Node(node), ResourceSpecV1::Segment(segment)) =
                (&node.resource, &segment.resource)
            else {
                return Err(ControlStoreError::ReferenceConflict);
            };
            if node.site_id != value.site_id
                || !valid_overlay_host(segment.overlay_prefix, value.overlay_router_ipv4)
            {
                return Err(ControlStoreError::ReferenceConflict);
            }
            let duplicate: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'ATTACHMENT' AND id <> ? AND state <> 'DELETED' AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.segment_id')) = ? AND JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.overlay_router_ipv4')) = ?)",
            )
            .bind(resource.metadata.tenant_id)
            .bind(resource.metadata.id)
            .bind(value.segment_id.to_string())
            .bind(value.overlay_router_ipv4.to_string())
            .fetch_one(&mut **transaction)
            .await?;
            if duplicate {
                return Err(ControlStoreError::ReferenceConflict);
            }
        }
        ResourceSpecV1::Prefix(value) => {
            let segment = load_control_resource(
                transaction,
                resource.metadata.tenant_id,
                ResourceKind::Segment,
                value.segment_id,
            )
            .await?;
            let ResourceSpecV1::Segment(segment) = segment.resource else {
                return Err(ControlStoreError::ReferenceConflict);
            };
            if value.prefix.overlaps(segment.overlay_prefix) {
                return Err(ControlStoreError::ReferenceConflict);
            }
            let rows = sqlx::query(
                "SELECT CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'PREFIX' AND id <> ? AND state <> 'DELETED' AND segment_id = ? FOR SHARE",
            )
            .bind(resource.metadata.tenant_id)
            .bind(resource.metadata.id)
            .bind(value.segment_id)
            .fetch_all(&mut **transaction)
            .await?;
            for row in rows {
                let other = decode_resource(row.try_get("document_json")?)?;
                if let ResourceSpecV1::Prefix(other) = other.resource {
                    if value.prefix.overlaps(other.prefix) {
                        return Err(ControlStoreError::ReferenceConflict);
                    }
                }
            }
        }
        ResourceSpecV1::Peer(value) => {
            let rows = sqlx::query(
                "SELECT CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = 'PEER' AND id <> ? AND state <> 'DELETED' AND segment_id = ? FOR SHARE",
            )
            .bind(resource.metadata.tenant_id)
            .bind(resource.metadata.id)
            .bind(value.segment_id)
            .fetch_all(&mut **transaction)
            .await?;
            for row in rows {
                let other = decode_resource(row.try_get("document_json")?)?;
                if let ResourceSpecV1::Peer(other) = other.resource {
                    if other.site_a_id == value.site_a_id && other.site_b_id == value.site_b_id {
                        return Err(ControlStoreError::ReferenceConflict);
                    }
                }
            }
        }
        ResourceSpecV1::PathCandidate(value) => {
            validate_path_candidate_references(transaction, resource.metadata.tenant_id, value)
                .await?;
        }
        ResourceSpecV1::Egress(value) => {
            let attachment = load_control_resource(
                transaction,
                resource.metadata.tenant_id,
                ResourceKind::Attachment,
                value.attachment_id,
            )
            .await?;
            if !matches!(attachment.resource, ResourceSpecV1::Attachment(ref attachment) if attachment.site_id == value.site_id)
            {
                return Err(ControlStoreError::ReferenceConflict);
            }
        }
        ResourceSpecV1::ServicePolicy(value) => {
            for rule in &value.rules {
                if let PolicyActionV1::RemoteEgress(egress_id) = rule.action {
                    let egress = load_control_resource(
                        transaction,
                        resource.metadata.tenant_id,
                        ResourceKind::Egress,
                        egress_id,
                    )
                    .await?;
                    let ResourceSpecV1::Egress(egress) = egress.resource else {
                        return Err(ControlStoreError::ReferenceConflict);
                    };
                    let attachment = load_control_resource(
                        transaction,
                        resource.metadata.tenant_id,
                        ResourceKind::Attachment,
                        egress.attachment_id,
                    )
                    .await?;
                    if !matches!(attachment.resource, ResourceSpecV1::Attachment(attachment) if attachment.segment_id == value.segment_id)
                    {
                        return Err(ControlStoreError::ReferenceConflict);
                    }
                }
            }
        }
        ResourceSpecV1::DnsIntent(value) => {
            for prefix_id in value
                .records
                .iter()
                .filter_map(|record| record.required_prefix_id)
            {
                let prefix = load_control_resource(
                    transaction,
                    resource.metadata.tenant_id,
                    ResourceKind::Prefix,
                    prefix_id,
                )
                .await?;
                if !matches!(prefix.resource, ResourceSpecV1::Prefix(prefix) if prefix.segment_id == value.segment_id)
                {
                    return Err(ControlStoreError::ReferenceConflict);
                }
            }
        }
        ResourceSpecV1::Site(_) | ResourceSpecV1::Relay(_) => {}
    }
    Ok(())
}

async fn load_control_resource(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    kind: ResourceKind,
    id: Uuid,
) -> Result<ControlResourceV1, ControlStoreError> {
    let row = sqlx::query(
        "SELECT CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND resource_kind = ? AND id = ? AND state = 'ACTIVE' FOR SHARE",
    )
    .bind(tenant_id)
    .bind(kind.database_value())
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(ControlStoreError::ReferenceConflict)?;
    decode_resource(row.try_get("document_json")?)
}

async fn validate_segment_overlay(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    segment_id: Uuid,
    overlay_prefix: Ipv4PrefixV1,
) -> Result<(), ControlStoreError> {
    let rows = sqlx::query(
        "SELECT resource_kind, CAST(document_json AS CHAR) AS document_json FROM sdwan_control_resources WHERE tenant_id = ? AND segment_id = ? AND resource_kind IN ('ATTACHMENT','PREFIX') AND state <> 'DELETED' FOR SHARE",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let resource = decode_resource(row.try_get("document_json")?)?;
        match resource.resource {
            ResourceSpecV1::Attachment(attachment)
                if !valid_overlay_host(overlay_prefix, attachment.overlay_router_ipv4) =>
            {
                return Err(ControlStoreError::ReferenceConflict);
            }
            ResourceSpecV1::Prefix(prefix) if overlay_prefix.overlaps(prefix.prefix) => {
                return Err(ControlStoreError::ReferenceConflict);
            }
            _ => {}
        }
    }
    Ok(())
}

fn valid_overlay_host(prefix: Ipv4PrefixV1, address: Ipv4Addr) -> bool {
    if prefix.prefix_len == 0 || prefix.prefix_len > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix.prefix_len);
    let network = u32::from(prefix.network);
    let address = u32::from(address);
    if address & mask != network {
        return false;
    }
    if prefix.prefix_len <= 30 {
        let broadcast = network | !mask;
        address != network && address != broadcast
    } else {
        true
    }
}

async fn validate_path_candidate_references(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    candidate: &PathCandidateV1,
) -> Result<(), ControlStoreError> {
    let peer = load_control_resource(
        transaction,
        tenant_id,
        ResourceKind::Peer,
        candidate.peer_id,
    )
    .await?;
    let source = load_control_resource(
        transaction,
        tenant_id,
        ResourceKind::Attachment,
        candidate.source_attachment_id,
    )
    .await?;
    let destination = load_control_resource(
        transaction,
        tenant_id,
        ResourceKind::Attachment,
        candidate.destination_attachment_id,
    )
    .await?;
    let (
        ResourceSpecV1::Peer(peer),
        ResourceSpecV1::Attachment(source),
        ResourceSpecV1::Attachment(destination),
    ) = (peer.resource, source.resource, destination.resource)
    else {
        return Err(ControlStoreError::ReferenceConflict);
    };
    let sites_match = (source.site_id == peer.site_a_id && destination.site_id == peer.site_b_id)
        || (source.site_id == peer.site_b_id && destination.site_id == peer.site_a_id);
    let policy_matches = match peer.path_policy {
        PeerPathPolicyV1::DirectOnly => candidate.kind == PathCandidateKindV1::Direct,
        PeerPathPolicyV1::DirectPreferred => true,
        PeerPathPolicyV1::RelayRequired => candidate.kind == PathCandidateKindV1::Relay,
    };
    let direct_transport_is_endpoint = candidate.kind != PathCandidateKindV1::Direct
        || candidate.transport_node_id == source.node_id
        || candidate.transport_node_id == destination.node_id;
    if peer.segment_id != candidate.segment_id
        || source.segment_id != candidate.segment_id
        || destination.segment_id != candidate.segment_id
        || !sites_match
        || !policy_matches
        || !direct_transport_is_endpoint
    {
        return Err(ControlStoreError::ReferenceConflict);
    }
    Ok(())
}

async fn replace_resource_references(
    transaction: &mut Transaction<'_, MySql>,
    resource: &ControlResourceV1,
) -> Result<(), ControlStoreError> {
    sqlx::query(
        "DELETE FROM sdwan_control_resource_references WHERE tenant_id = ? AND source_kind = ? AND source_id = ?",
    )
    .bind(resource.metadata.tenant_id)
    .bind(resource.resource.kind().database_value())
    .bind(resource.metadata.id)
    .execute(&mut **transaction)
    .await?;
    if resource.metadata.state == ResourceState::Deleted {
        return Ok(());
    }
    for (target_kind, target_id) in resource_references(resource) {
        sqlx::query(
            "INSERT INTO sdwan_control_resource_references (tenant_id, source_kind, source_id, target_kind, target_id) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(resource.metadata.tenant_id)
        .bind(resource.resource.kind().database_value())
        .bind(resource.metadata.id)
        .bind(target_kind.database_value())
        .bind(target_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn dependent_segments(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    kind: ResourceKind,
    id: Uuid,
) -> Result<HashSet<Uuid>, ControlStoreError> {
    let rows = sqlx::query(
        "WITH RECURSIVE dependents (resource_kind, resource_id) AS (SELECT CAST(? AS CHAR(32)), CAST(? AS BINARY(16)) UNION DISTINCT SELECT CAST(refs.source_kind AS CHAR(32)), refs.source_id FROM sdwan_control_resource_references refs JOIN dependents current ON refs.tenant_id = ? AND CAST(refs.target_kind AS CHAR(32)) = current.resource_kind AND refs.target_id = current.resource_id) SELECT DISTINCT resources.segment_id FROM dependents JOIN sdwan_control_resources resources ON resources.tenant_id = ? AND CAST(resources.resource_kind AS CHAR(32)) = dependents.resource_kind AND resources.id = dependents.resource_id WHERE resources.state <> 'DELETED' AND resources.segment_id IS NOT NULL",
    )
    .bind(kind.database_value())
    .bind(id)
    .bind(tenant_id)
    .bind(tenant_id)
    .fetch_all(&mut **transaction)
    .await?;
    rows.into_iter()
        .map(|row| row.try_get("segment_id").map_err(ControlStoreError::from))
        .collect()
}

async fn replay_idempotency(
    transaction: &mut Transaction<'_, MySql>,
    mutation: &ResourceMutation,
    now: DateTime<Utc>,
) -> Result<Option<ControlResourceV1>, ControlStoreError> {
    let row = sqlx::query(
        "SELECT request_method, request_path, request_hash, resource_kind, resource_id, resource_revision, CAST(response_document_json AS CHAR) AS response_document_json, replay_until FROM management_idempotency_records WHERE tenant_id = ? AND actor_id = ? AND idempotency_key = ? FOR UPDATE",
    )
    .bind(mutation.resource.metadata.tenant_id)
    .bind(&mutation.context.actor_id)
    .bind(&mutation.context.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let hash: Vec<u8> = row.try_get("request_hash")?;
    let method: String = row.try_get("request_method")?;
    let path: String = row.try_get("request_path")?;
    let kind: String = row.try_get("resource_kind")?;
    let resource_id: Uuid = row.try_get("resource_id")?;
    let revision: u64 = row.try_get("resource_revision")?;
    let response_document: String = row.try_get("response_document_json")?;
    let replay_until: DateTime<Utc> = row.try_get("replay_until")?;
    if hash.as_slice() != mutation.context.request_hash
        || method != mutation.context.request_method
        || path != mutation.context.request_path
        || kind != mutation.resource.resource.kind().database_value()
        || resource_id != mutation.resource.metadata.id
        || revision != mutation.resource.metadata.revision
    {
        return Err(ControlStoreError::IdempotencyConflict);
    }
    if replay_until <= now {
        return Err(ControlStoreError::IdempotencyReplayExpired);
    }
    Ok(Some(decode_resource(response_document)?))
}

async fn insert_idempotency(
    transaction: &mut Transaction<'_, MySql>,
    mutation: &ResourceMutation,
) -> Result<(), ControlStoreError> {
    let resource = &mutation.resource;
    let response_document = serde_json::to_string(resource)
        .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
    sqlx::query(
        "INSERT INTO management_idempotency_records (tenant_id, actor_id, idempotency_key, request_method, request_path, request_hash, resource_kind, resource_id, resource_revision, response_document_json, response_status, replay_until) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), 200, ?)",
    )
    .bind(resource.metadata.tenant_id)
    .bind(&mutation.context.actor_id)
    .bind(&mutation.context.idempotency_key)
    .bind(&mutation.context.request_method)
    .bind(&mutation.context.request_path)
    .bind(mutation.context.request_hash.as_slice())
    .bind(resource.resource.kind().database_value())
    .bind(resource.metadata.id)
    .bind(resource.metadata.revision)
    .bind(response_document)
    .bind(mutation.context.idempotency_replay_until)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn enqueue_generation(
    transaction: &mut Transaction<'_, MySql>,
    tenant_id: Uuid,
    segment_id: Uuid,
    idempotency_hash: [u8; 32],
) -> Result<(), ControlStoreError> {
    sqlx::query(
        "INSERT IGNORE INTO segment_generation_heads (tenant_id, segment_id, desired_revision) VALUES (?, ?, 0)",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .execute(&mut **transaction)
    .await?;
    let current: u64 = sqlx::query_scalar(
        "SELECT desired_revision FROM segment_generation_heads WHERE tenant_id = ? AND segment_id = ? FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_one(&mut **transaction)
    .await?;
    let desired = current
        .checked_add(1)
        .ok_or(ControlStoreError::InvalidTransition)?;
    sqlx::query(
        "UPDATE segment_generation_heads SET desired_revision = ? WHERE tenant_id = ? AND segment_id = ? AND desired_revision = ?",
    )
    .bind(desired)
    .bind(tenant_id)
    .bind(segment_id)
    .bind(current)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO segment_generation_jobs (id, tenant_id, segment_id, desired_revision, idempotency_hash) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(segment_id)
    .bind(desired)
    .bind(idempotency_hash.as_slice())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationJobState {
    Pending,
    Leased,
    Retry,
    Published,
    PermanentFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationJob {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub desired_revision: u64,
    pub attempt_count: u32,
    pub lease_owner: String,
    pub lease_until: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobFailure {
    Retry {
        code: String,
        retry_at: DateTime<Utc>,
    },
    Permanent {
        code: String,
    },
}

impl JobFailure {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), ControlStoreError> {
        let (code, retry_at) = match self {
            Self::Retry { code, retry_at } => (code, Some(*retry_at)),
            Self::Permanent { code } => (code, None),
        };
        if code.is_empty()
            || code.len() > MAX_ERROR_CODE_LEN
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || retry_at.is_some_and(|at| at <= now)
        {
            return Err(ControlStoreError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct GenerationJobRepository {
    pool: DbPool,
}

impl GenerationJobRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn claim_next(
        &self,
        owner: &str,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<Option<GenerationJob>, ControlStoreError> {
        validate_lease(owner, ttl)?;
        let lease_until =
            now + chrono::Duration::from_std(ttl).map_err(|_| ControlStoreError::InvalidRequest)?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT candidate.id, candidate.tenant_id, candidate.segment_id, candidate.desired_revision, candidate.attempt_count FROM segment_generation_jobs candidate WHERE ((candidate.state IN ('PENDING','RETRY') AND candidate.next_attempt_at <= ?) OR (candidate.state = 'LEASED' AND candidate.lease_until <= ?)) AND NOT EXISTS (SELECT 1 FROM segment_generation_jobs earlier WHERE earlier.tenant_id = candidate.tenant_id AND earlier.segment_id = candidate.segment_id AND earlier.desired_revision < candidate.desired_revision AND earlier.state NOT IN ('PUBLISHED','PERMANENT_FAILURE')) ORDER BY candidate.next_attempt_at, candidate.created_at, candidate.id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .bind(now)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let id: Uuid = row.try_get("id")?;
        let attempt_count: u32 = row.try_get("attempt_count")?;
        let next_attempt = attempt_count
            .checked_add(1)
            .ok_or(ControlStoreError::InvalidTransition)?;
        let changed = sqlx::query(
            "UPDATE segment_generation_jobs SET state = 'LEASED', attempt_count = ?, lease_owner = ?, lease_until = ?, last_error_code = NULL WHERE id = ?",
        )
        .bind(next_attempt)
        .bind(owner)
        .bind(lease_until)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if changed.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(ControlStoreError::LeaseLost);
        }
        let job = GenerationJob {
            id,
            tenant_id: row.try_get("tenant_id")?,
            segment_id: row.try_get("segment_id")?,
            desired_revision: row.try_get("desired_revision")?,
            attempt_count: next_attempt,
            lease_owner: owner.to_owned(),
            lease_until,
        };
        transaction.commit().await?;
        Ok(Some(job))
    }

    /// Requeue jobs that were permanently stopped by the pre-materialization
    /// publisher. The route publisher now creates the normalized contract
    /// transactionally, so this exact historical error is recoverable after an
    /// upgrade. Other permanent failures remain terminal by design.
    pub async fn recover_route_input_head_failures(&self) -> Result<u64, ControlStoreError> {
        let result = sqlx::query(
            "UPDATE segment_generation_jobs SET state = 'RETRY', lease_owner = NULL, lease_until = NULL, next_attempt_at = CURRENT_TIMESTAMP(6), last_error_code = 'ROUTE_RETRY_TOPOLOGY_MATERIALIZATION' WHERE state = 'PERMANENT_FAILURE' AND last_error_code IN ('ROUTE_INPUT_LOAD_SEGMENT_PUBLICATION_HEAD', 'ROUTE_DB_PRINCIPAL_MISMATCH')",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn renew(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        ttl: StdDuration,
    ) -> Result<DateTime<Utc>, ControlStoreError> {
        validate_lease(&job.lease_owner, ttl)?;
        let lease_until =
            now + chrono::Duration::from_std(ttl).map_err(|_| ControlStoreError::InvalidRequest)?;
        let result = sqlx::query(
            "UPDATE segment_generation_jobs SET lease_until = ? WHERE id = ? AND state = 'LEASED' AND lease_owner = ? AND lease_until > ?",
        )
        .bind(lease_until)
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(now)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ControlStoreError::LeaseLost);
        }
        Ok(lease_until)
    }

    pub async fn publish(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        generation: u64,
        content_hash: [u8; 32],
    ) -> Result<(), ControlStoreError> {
        if generation == 0 || content_hash == [0; 32] {
            return Err(ControlStoreError::InvalidRequest);
        }
        let result = sqlx::query(
            "UPDATE segment_generation_jobs SET state = 'PUBLISHED', lease_owner = NULL, lease_until = NULL, published_generation = ?, published_content_hash = ?, last_error_code = NULL WHERE id = ? AND state = 'LEASED' AND lease_owner = ? AND lease_until > ?",
        )
        .bind(generation)
        .bind(content_hash.as_slice())
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(now)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ControlStoreError::LeaseLost);
        }
        Ok(())
    }

    pub async fn fail(
        &self,
        job: &GenerationJob,
        now: DateTime<Utc>,
        failure: &JobFailure,
    ) -> Result<(), ControlStoreError> {
        failure.validate(now)?;
        let (state, code, retry_at) = match failure {
            JobFailure::Retry { code, retry_at } => ("RETRY", code, *retry_at),
            JobFailure::Permanent { code } => ("PERMANENT_FAILURE", code, now),
        };
        let result = sqlx::query(
            "UPDATE segment_generation_jobs SET state = ?, lease_owner = NULL, lease_until = NULL, next_attempt_at = ?, last_error_code = ? WHERE id = ? AND state = 'LEASED' AND lease_owner = ? AND lease_until > ?",
        )
        .bind(state)
        .bind(retry_at)
        .bind(code)
        .bind(job.id)
        .bind(&job.lease_owner)
        .bind(now)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ControlStoreError::LeaseLost);
        }
        Ok(())
    }
}

fn validate_lease(owner: &str, ttl: StdDuration) -> Result<(), ControlStoreError> {
    if owner.is_empty() || owner.len() > MAX_ACTOR_LEN || ttl.is_zero() || ttl > MAX_LEASE_TTL {
        Err(ControlStoreError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn decode_resource(value: String) -> Result<ControlResourceV1, ControlStoreError> {
    let resource: ControlResourceV1 = serde_json::from_str(&value)
        .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
    resource
        .validate()
        .map_err(|error| ControlStoreError::InvalidResource(error.to_string()))?;
    Ok(resource)
}

fn validate_scope(tenant_id: Uuid, id: Uuid) -> Result<(), ControlStoreError> {
    if tenant_id.is_nil() || id.is_nil() {
        Err(ControlStoreError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn resource_state(state: ResourceState) -> &'static str {
    match state {
        ResourceState::Active => "ACTIVE",
        ResourceState::Disabled => "DISABLED",
        ResourceState::Deleted => "DELETED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_context_rejects_zero_hash_and_expired_replay_window() {
        let now = Utc::now();
        let mut context = MutationContext {
            actor_id: "user-1".into(),
            idempotency_key: "request-1".into(),
            request_method: "POST".into(),
            request_path: "/v1/tenants/t/sites".into(),
            request_hash: [0; 32],
            idempotency_replay_until: now + chrono::Duration::hours(1),
        };
        assert!(matches!(
            context.validate(now),
            Err(ControlStoreError::InvalidRequest)
        ));
        context.request_hash = [1; 32];
        context.idempotency_replay_until = now;
        assert!(matches!(
            context.validate(now),
            Err(ControlStoreError::InvalidRequest)
        ));
    }

    #[test]
    fn retry_and_permanent_failures_are_explicit() {
        let now = Utc::now();
        assert!(JobFailure::Retry {
            code: "DATABASE_UNAVAILABLE".into(),
            retry_at: now + chrono::Duration::seconds(5),
        }
        .validate(now)
        .is_ok());
        assert!(JobFailure::Permanent {
            code: "PREFIX_OVERLAP".into()
        }
        .validate(now)
        .is_ok());
        assert!(JobFailure::Permanent {
            code: "secret text".into()
        }
        .validate(now)
        .is_err());
    }

    #[test]
    fn lease_is_bounded() {
        assert!(validate_lease("worker-a", StdDuration::from_secs(30)).is_ok());
        assert!(validate_lease("worker-a", StdDuration::from_secs(301)).is_err());
    }
}
