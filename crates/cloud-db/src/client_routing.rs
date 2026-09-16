use std::{collections::HashSet, net::SocketAddr};

use sqlx::Row;
use uuid::Uuid;

use crate::DbPool;

pub const MAX_CLIENT_NODE_BACKUPS: usize = 2;
const MAX_CLIENT_NODE_CANDIDATES: usize = 4096;
const MAX_REGION_LEN: usize = 80;
const MAX_SERVER_NAME_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNodeCandidate {
    pub node_id: Uuid,
    pub node_key_id: Uuid,
    pub endpoint_id: Uuid,
    pub endpoint: SocketAddr,
    pub region: String,
    pub server_name: String,
    pub server_cert_sha256: [u8; 32],
}

impl ClientNodeCandidate {
    pub fn validate(&self) -> Result<(), ClientRoutingError> {
        if [self.node_id, self.node_key_id, self.endpoint_id]
            .into_iter()
            .any(|id| id.is_nil())
            || self.region.is_empty()
            || self.region.len() > MAX_REGION_LEN
            || self.server_name.is_empty()
            || self.server_name.len() > MAX_SERVER_NAME_LEN
            || self.server_cert_sha256 == [0; 32]
        {
            return Err(ClientRoutingError::InvalidCandidate);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNodeSelection {
    pub primary: ClientNodeCandidate,
    pub backups: Vec<ClientNodeCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientRoutingError {
    #[error("invalid terminal client routing scope")]
    InvalidScope,
    #[error("terminal client node candidate is invalid")]
    InvalidCandidate,
    #[error("no active terminal client node is available")]
    NoActiveNode,
    #[error("terminal client node backup count is unsupported")]
    InvalidBackupCount,
    #[error("terminal client routing database record is invalid")]
    InvalidRecord,
}

#[derive(Clone)]
pub struct ClientNodeRepository {
    pool: DbPool,
}

impl ClientNodeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Returns only nodes that Cloud can currently use as a terminal-client
    /// transport. Data-plane traffic does not pass through this repository.
    pub async fn active_candidates(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<ClientNodeCandidate>, ClientRoutingError> {
        if tenant_id.is_nil() {
            return Err(ClientRoutingError::InvalidScope);
        }
        let rows = sqlx::query(
            "SELECT DISTINCT node.id AS node_id, node.device_key_id AS node_key_id, endpoint.id AS endpoint_id, endpoint.endpoint, endpoint.region, endpoint.server_name, endpoint.server_cert_sha256 FROM nodes node JOIN tenants tenant ON tenant.id = node.tenant_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' JOIN node_pools pool ON pool.id = node.node_pool_id AND pool.tenant_id = node.tenant_id AND pool.status = 'ACTIVE' JOIN entitlements entitlement ON entitlement.tenant_id = node.tenant_id AND entitlement.node_pool_id = pool.id AND entitlement.service_permission = 'private.tun.connect' AND entitlement.status = 'ACTIVE' JOIN subscriptions subscription ON subscription.id = entitlement.subscription_id AND subscription.tenant_id = entitlement.tenant_id AND subscription.status IN ('TRIAL','ACTIVE') JOIN devices device ON device.id = node.device_id AND device.tenant_id = node.tenant_id AND device.status = 'ACTIVE' JOIN device_keys device_key ON device_key.id = node.device_key_id AND device_key.tenant_id = node.tenant_id AND device_key.device_id = device.id AND device_key.status = 'ACTIVE' JOIN node_endpoints endpoint ON endpoint.node_id = node.id AND endpoint.status = 'ACTIVE' AND endpoint.transport = 'CANDY_QUIC_UDP' WHERE node.tenant_id = ? AND node.status = 'ACTIVE' ORDER BY endpoint.region, node.id, endpoint.id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ClientRoutingError::InvalidRecord)?;
        if rows.len() > MAX_CLIENT_NODE_CANDIDATES {
            return Err(ClientRoutingError::InvalidRecord);
        }
        rows.into_iter()
            .map(|row| {
                let endpoint: String = row
                    .try_get("endpoint")
                    .map_err(|_| ClientRoutingError::InvalidRecord)?;
                let server_name: Option<String> = row
                    .try_get("server_name")
                    .map_err(|_| ClientRoutingError::InvalidRecord)?;
                let server_cert_sha256: Option<Vec<u8>> = row
                    .try_get("server_cert_sha256")
                    .map_err(|_| ClientRoutingError::InvalidRecord)?;
                let candidate = ClientNodeCandidate {
                    node_id: row
                        .try_get("node_id")
                        .map_err(|_| ClientRoutingError::InvalidRecord)?,
                    node_key_id: row
                        .try_get("node_key_id")
                        .map_err(|_| ClientRoutingError::InvalidRecord)?,
                    endpoint_id: row
                        .try_get("endpoint_id")
                        .map_err(|_| ClientRoutingError::InvalidRecord)?,
                    endpoint: endpoint
                        .parse()
                        .map_err(|_| ClientRoutingError::InvalidRecord)?,
                    region: row
                        .try_get("region")
                        .map_err(|_| ClientRoutingError::InvalidRecord)?,
                    server_name: server_name.ok_or(ClientRoutingError::InvalidRecord)?,
                    server_cert_sha256: fixed_hash(
                        &server_cert_sha256.ok_or(ClientRoutingError::InvalidRecord)?,
                    )?,
                };
                candidate.validate()?;
                Ok(candidate)
            })
            .collect()
    }
}

pub fn select_nodes(
    mut candidates: Vec<ClientNodeCandidate>,
    preferred_region: Option<&str>,
    backup_count: usize,
) -> Result<ClientNodeSelection, ClientRoutingError> {
    if backup_count > MAX_CLIENT_NODE_BACKUPS {
        return Err(ClientRoutingError::InvalidBackupCount);
    }
    if preferred_region.is_some_and(|region| region.is_empty() || region.len() > MAX_REGION_LEN) {
        return Err(ClientRoutingError::InvalidCandidate);
    }
    for candidate in &candidates {
        candidate.validate()?;
    }
    candidates.sort_unstable_by(|left, right| {
        let left_preferred = preferred_region.is_some_and(|region| left.region == region);
        let right_preferred = preferred_region.is_some_and(|region| right.region == region);
        right_preferred
            .cmp(&left_preferred)
            .then_with(|| left.region.cmp(&right.region))
            .then_with(|| left.node_id.cmp(&right.node_id))
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    let mut selected_nodes = HashSet::new();
    candidates.retain(|candidate| selected_nodes.insert(candidate.node_id));
    let required = backup_count + 1;
    if candidates.len() < required {
        return Err(ClientRoutingError::NoActiveNode);
    }
    let mut selected = candidates.into_iter().take(required);
    let primary = selected.next().ok_or(ClientRoutingError::NoActiveNode)?;
    Ok(ClientNodeSelection {
        primary,
        backups: selected.collect(),
    })
}

fn fixed_hash(value: &[u8]) -> Result<[u8; 32], ClientRoutingError> {
    value
        .try_into()
        .map_err(|_| ClientRoutingError::InvalidRecord)
}
