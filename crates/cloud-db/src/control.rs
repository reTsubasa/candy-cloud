use std::{collections::HashSet, net::Ipv4Addr, time::Duration as StdDuration};

use chrono::{DateTime, Utc};
use cloud_control::{
    ControlResourceV1, Ipv4PrefixV1, PathCandidateKindV1, PathCandidateV1, PeerPathPolicyV1,
    PolicyActionV1, ResourceKind, ResourceSpecV1, ResourceState,
};
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
}

impl ControlRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn readiness_check(&self) -> Result<(), ControlStoreError> {
        let migration_ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = 8 AND success = TRUE)",
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
            "WITH RECURSIVE graph (resource_kind, resource_id) AS (SELECT resource_kind, id FROM sdwan_control_resources WHERE tenant_id = ? AND state = 'ACTIVE' AND ((resource_kind = 'SEGMENT' AND id = ?) OR segment_id = ?) UNION DISTINCT SELECT refs.target_kind, refs.target_id FROM sdwan_control_resource_references refs JOIN graph current ON refs.tenant_id = ? AND refs.source_kind = current.resource_kind AND refs.source_id = current.resource_id) SELECT DISTINCT CAST(resources.document_json AS CHAR) AS document_json FROM graph JOIN sdwan_control_resources resources ON resources.tenant_id = ? AND resources.resource_kind = graph.resource_kind AND resources.id = graph.resource_id WHERE resources.state = 'ACTIVE' ORDER BY resources.resource_kind, resources.id",
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
        })
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
    if peer.segment_id != candidate.segment_id
        || source.segment_id != candidate.segment_id
        || destination.segment_id != candidate.segment_id
        || !sites_match
        || !policy_matches
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
