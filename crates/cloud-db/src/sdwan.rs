use std::collections::HashSet;

use sqlx::{MySql, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::DbPool;

const MAX_SIGNED_ENVELOPE_LEN: usize = 1024 * 1024;
const MAX_ACTOR_ID_LEN: usize = 120;
const MAX_PROJECTIONS: usize = 4096;
const MAX_EXPANSION_OBJECTS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    network: [u8; 4],
    prefix_len: u8,
}

impl Ipv4Prefix {
    pub fn new(network: [u8; 4], prefix_len: u8) -> Result<Self, SdwanError> {
        if prefix_len == 0 || prefix_len > 32 {
            return Err(SdwanError::InvalidPrefix);
        }
        let value = u32::from_be_bytes(network);
        let mask = u32::MAX << (32 - prefix_len);
        if value & !mask != 0 {
            return Err(SdwanError::InvalidPrefix);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn network(self) -> [u8; 4] {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    fn overlaps(self, other: Self) -> bool {
        let bits = self.prefix_len.min(other.prefix_len);
        let mask = u32::MAX << (32 - bits);
        u32::from_be_bytes(self.network) & mask == u32::from_be_bytes(other.network) & mask
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentPrincipalWrite {
    Device {
        device_id: Uuid,
        device_key_id: Uuid,
    },
    Node {
        node_id: Uuid,
        node_key_id: Uuid,
        node_pool_id: Uuid,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentState {
    Active,
    Standby,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePrefixWrite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub site_id: Uuid,
    pub prefix: Ipv4Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentAttachmentWrite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub site_id: Option<Uuid>,
    pub principal: AttachmentPrincipalWrite,
    pub overlay_router_ipv4: [u8; 4],
    pub local_prefixes: Vec<Ipv4Prefix>,
    pub state: AttachmentState,
    pub epoch_floor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdwanTopologyWrite {
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub site_prefixes: Vec<SitePrefixWrite>,
    pub attachments: Vec<SegmentAttachmentWrite>,
}

impl SdwanTopologyWrite {
    pub fn validate(&self) -> Result<(), SdwanError> {
        if self.tenant_id.is_nil() || self.segment_id.is_nil() {
            return Err(SdwanError::InvalidScope);
        }
        let mut prefix_ids = HashSet::new();
        for (index, prefix) in self.site_prefixes.iter().enumerate() {
            if prefix.id.is_nil() || prefix.site_id.is_nil() {
                return Err(SdwanError::InvalidScope);
            }
            if prefix.tenant_id != self.tenant_id {
                return Err(SdwanError::ScopeMismatch);
            }
            if !prefix_ids.insert(prefix.id) {
                return Err(SdwanError::InvalidScope);
            }
            if self.site_prefixes[index + 1..]
                .iter()
                .any(|other| prefix.prefix.overlaps(other.prefix))
            {
                return Err(SdwanError::OverlappingPrefix);
            }
        }

        let mut attachment_ids = HashSet::new();
        let mut router_addresses = HashSet::new();
        for attachment in &self.attachments {
            if attachment.id.is_nil()
                || attachment.tenant_id != self.tenant_id
                || attachment.segment_id != self.segment_id
                || attachment.epoch_floor == 0
            {
                return Err(SdwanError::InvalidScope);
            }
            if !attachment_ids.insert(attachment.id) {
                return Err(SdwanError::InvalidScope);
            }
            if !router_addresses.insert(attachment.overlay_router_ipv4) {
                return Err(SdwanError::DuplicateRouterAddress);
            }
            if has_overlap(&attachment.local_prefixes) {
                return Err(SdwanError::OverlappingPrefix);
            }
            match &attachment.principal {
                AttachmentPrincipalWrite::Device {
                    device_id,
                    device_key_id,
                } => {
                    if device_id.is_nil() || device_key_id.is_nil() {
                        return Err(SdwanError::InvalidScope);
                    }
                    let site_id = attachment.site_id.ok_or(SdwanError::PrincipalMismatch)?;
                    if site_id.is_nil() || attachment.local_prefixes.is_empty() {
                        return Err(SdwanError::PrincipalMismatch);
                    }
                    for local in &attachment.local_prefixes {
                        if !self.site_prefixes.iter().any(|site_prefix| {
                            site_prefix.site_id == site_id && site_prefix.prefix == *local
                        }) {
                            return Err(SdwanError::PrincipalMismatch);
                        }
                    }
                }
                AttachmentPrincipalWrite::Node {
                    node_id,
                    node_key_id,
                    node_pool_id,
                } => {
                    if node_id.is_nil() || node_key_id.is_nil() || node_pool_id.is_nil() {
                        return Err(SdwanError::InvalidScope);
                    }
                    if attachment.site_id.is_some() || !attachment.local_prefixes.is_empty() {
                        return Err(SdwanError::PrincipalMismatch);
                    }
                }
            }
        }
        Ok(())
    }
}

fn has_overlap(prefixes: &[Ipv4Prefix]) -> bool {
    prefixes.iter().enumerate().any(|(index, prefix)| {
        prefixes[index + 1..]
            .iter()
            .any(|other| prefix.overlaps(*other))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedObjectWrite {
    pub content_hash: [u8; 32],
    pub signed_envelope: Vec<u8>,
}

impl SignedObjectWrite {
    fn validate(&self) -> Result<(), SdwanError> {
        if self.content_hash == [0; 32]
            || self.signed_envelope.is_empty()
            || self.signed_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
        {
            return Err(SdwanError::UnsignedObject);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteProjectionPublicationWrite {
    pub publication_id: Uuid,
    pub projection_id: Uuid,
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub site_id: Uuid,
    pub attachment_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub projection_generation: u64,
    pub previous_hash: [u8; 32],
    pub object: SignedObjectWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExpansionObjectKind {
    SharedHubAdmission,
    MeshMembership,
    DynamicRouteSnapshot,
    FabricAssignment,
}

impl ExpansionObjectKind {
    fn database_value(self) -> &'static str {
        match self {
            Self::SharedHubAdmission => "SHARED_HUB_ADMISSION",
            Self::MeshMembership => "MESH_MEMBERSHIP",
            Self::DynamicRouteSnapshot => "DYNAMIC_ROUTE_SNAPSHOT",
            Self::FabricAssignment => "FABRIC_ASSIGNMENT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpansionObjectPublicationWrite {
    pub publication_id: Uuid,
    pub kind: ExpansionObjectKind,
    pub policy_id: Uuid,
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub generation: u64,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub site_id: Option<Uuid>,
    pub attachment_id: Option<Uuid>,
    pub object: SignedObjectWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentPublicationWrite {
    pub publication_id: Uuid,
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub expected_previous_generation: u64,
    pub expected_previous_hash: [u8; 32],
    pub generation: u64,
    pub snapshot: SignedObjectWrite,
    pub projections: Vec<SiteProjectionPublicationWrite>,
    pub expansions: Vec<ExpansionObjectPublicationWrite>,
    pub audit_event_id: Uuid,
    pub actor_id: String,
}

impl SegmentPublicationWrite {
    pub fn validate(&self) -> Result<(), SdwanError> {
        if self.publication_id.is_nil()
            || self.tenant_id.is_nil()
            || self.segment_id.is_nil()
            || self.audit_event_id.is_nil()
            || self.actor_id.is_empty()
            || self.actor_id.len() > MAX_ACTOR_ID_LEN
        {
            return Err(SdwanError::InvalidScope);
        }
        if self.generation == 0
            || self.generation
                != self
                    .expected_previous_generation
                    .checked_add(1)
                    .ok_or(SdwanError::GenerationGap)?
            || (self.expected_previous_generation == 0 && self.expected_previous_hash != [0; 32])
            || (self.expected_previous_generation != 0 && self.expected_previous_hash == [0; 32])
        {
            return Err(SdwanError::GenerationGap);
        }
        self.snapshot.validate()?;
        if self.projections.is_empty() || self.projections.len() > MAX_PROJECTIONS {
            return Err(SdwanError::MissingProjection);
        }
        let mut row_ids = HashSet::new();
        let mut projection_versions = HashSet::new();
        let mut attachments = HashSet::new();
        let mut devices = HashSet::new();
        for projection in &self.projections {
            if projection.publication_id.is_nil()
                || projection.projection_id.is_nil()
                || projection.site_id.is_nil()
                || projection.attachment_id.is_nil()
                || projection.device_id.is_nil()
                || projection.device_key_id.is_nil()
                || projection.projection_generation == 0
            {
                return Err(SdwanError::InvalidScope);
            }
            if projection.tenant_id != self.tenant_id
                || projection.segment_id != self.segment_id
                || projection.segment_generation != self.generation
                || projection.segment_content_hash != self.snapshot.content_hash
            {
                return Err(SdwanError::ScopeMismatch);
            }
            if (projection.projection_generation == 1 && projection.previous_hash != [0; 32])
                || (projection.projection_generation != 1 && projection.previous_hash == [0; 32])
            {
                return Err(SdwanError::GenerationGap);
            }
            projection.object.validate()?;
            if !row_ids.insert(projection.publication_id)
                || !projection_versions
                    .insert((projection.projection_id, projection.projection_generation))
                || !attachments.insert(projection.attachment_id)
                || !devices.insert((projection.device_id, projection.device_key_id))
            {
                return Err(SdwanError::DuplicateProjection);
            }
        }
        if self.expansions.len() > MAX_EXPANSION_OBJECTS {
            return Err(SdwanError::InvalidScope);
        }
        let mut expansion_ids = HashSet::new();
        let mut expansion_versions = HashSet::new();
        for expansion in &self.expansions {
            if expansion.publication_id.is_nil()
                || expansion.policy_id.is_nil()
                || expansion.generation == 0
                || expansion.tenant_id != self.tenant_id
                || expansion.segment_id != self.segment_id
                || expansion.segment_generation != self.generation
                || expansion.segment_content_hash != self.snapshot.content_hash
            {
                return Err(SdwanError::ScopeMismatch);
            }
            let scoped = match expansion.kind {
                ExpansionObjectKind::MeshMembership => expansion
                    .site_id
                    .zip(expansion.attachment_id)
                    .is_some_and(|(site, attachment)| !site.is_nil() && !attachment.is_nil()),
                ExpansionObjectKind::SharedHubAdmission
                | ExpansionObjectKind::DynamicRouteSnapshot
                | ExpansionObjectKind::FabricAssignment => {
                    expansion.site_id.is_none() && expansion.attachment_id.is_none()
                }
            };
            if !scoped
                || !expansion_ids.insert(expansion.publication_id)
                || !expansion_versions.insert((
                    expansion.kind,
                    expansion.policy_id,
                    expansion.generation,
                ))
            {
                return Err(SdwanError::InvalidScope);
            }
            expansion.object.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationOutcome {
    Published,
    Replayed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SdwanError {
    #[error("invalid SD-WAN scope")]
    InvalidScope,
    #[error("tenant or segment scope mismatch")]
    ScopeMismatch,
    #[error("invalid IPv4 prefix")]
    InvalidPrefix,
    #[error("overlapping IPv4 prefixes")]
    OverlappingPrefix,
    #[error("duplicate overlay router address")]
    DuplicateRouterAddress,
    #[error("attachment principal does not match its ownership")]
    PrincipalMismatch,
    #[error("signed object is empty, zero-hash, or oversized")]
    UnsignedObject,
    #[error("publication generation is not adjacent")]
    GenerationGap,
    #[error("publication does not contain a complete projection set")]
    MissingProjection,
    #[error("publication contains duplicate projection ownership")]
    DuplicateProjection,
    #[error("publication id was reused with different content")]
    DivergentReplay,
    #[error("segment was not found in the requested tenant")]
    SegmentNotFound,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for SdwanError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

#[derive(Clone)]
pub struct SdwanRepository {
    pool: DbPool,
}

impl SdwanRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn publish(
        &self,
        write: &SegmentPublicationWrite,
    ) -> Result<PublicationOutcome, SdwanError> {
        write.validate()?;
        let mut transaction = self.pool.begin().await?;

        if publication_exists(&mut transaction, write.publication_id).await? {
            let exact = publication_matches(&mut transaction, write).await?;
            transaction.commit().await?;
            return if exact {
                Ok(PublicationOutcome::Replayed)
            } else {
                Err(SdwanError::DivergentReplay)
            };
        }

        let segment = sqlx::query(
            "SELECT current_generation, current_content_hash FROM segments WHERE tenant_id = ? AND id = ? AND state = 'ACTIVE' FOR UPDATE",
        )
        .bind(write.tenant_id)
        .bind(write.segment_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(segment) = segment else {
            transaction.rollback().await?;
            return Err(SdwanError::SegmentNotFound);
        };
        let current_generation: u64 = segment.try_get("current_generation")?;
        let current_hash: Vec<u8> = segment.try_get("current_content_hash")?;
        if current_generation != write.expected_previous_generation
            || current_hash.as_slice() != write.expected_previous_hash
        {
            transaction.rollback().await?;
            return Err(SdwanError::GenerationGap);
        }

        validate_projection_ownership(&mut transaction, write).await?;

        sqlx::query(
            "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'WORKER', ?, 'SDWAN_SEGMENT_ROUTES_PUBLISHED', 'SEGMENT', ?, JSON_OBJECT('generation', ?, 'projection_count', ?, 'expansion_count', ?))",
        )
        .bind(write.audit_event_id)
        .bind(write.tenant_id)
        .bind(&write.actor_id)
        .bind(write.segment_id.to_string())
        .bind(write.generation)
        .bind(write.projections.len() as u64)
        .bind(write.expansions.len() as u64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO segment_route_publications (id, tenant_id, segment_id, expected_previous_generation, expected_previous_hash, generation, content_hash, signed_envelope, audit_event_id, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(write.publication_id)
        .bind(write.tenant_id)
        .bind(write.segment_id)
        .bind(write.expected_previous_generation)
        .bind(write.expected_previous_hash.as_slice())
        .bind(write.generation)
        .bind(write.snapshot.content_hash.as_slice())
        .bind(&write.snapshot.signed_envelope)
        .bind(write.audit_event_id)
        .bind(&write.actor_id)
        .execute(&mut *transaction)
        .await?;

        for projection in &write.projections {
            insert_projection(&mut transaction, write.publication_id, projection).await?;
        }
        for expansion in &write.expansions {
            insert_expansion(&mut transaction, write.publication_id, expansion).await?;
        }

        let advanced = sqlx::query(
            "UPDATE segments SET current_generation = ?, current_content_hash = ? WHERE tenant_id = ? AND id = ? AND current_generation = ? AND current_content_hash = ?",
        )
        .bind(write.generation)
        .bind(write.snapshot.content_hash.as_slice())
        .bind(write.tenant_id)
        .bind(write.segment_id)
        .bind(write.expected_previous_generation)
        .bind(write.expected_previous_hash.as_slice())
        .execute(&mut *transaction)
        .await?;
        if advanced.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(SdwanError::GenerationGap);
        }
        transaction.commit().await?;
        Ok(PublicationOutcome::Published)
    }
}

async fn validate_projection_ownership(
    transaction: &mut Transaction<'_, MySql>,
    write: &SegmentPublicationWrite,
) -> Result<(), SdwanError> {
    // MySQL returns COUNT(*) as signed BIGINT even when the counted keys are unsigned.
    let expected_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM segment_attachments WHERE tenant_id = ? AND segment_id = ? AND principal_kind = 'DEVICE' AND state IN ('ACTIVE', 'STANDBY')",
    )
    .bind(write.tenant_id)
    .bind(write.segment_id)
    .fetch_one(&mut **transaction)
    .await?;
    if expected_count != write.projections.len() as i64 {
        return Err(SdwanError::MissingProjection);
    }

    for projection in &write.projections {
        let matches: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM segment_attachments a JOIN sites s ON s.id = a.site_id AND s.tenant_id = a.tenant_id AND s.state = 'ACTIVE' JOIN devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id AND d.status = 'ACTIVE' JOIN device_keys k ON k.id = a.device_key_id AND k.tenant_id = a.tenant_id AND k.device_id = d.id AND k.status = 'ACTIVE' WHERE a.id = ? AND a.tenant_id = ? AND a.segment_id = ? AND a.site_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE', 'STANDBY')",
        )
        .bind(projection.attachment_id)
        .bind(projection.tenant_id)
        .bind(projection.segment_id)
        .bind(projection.site_id)
        .bind(projection.device_id)
        .bind(projection.device_key_id)
        .fetch_one(&mut **transaction)
        .await?;
        if matches != 1 {
            return Err(SdwanError::ScopeMismatch);
        }
    }
    Ok(())
}

async fn publication_exists(
    transaction: &mut Transaction<'_, MySql>,
    publication_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT 1 FROM segment_route_publications WHERE id = ? FOR SHARE")
        .bind(publication_id)
        .fetch_optional(&mut **transaction)
        .await
        .map(|value| value.is_some())
}

async fn publication_matches(
    transaction: &mut Transaction<'_, MySql>,
    write: &SegmentPublicationWrite,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT tenant_id, segment_id, expected_previous_generation, expected_previous_hash, generation, content_hash, signed_envelope, audit_event_id, actor_id FROM segment_route_publications WHERE id = ? FOR SHARE",
    )
    .bind(write.publication_id)
    .fetch_one(&mut **transaction)
    .await?;
    if row.try_get::<Uuid, _>("tenant_id")? != write.tenant_id
        || row.try_get::<Uuid, _>("segment_id")? != write.segment_id
        || row.try_get::<u64, _>("expected_previous_generation")?
            != write.expected_previous_generation
        || row
            .try_get::<Vec<u8>, _>("expected_previous_hash")?
            .as_slice()
            != write.expected_previous_hash
        || row.try_get::<u64, _>("generation")? != write.generation
        || row.try_get::<Vec<u8>, _>("content_hash")?.as_slice() != write.snapshot.content_hash
        || row.try_get::<Vec<u8>, _>("signed_envelope")? != write.snapshot.signed_envelope
        || row.try_get::<Uuid, _>("audit_event_id")? != write.audit_event_id
        || row.try_get::<String, _>("actor_id")? != write.actor_id
    {
        return Ok(false);
    }

    let persisted = sqlx::query(
        "SELECT p.id, p.projection_id, p.tenant_id, p.segment_id, p.site_id, p.attachment_id, p.device_id, p.device_key_id, p.segment_generation, p.segment_content_hash, p.projection_generation, p.previous_hash, p.content_hash, p.signed_envelope FROM site_route_projection_publications p JOIN segment_route_publication_members m ON m.projection_publication_id = p.id WHERE m.segment_publication_id = ? ORDER BY p.id",
    )
    .bind(write.publication_id)
    .fetch_all(&mut **transaction)
    .await?;
    if persisted.len() != write.projections.len() {
        return Ok(false);
    }
    let mut expected: Vec<&SiteProjectionPublicationWrite> = write.projections.iter().collect();
    expected.sort_unstable_by_key(|projection| projection.publication_id);
    for (row, projection) in persisted.into_iter().zip(expected) {
        if row.try_get::<Uuid, _>("id")? != projection.publication_id
            || row.try_get::<Uuid, _>("projection_id")? != projection.projection_id
            || row.try_get::<Uuid, _>("tenant_id")? != projection.tenant_id
            || row.try_get::<Uuid, _>("segment_id")? != projection.segment_id
            || row.try_get::<Uuid, _>("site_id")? != projection.site_id
            || row.try_get::<Uuid, _>("attachment_id")? != projection.attachment_id
            || row.try_get::<Uuid, _>("device_id")? != projection.device_id
            || row.try_get::<Uuid, _>("device_key_id")? != projection.device_key_id
            || row.try_get::<u64, _>("segment_generation")? != projection.segment_generation
            || row
                .try_get::<Vec<u8>, _>("segment_content_hash")?
                .as_slice()
                != projection.segment_content_hash
            || row.try_get::<u64, _>("projection_generation")? != projection.projection_generation
            || row.try_get::<Vec<u8>, _>("previous_hash")?.as_slice() != projection.previous_hash
            || row.try_get::<Vec<u8>, _>("content_hash")?.as_slice()
                != projection.object.content_hash
            || row.try_get::<Vec<u8>, _>("signed_envelope")? != projection.object.signed_envelope
        {
            return Ok(false);
        }
    }
    let persisted = sqlx::query(
        "SELECT id, tenant_id, segment_id, object_kind, policy_id, generation, segment_generation, segment_content_hash, site_id, attachment_id, content_hash, signed_envelope FROM segment_expansion_publications WHERE segment_publication_id = ? ORDER BY id",
    )
    .bind(write.publication_id)
    .fetch_all(&mut **transaction)
    .await?;
    if persisted.len() != write.expansions.len() {
        return Ok(false);
    }
    let mut expected: Vec<&ExpansionObjectPublicationWrite> = write.expansions.iter().collect();
    expected.sort_unstable_by_key(|expansion| expansion.publication_id);
    for (row, expansion) in persisted.into_iter().zip(expected) {
        if row.try_get::<Uuid, _>("id")? != expansion.publication_id
            || row.try_get::<Uuid, _>("tenant_id")? != expansion.tenant_id
            || row.try_get::<Uuid, _>("segment_id")? != expansion.segment_id
            || row.try_get::<String, _>("object_kind")? != expansion.kind.database_value()
            || row.try_get::<Uuid, _>("policy_id")? != expansion.policy_id
            || row.try_get::<u64, _>("generation")? != expansion.generation
            || row.try_get::<u64, _>("segment_generation")? != expansion.segment_generation
            || row
                .try_get::<Vec<u8>, _>("segment_content_hash")?
                .as_slice()
                != expansion.segment_content_hash
            || row.try_get::<Option<Uuid>, _>("site_id")? != expansion.site_id
            || row.try_get::<Option<Uuid>, _>("attachment_id")? != expansion.attachment_id
            || row.try_get::<Vec<u8>, _>("content_hash")?.as_slice()
                != expansion.object.content_hash
            || row.try_get::<Vec<u8>, _>("signed_envelope")? != expansion.object.signed_envelope
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn insert_expansion(
    transaction: &mut Transaction<'_, MySql>,
    segment_publication_id: Uuid,
    expansion: &ExpansionObjectPublicationWrite,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO segment_expansion_publications (id, segment_publication_id, tenant_id, segment_id, object_kind, policy_id, generation, segment_generation, segment_content_hash, site_id, attachment_id, content_hash, signed_envelope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(expansion.publication_id)
    .bind(segment_publication_id)
    .bind(expansion.tenant_id)
    .bind(expansion.segment_id)
    .bind(expansion.kind.database_value())
    .bind(expansion.policy_id)
    .bind(expansion.generation)
    .bind(expansion.segment_generation)
    .bind(expansion.segment_content_hash.as_slice())
    .bind(expansion.site_id)
    .bind(expansion.attachment_id)
    .bind(expansion.object.content_hash.as_slice())
    .bind(&expansion.object.signed_envelope)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_projection(
    transaction: &mut Transaction<'_, MySql>,
    segment_publication_id: Uuid,
    projection: &SiteProjectionPublicationWrite,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO site_route_projection_publications (id, publication_id, projection_id, tenant_id, segment_id, site_id, attachment_id, device_id, device_key_id, segment_generation, segment_content_hash, projection_generation, previous_hash, content_hash, signed_envelope) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(projection.publication_id)
    .bind(segment_publication_id)
    .bind(projection.projection_id)
    .bind(projection.tenant_id)
    .bind(projection.segment_id)
    .bind(projection.site_id)
    .bind(projection.attachment_id)
    .bind(projection.device_id)
    .bind(projection.device_key_id)
    .bind(projection.segment_generation)
    .bind(projection.segment_content_hash.as_slice())
    .bind(projection.projection_generation)
    .bind(projection.previous_hash.as_slice())
    .bind(projection.object.content_hash.as_slice())
    .bind(&projection.object.signed_envelope)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO segment_route_publication_members (tenant_id, segment_publication_id, projection_publication_id, projection_id, attachment_id) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(projection.tenant_id)
    .bind(segment_publication_id)
    .bind(projection.publication_id)
    .bind(projection.projection_id)
    .bind(projection.attachment_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
