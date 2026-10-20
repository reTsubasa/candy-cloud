use sqlx::Row;
use uuid::Uuid;

use crate::{DbPool, RepositoryError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationLookup {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub node_pool_id: Uuid,
}

impl AuthorizationLookup {
    pub fn validate(&self) -> Result<(), RepositoryError> {
        if self.tenant_id.is_nil()
            || self.device_id.is_nil()
            || self.device_key_id.is_nil()
            || self.node_pool_id.is_nil()
        {
            return Err(RepositoryError::InvalidAuthorizationScope);
        }
        Ok(())
    }
}

/// Exact signed route policy requested by an authenticated Runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationPolicyRef {
    pub policy_id: Uuid,
    pub generation: u64,
    pub content_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub device_id: Uuid,
    pub device_status: String,
    pub device_key_id: Uuid,
    pub device_public_key: Vec<u8>,
    pub assurance_level: u64,
    pub node_pool_id: Uuid,
    pub service_class: String,
    pub entitlement_id: Uuid,
    pub service_permission: String,
    pub entitlement_status: String,
    pub entitlement_generation: u64,
    pub subscription_status: String,
    pub policy_generation: u64,
    pub revocation_generation: u64,
    pub authorization_generation: u64,
    pub quota_json: String,
    pub route_policy: Option<AuthorizationRoutePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRoutePolicy {
    pub segment_id: Uuid,
    pub attachment_id: Uuid,
    pub site_id: Uuid,
    pub projection_id: Uuid,
    pub projection_generation: u64,
    pub projection_content_hash: Vec<u8>,
    pub segment_generation: u64,
    pub segment_content_hash: Vec<u8>,
}

#[derive(Clone)]
pub struct AuthorizationRepository {
    pool: DbPool,
    policy_isolation: bool,
}

impl AuthorizationRepository {
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            policy_isolation: std::env::var("CANDY_ENABLE_MULTI_GENERATION_POLICY_ISOLATION")
                .as_deref()
                == Ok("1"),
        }
    }

    pub fn with_policy_isolation(mut self, enabled: bool) -> Self {
        self.policy_isolation = enabled;
        self
    }

    /// Reads every input to a Grant under one repeatable transaction and locks the selected rows
    /// against concurrent policy/key changes until the snapshot has been copied into memory.
    pub async fn load(
        &self,
        lookup: &AuthorizationLookup,
    ) -> Result<Option<AuthorizationRecord>, RepositoryError> {
        self.load_for_policy(lookup, None).await
    }

    pub async fn load_for_policy(
        &self,
        lookup: &AuthorizationLookup,
        requested: Option<&AuthorizationPolicyRef>,
    ) -> Result<Option<AuthorizationRecord>, RepositoryError> {
        lookup.validate()?;
        if requested.is_some_and(|policy| {
            policy.policy_id.is_nil() || policy.generation == 0 || policy.content_hash == [0; 32]
        }) {
            return Err(RepositoryError::InvalidAuthorizationScope);
        }
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT t.organization_id, t.id AS tenant_id, e.subscription_id, \
                    d.id AS device_id, d.status AS device_status, \
                    dk.id AS device_key_id, dk.public_key AS device_public_key, dk.assurance_level, \
                    np.id AS node_pool_id, np.service_class, \
                    e.id AS entitlement_id, e.service_permission, e.status AS entitlement_status, \
                    e.generation AS entitlement_generation, s.status AS subscription_status, \
                    CAST(COALESCE((SELECT MAX(policy.generation) FROM policies policy WHERE policy.tenant_id = t.id), 0) AS UNSIGNED) AS policy_generation, \
                    CAST(COALESCE(r.generation, 0) AS UNSIGNED) AS revocation_generation, \
                    ag.generation AS authorization_generation, \
                    CAST(e.quota_json AS CHAR) AS quota_json \
             FROM tenants t \
             JOIN organizations org ON org.id = t.organization_id AND org.status = 'ACTIVE' \
             JOIN devices d ON d.tenant_id = t.id AND d.id = ? \
             JOIN device_keys dk ON dk.tenant_id = t.id AND dk.device_id = d.id AND dk.id = ? AND dk.status = 'ACTIVE' \
             JOIN entitlements e ON e.tenant_id = t.id AND e.node_pool_id = ? \
             JOIN subscriptions s ON s.tenant_id = t.id AND s.id = e.subscription_id \
             JOIN node_pools np ON np.id = e.node_pool_id AND np.status = 'ACTIVE' \
             JOIN authorization_generations ag ON ag.tenant_id = t.id \
             LEFT JOIN revocation_generations r ON r.tenant_id = t.id \
             WHERE t.id = ? AND t.status = 'ACTIVE' FOR SHARE",
        )
        .bind(lookup.device_id)
        .bind(lookup.device_key_id)
        .bind(lookup.node_pool_id)
        .bind(lookup.tenant_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.commit().await?;
            return Ok(None);
        };
        let mut record = record_from_row(row)?;
        if record.device_status != "ACTIVE"
            || record.entitlement_status != "ACTIVE"
            || !matches!(
                record.subscription_status.as_str(),
                "TRIAL" | "ACTIVE" | "GRACE"
            )
        {
            transaction.commit().await?;
            return Ok(None);
        }
        if record.service_permission == "private.tun.connect" {
            let policies = if let Some(requested) = requested {
                // A signed request for the current target is needed during
                // Prepare. An older request is granted only for the exact
                // acknowledged active version, across policy-only updates;
                // arbitrary historical generations cannot acquire a Grant.
                sqlx::query(
                    "SELECT seg.id AS segment_id, a.id AS attachment_id, a.site_id, p.projection_id, p.projection_generation, p.content_hash AS projection_content_hash, publication.generation AS segment_generation, publication.content_hash AS segment_content_hash FROM segment_attachments a JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' JOIN sites site ON site.id = a.site_id AND site.tenant_id = a.tenant_id AND site.state = 'ACTIVE' JOIN runtime_configuration_rollouts rollout ON rollout.tenant_id = seg.tenant_id AND rollout.segment_id = seg.id AND rollout.segment_generation = seg.current_generation JOIN site_route_projection_publications target ON target.tenant_id = a.tenant_id AND target.segment_id = a.segment_id AND target.attachment_id = a.id AND target.device_id = a.device_id AND target.device_key_id = a.device_key_id AND target.segment_generation = seg.current_generation JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id JOIN segment_route_publication_members member ON member.tenant_id = p.tenant_id AND member.projection_publication_id = p.id AND member.attachment_id = p.attachment_id AND member.projection_id = p.projection_id JOIN segment_route_publications publication ON publication.id = member.segment_publication_id AND publication.id = p.publication_id AND publication.tenant_id = p.tenant_id AND publication.segment_id = p.segment_id AND publication.generation = p.segment_generation AND publication.content_hash = p.segment_content_hash LEFT JOIN runtime_configuration_status status ON status.tenant_id = a.tenant_id AND status.device_id = a.device_id AND status.device_key_id = a.device_key_id WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY') AND p.projection_id = ? AND p.projection_generation = ? AND p.content_hash = ? AND publication.expires_at >= UNIX_TIMESTAMP() AND publication.stale_until >= UNIX_TIMESTAMP() AND ((p.id = target.id AND member.rollout_ordinal <= rollout.allowed_ordinal) OR (p.id = status.active_projection_publication_id AND p.segment_generation < seg.current_generation AND (p.segment_generation = seg.current_generation - 1 OR (? AND p.segment_generation >= seg.current_generation - LEAST(seg.current_generation, 32) AND NOT EXISTS(SELECT 1 FROM segment_route_publications changed WHERE changed.tenant_id = p.tenant_id AND changed.segment_id = p.segment_id AND changed.generation > p.segment_generation AND changed.generation <= seg.current_generation AND changed.activation_mode <> 'POLICY_ONLY'))))) FOR SHARE",
                ).bind(lookup.tenant_id).bind(lookup.device_id).bind(lookup.device_key_id)
                    .bind(requested.policy_id).bind(requested.generation).bind(requested.content_hash.as_slice())
                    .bind(self.policy_isolation)
                    .fetch_all(&mut *transaction).await?
            } else {
                sqlx::query(
                "SELECT seg.id AS segment_id, a.id AS attachment_id, a.site_id, p.projection_id, p.projection_generation, p.content_hash AS projection_content_hash, publication.generation AS segment_generation, publication.content_hash AS segment_content_hash \
                 FROM segment_attachments a \
                 JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' \
                 JOIN sites site ON site.id = a.site_id AND site.tenant_id = a.tenant_id AND site.state = 'ACTIVE' \
                 JOIN runtime_configuration_rollouts rollout ON rollout.tenant_id = seg.tenant_id AND rollout.segment_id = seg.id AND rollout.segment_generation = seg.current_generation \
                 JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id \
                 JOIN segment_route_publication_members member ON member.tenant_id = p.tenant_id AND member.projection_publication_id = p.id AND member.attachment_id = p.attachment_id AND member.projection_id = p.projection_id \
                 JOIN segment_route_publications publication ON publication.tenant_id = p.tenant_id AND publication.segment_id = p.segment_id AND publication.generation = p.segment_generation AND publication.content_hash = p.segment_content_hash AND publication.id = member.segment_publication_id \
                 WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE', 'STANDBY') \
                   AND publication.expires_at >= UNIX_TIMESTAMP() AND publication.stale_until >= UNIX_TIMESTAMP() \
                   AND (((rollout.state = 'BLOCKED' OR member.rollout_ordinal > rollout.allowed_ordinal) AND seg.current_generation > 1 AND p.segment_generation = seg.current_generation - 1) \
                    OR (rollout.state <> 'BLOCKED' AND member.rollout_ordinal <= rollout.allowed_ordinal AND p.segment_generation = seg.current_generation) \
                    OR (rollout.state = 'BLOCKED' AND member.rollout_ordinal <= rollout.allowed_ordinal AND p.segment_generation = seg.current_generation \
                        AND NOT EXISTS (SELECT 1 FROM site_route_projection_publications previous \
                                        WHERE previous.tenant_id = p.tenant_id AND previous.segment_id = p.segment_id \
                                          AND previous.attachment_id = p.attachment_id AND previous.device_id = p.device_id \
                                          AND previous.device_key_id = p.device_key_id AND previous.segment_generation = seg.current_generation - 1))) FOR SHARE",
            )
            .bind(lookup.tenant_id)
            .bind(lookup.device_id)
            .bind(lookup.device_key_id)
            .fetch_all(&mut *transaction)
            .await?
            };
            if policies.len() != 1 {
                if self.policy_isolation {
                    if let Some(requested) = requested {
                        let resync: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM segment_attachments a JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' JOIN sites site ON site.id = a.site_id AND site.tenant_id = a.tenant_id AND site.state = 'ACTIVE' JOIN runtime_configuration_status status ON status.tenant_id = a.tenant_id AND status.device_id = a.device_id AND status.device_key_id = a.device_key_id JOIN site_route_projection_publications p ON p.id = status.active_projection_publication_id AND p.tenant_id = a.tenant_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.state IN ('ACTIVE','STANDBY') AND p.projection_id = ? AND p.projection_generation = ? AND p.content_hash = ? AND p.segment_generation < seg.current_generation - LEAST(seg.current_generation, 32)")
                            .bind(lookup.tenant_id).bind(lookup.device_id).bind(lookup.device_key_id)
                            .bind(requested.policy_id).bind(requested.generation).bind(requested.content_hash.as_slice())
                            .fetch_one(&mut *transaction).await?;
                        if resync == 1 {
                            transaction.rollback().await?;
                            return Err(RepositoryError::RoutePolicyResyncRequired);
                        }
                    }
                }
                transaction.rollback().await?;
                return Err(RepositoryError::InvalidAuthorizationScope);
            }
            let policy = &policies[0];
            record.route_policy = Some(AuthorizationRoutePolicy {
                segment_id: policy.try_get("segment_id")?,
                attachment_id: policy.try_get("attachment_id")?,
                site_id: policy.try_get("site_id")?,
                projection_id: policy.try_get("projection_id")?,
                projection_generation: policy.try_get("projection_generation")?,
                projection_content_hash: policy.try_get("projection_content_hash")?,
                segment_generation: policy.try_get("segment_generation")?,
                segment_content_hash: policy.try_get("segment_content_hash")?,
            });
        }
        transaction.commit().await?;
        Ok(Some(record))
    }
}

fn record_from_row(row: sqlx::mysql::MySqlRow) -> Result<AuthorizationRecord, RepositoryError> {
    Ok(AuthorizationRecord {
        organization_id: row.try_get("organization_id")?,
        tenant_id: row.try_get("tenant_id")?,
        subscription_id: row.try_get("subscription_id")?,
        device_id: row.try_get("device_id")?,
        device_status: row.try_get("device_status")?,
        device_key_id: row.try_get("device_key_id")?,
        device_public_key: row.try_get("device_public_key")?,
        assurance_level: row.try_get("assurance_level")?,
        node_pool_id: row.try_get("node_pool_id")?,
        service_class: row.try_get("service_class")?,
        entitlement_id: row.try_get("entitlement_id")?,
        service_permission: row.try_get("service_permission")?,
        entitlement_status: row.try_get("entitlement_status")?,
        entitlement_generation: row.try_get("entitlement_generation")?,
        subscription_status: row.try_get("subscription_status")?,
        policy_generation: row.try_get("policy_generation")?,
        revocation_generation: row.try_get("revocation_generation")?,
        authorization_generation: row.try_get("authorization_generation")?,
        quota_json: row.try_get("quota_json")?,
        route_policy: None,
    })
}
