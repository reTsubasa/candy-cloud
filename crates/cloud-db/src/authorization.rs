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
}

impl AuthorizationRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Reads every input to a Grant under one repeatable transaction and locks the selected rows
    /// against concurrent policy/key changes until the snapshot has been copied into memory.
    pub async fn load(
        &self,
        lookup: &AuthorizationLookup,
    ) -> Result<Option<AuthorizationRecord>, RepositoryError> {
        lookup.validate()?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT t.organization_id, t.id AS tenant_id, e.subscription_id, \
                    d.id AS device_id, d.status AS device_status, \
                    dk.id AS device_key_id, dk.public_key AS device_public_key, dk.assurance_level, \
                    np.id AS node_pool_id, np.service_class, \
                    e.id AS entitlement_id, e.service_permission, e.status AS entitlement_status, \
                    e.generation AS entitlement_generation, s.status AS subscription_status, \
                    CAST(COALESCE(p.generation, 0) AS UNSIGNED) AS policy_generation, \
                    CAST(COALESCE(r.generation, 0) AS UNSIGNED) AS revocation_generation, \
                    ag.generation AS authorization_generation, \
                    CAST(e.quota_json AS CHAR) AS quota_json \
             FROM tenants t \
             JOIN devices d ON d.tenant_id = t.id AND d.id = ? \
             JOIN device_keys dk ON dk.tenant_id = t.id AND dk.device_id = d.id AND dk.id = ? AND dk.status = 'ACTIVE' \
             JOIN entitlements e ON e.tenant_id = t.id AND e.node_pool_id = ? \
             JOIN subscriptions s ON s.tenant_id = t.id AND s.id = e.subscription_id \
             JOIN node_pools np ON np.id = e.node_pool_id \
             JOIN authorization_generations ag ON ag.tenant_id = t.id \
             LEFT JOIN policies p ON p.tenant_id = t.id \
             LEFT JOIN revocation_generations r ON r.tenant_id = t.id \
             WHERE t.id = ? FOR SHARE",
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
        if record.service_permission == "private.tun.connect" {
            let policies = sqlx::query(
                "SELECT seg.id AS segment_id, a.id AS attachment_id, a.site_id, p.projection_id, p.projection_generation, p.content_hash AS projection_content_hash, seg.current_generation AS segment_generation, seg.current_content_hash AS segment_content_hash \
                 FROM segment_attachments a \
                 JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' \
                 JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id AND p.segment_generation = seg.current_generation AND p.segment_content_hash = seg.current_content_hash \
                 WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE', 'STANDBY') FOR SHARE",
            )
            .bind(lookup.tenant_id)
            .bind(lookup.device_id)
            .bind(lookup.device_key_id)
            .fetch_all(&mut *transaction)
            .await?;
            if policies.len() != 1 {
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
