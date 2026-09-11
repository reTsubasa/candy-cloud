use super::{ControlRepository, ControlStoreError};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{MySql, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpgradeTarget {
    pub component: String,
    pub current_version: String,
    pub version: String,
    pub version_key: String,
    pub digest: String,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"._+-".contains(&v))
}

impl UpgradeTarget {
    pub fn validate(&self) -> bool {
        matches!(self.component.as_str(), "core" | "runtime")
            && identifier(&self.current_version)
            && identifier(&self.version)
            && identifier(&self.version_key)
            && self.digest.len() == 64
            && self
                .digest
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeInventory {
    pub schema_version: u8,
    pub platform: String,
    pub architecture: String,
    pub targets: Vec<UpgradeTarget>,
}

impl UpgradeInventory {
    pub fn validate(&self) -> bool {
        self.schema_version == 1
            && matches!(self.platform.as_str(), "linux" | "openwrt")
            && identifier(&self.architecture)
            && self.targets.len() <= 2
            && self.targets.iter().all(|t| {
                t.validate()
                    && self
                        .targets
                        .iter()
                        .filter(|v| v.component == t.component)
                        .count()
                        == 1
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeJob {
    pub id: Uuid,
    pub node_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub target: UpgradeTarget,
    pub state: String,
    pub error_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn job(row: sqlx::mysql::MySqlRow) -> Result<UpgradeJob, ControlStoreError> {
    Ok(UpgradeJob {
        id: row.try_get("id")?,
        node_id: row.try_get("node_id")?,
        device_id: row.try_get("device_id")?,
        device_key_id: row.try_get("device_key_id")?,
        target: serde_json::from_str(&row.try_get::<String, _>("target_json")?)
            .map_err(|_| ControlStoreError::InvalidTransition)?,
        state: row.try_get("state")?,
        error_code: row.try_get("error_code")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn identity(
    tx: &mut Transaction<'_, MySql>,
    tenant: Uuid,
    node: Uuid,
) -> Result<(Uuid, Uuid), ControlStoreError> {
    let row = sqlx::query("SELECT JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_id')) AS device, JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.resource.spec.device_key_id')) AS device_key FROM sdwan_control_resources WHERE tenant_id=? AND resource_kind='NODE' AND id=? AND state='ACTIVE' FOR UPDATE")
        .bind(tenant).bind(node).fetch_optional(&mut **tx).await?.ok_or(ControlStoreError::NotFound)?;
    let device: String = row.try_get("device")?;
    let key: String = row.try_get("device_key")?;
    Ok((
        Uuid::parse_str(&device).map_err(|_| ControlStoreError::InvalidRequest)?,
        Uuid::parse_str(&key).map_err(|_| ControlStoreError::InvalidRequest)?,
    ))
}

async fn audit(
    tx: &mut Transaction<'_, MySql>,
    tenant: Uuid,
    id: Uuid,
    actor: &str,
    action: &str,
) -> Result<(), ControlStoreError> {
    sqlx::query("INSERT INTO audit_events (id,tenant_id,actor_type,actor_id,action,object_type,object_id,metadata_json) VALUES (?,?,'UPGRADE',?,?,'NODE_UPGRADE',?,JSON_OBJECT())")
        .bind(Uuid::new_v4()).bind(tenant).bind(actor).bind(action).bind(id.to_string()).execute(&mut **tx).await?;
    Ok(())
}

impl ControlRepository {
    pub async fn upgrade_inventory(
        &self,
        tenant: Uuid,
        node: Uuid,
    ) -> Result<Option<(UpgradeInventory, DateTime<Utc>)>, ControlStoreError> {
        let mut tx = self.pool.begin().await?;
        let (device, key) = identity(&mut tx, tenant, node).await?;
        let row = sqlx::query("SELECT CAST(inventory AS CHAR) AS inventory,reported_at FROM runtime_upgrade_inventory WHERE tenant_id=? AND device_id=? AND device_key_id=?")
            .bind(tenant).bind(device).bind(key).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        row.map(|r| {
            Ok((
                serde_json::from_str(&r.try_get::<String, _>("inventory")?)
                    .map_err(|_| ControlStoreError::InvalidTransition)?,
                r.try_get("reported_at")?,
            ))
        })
        .transpose()
    }

    pub async fn record_upgrade_inventory(
        &self,
        tenant: Uuid,
        device: Uuid,
        key: Uuid,
        inventory: UpgradeInventory,
    ) -> Result<(), ControlStoreError> {
        if !inventory.validate() || tenant.is_nil() || device.is_nil() || key.is_nil() {
            return Err(ControlStoreError::InvalidRequest);
        }
        sqlx::query("INSERT INTO runtime_upgrade_inventory (tenant_id,device_id,device_key_id,inventory,reported_at) VALUES (?,?,?,CAST(? AS JSON),?) ON DUPLICATE KEY UPDATE inventory=VALUES(inventory),reported_at=VALUES(reported_at)")
            .bind(tenant).bind(device).bind(key).bind(serde_json::to_string(&inventory).map_err(|_| ControlStoreError::InvalidRequest)?).bind(Utc::now()).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn node_upgrade_jobs(
        &self,
        tenant: Uuid,
        node: Uuid,
    ) -> Result<Vec<UpgradeJob>, ControlStoreError> {
        sqlx::query("SELECT *,CAST(target AS CHAR) AS target_json FROM runtime_upgrade_jobs WHERE tenant_id=? AND node_id=? ORDER BY created_at DESC LIMIT 20")
            .bind(tenant).bind(node).fetch_all(&self.pool).await?.into_iter().map(job).collect()
    }

    pub async fn create_node_upgrade(
        &self,
        tenant: Uuid,
        node: Uuid,
        actor: &str,
        request: Uuid,
        target: UpgradeTarget,
    ) -> Result<UpgradeJob, ControlStoreError> {
        if actor.is_empty() || actor.len() > 120 || request.is_nil() || !target.validate() {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        let (device, key) = identity(&mut tx, tenant, node).await?;
        if let Some(row)=sqlx::query("SELECT *,CAST(target AS CHAR) AS target_json FROM runtime_upgrade_jobs WHERE tenant_id=? AND node_id=? AND actor_id=? AND request_id=?")
            .bind(tenant).bind(node).bind(actor).bind(request).fetch_optional(&mut *tx).await? {
            let result=job(row)?;
            if result.target!=target { return Err(ControlStoreError::IdempotencyConflict); }
            tx.commit().await?; return Ok(result);
        }
        let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM runtime_upgrade_jobs WHERE tenant_id=? AND node_id=? AND state IN ('pending','running')")
            .bind(tenant).bind(node).fetch_one(&mut *tx).await?;
        if active > 0 {
            return Err(ControlStoreError::InvalidTransition);
        }
        let row=sqlx::query("SELECT CAST(inventory AS CHAR) FROM runtime_upgrade_inventory WHERE tenant_id=? AND device_id=? AND device_key_id=? AND reported_at>?")
            .bind(tenant).bind(device).bind(key).bind(Utc::now()-Duration::minutes(5)).fetch_optional(&mut *tx).await?.ok_or(ControlStoreError::InvalidTransition)?;
        let inventory: UpgradeInventory = serde_json::from_str(&row.try_get::<String, _>(0)?)
            .map_err(|_| ControlStoreError::InvalidRequest)?;
        if !inventory.targets.contains(&target) || target.current_version == target.version {
            return Err(ControlStoreError::InvalidRequest);
        }
        let id = Uuid::new_v4();
        let now = Utc::now();
        sqlx::query("INSERT INTO runtime_upgrade_jobs (id,tenant_id,node_id,device_id,device_key_id,actor_id,request_id,target,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?,CAST(? AS JSON),'pending',?,?)")
            .bind(id).bind(tenant).bind(node).bind(device).bind(key).bind(actor).bind(request).bind(serde_json::to_string(&target).map_err(|_| ControlStoreError::InvalidRequest)?).bind(now).bind(now).execute(&mut *tx).await?;
        audit(&mut tx, tenant, id, actor, "NODE_UPGRADE_REQUESTED").await?;
        tx.commit().await?;
        Ok(UpgradeJob {
            id,
            node_id: node,
            device_id: device,
            device_key_id: key,
            target,
            state: "pending".into(),
            error_code: None,
            created_at: now,
            updated_at: now,
        })
    }

    // Device polling does not claim work. The receipt is persisted locally before
    // the explicit pending -> running transition, so a lost HTTP reply is safe.
    pub async fn pending_node_upgrade(
        &self,
        tenant: Uuid,
        device: Uuid,
        key: Uuid,
    ) -> Result<Option<UpgradeJob>, ControlStoreError> {
        let row=sqlx::query("SELECT *,CAST(target AS CHAR) AS target_json FROM runtime_upgrade_jobs WHERE tenant_id=? AND device_id=? AND device_key_id=? AND state IN ('pending','running') ORDER BY created_at LIMIT 1")
            .bind(tenant).bind(device).bind(key).fetch_optional(&self.pool).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let result = job(row)?;
        let mut tx = self.pool.begin().await?;
        if identity(&mut tx, tenant, result.node_id).await? != (device, key) {
            return Err(ControlStoreError::NotFound);
        }
        if result.state == "pending" && result.created_at < Utc::now() - Duration::hours(24) {
            sqlx::query("UPDATE runtime_upgrade_jobs SET state='expired',error_code='dispatch_expired',updated_at=? WHERE id=? AND state='pending'")
                .bind(Utc::now()).bind(result.id).execute(&mut *tx).await?;
            audit(
                &mut tx,
                tenant,
                result.id,
                &device.to_string(),
                "NODE_UPGRADE_EXPIRED",
            )
            .await?;
            tx.commit().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(result))
    }

    pub async fn update_node_upgrade(
        &self,
        tenant: Uuid,
        device: Uuid,
        key: Uuid,
        id: Uuid,
        state: &str,
        error: Option<&str>,
    ) -> Result<(), ControlStoreError> {
        if !matches!(state, "running" | "succeeded" | "failed")
            || (state == "failed") != error.is_some()
            || error.is_some_and(|e| !identifier(e))
        {
            return Err(ControlStoreError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query("SELECT *,CAST(target AS CHAR) AS target_json FROM runtime_upgrade_jobs WHERE id=? AND tenant_id=? AND device_id=? AND device_key_id=?")
            .bind(id).bind(tenant).bind(device).bind(key).fetch_optional(&mut *tx).await?.ok_or(ControlStoreError::NotFound)?;
        let previous = job(row)?;
        if identity(&mut tx, tenant, previous.node_id).await? != (device, key) {
            return Err(ControlStoreError::NotFound);
        }
        let previous=job(sqlx::query("SELECT *,CAST(target AS CHAR) AS target_json FROM runtime_upgrade_jobs WHERE id=? FOR UPDATE").bind(id).fetch_one(&mut *tx).await?)?;
        if previous.state == state && previous.error_code.as_deref() == error {
            tx.commit().await?;
            return Ok(());
        }
        if !((previous.state == "pending" && state == "running")
            || (previous.state == "running" && matches!(state, "succeeded" | "failed")))
        {
            return Err(ControlStoreError::InvalidTransition);
        }
        sqlx::query("UPDATE runtime_upgrade_jobs SET state=?,error_code=?,updated_at=? WHERE id=?")
            .bind(state)
            .bind(error)
            .bind(Utc::now())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            tenant,
            id,
            &device.to_string(),
            match state {
                "running" => "NODE_UPGRADE_STARTED",
                "succeeded" => "NODE_UPGRADE_SUCCEEDED",
                _ => "NODE_UPGRADE_FAILED",
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_rejects_shell_values_and_duplicate_components() {
        let target = UpgradeTarget {
            component: "core".into(),
            current_version: "0.3.45".into(),
            version: "0.3.46".into(),
            version_key: "v0_3_46".into(),
            digest: "a".repeat(64),
        };
        let mut inventory = UpgradeInventory {
            schema_version: 1,
            platform: "linux".into(),
            architecture: "x86_64".into(),
            targets: vec![target.clone()],
        };
        assert!(inventory.validate());
        inventory.targets.push(target);
        assert!(!inventory.validate());
        inventory.targets.pop();
        inventory.targets[0].version = "$(id)".into();
        assert!(!inventory.validate());
    }
}
