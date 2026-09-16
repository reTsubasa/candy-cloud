use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::client_control::ClientPlatform;
use crate::DbPool;

const MAX_RESOURCES: usize = 4096;
const MAX_RESOURCE_NAME_LEN: usize = 128;
const MAX_DOMAIN_LEN: usize = 253;
const MAX_CIDR_LEN: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientTrafficMode {
    Policy,
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientAllowedResource {
    pub name: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientAccessPolicy {
    pub schema_version: u16,
    pub policy_id: Uuid,
    pub tenant_id: Uuid,
    pub generation: u64,
    pub mode_capabilities: Vec<ClientTrafficMode>,
    pub global_egress_enabled: bool,
    pub allowed_resources: Vec<ClientAllowedResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthorizationSnapshot {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub client_device_id: Uuid,
    pub device_key_id: Uuid,
    pub platform: ClientPlatform,
    pub device_generation: u64,
    pub public_key: [u8; 32],
    pub policy: ClientAccessPolicy,
    pub policy_content_hash: [u8; 32],
}

impl ClientAuthorizationSnapshot {
    pub fn validate(&self) -> Result<(), ClientAccessPolicyError> {
        if [
            self.organization_id,
            self.tenant_id,
            self.user_id,
            self.client_device_id,
            self.device_key_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
            || self.device_generation == 0
            || self.public_key == [0; 32]
            || self.policy.tenant_id != self.tenant_id
            || self.policy.generation == 0
            || self.policy_content_hash == [0; 32]
        {
            return Err(ClientAccessPolicyError::InvalidRecord);
        }
        let computed_hash = self
            .policy
            .content_hash()
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if computed_hash != self.policy_content_hash {
            return Err(ClientAccessPolicyError::InvalidRecord);
        }
        Ok(())
    }
}

impl ClientAccessPolicy {
    pub fn validate(&self) -> Result<(), ClientAccessPolicyError> {
        if self.schema_version != 1
            || self.policy_id.is_nil()
            || self.tenant_id.is_nil()
            || self.generation == 0
            || self.mode_capabilities.is_empty()
            || self.mode_capabilities.iter().any(|mode| {
                self.mode_capabilities[..self
                    .mode_capabilities
                    .iter()
                    .position(|candidate| candidate == mode)
                    .unwrap_or(0)]
                    .contains(mode)
            })
            || (!self.mode_capabilities.contains(&ClientTrafficMode::Global)
                && self.global_egress_enabled)
            || self.allowed_resources.len() > MAX_RESOURCES
        {
            return Err(ClientAccessPolicyError::InvalidPolicy);
        }
        let mut names = std::collections::HashSet::new();
        for resource in &self.allowed_resources {
            if resource.name.is_empty()
                || resource.name.len() > MAX_RESOURCE_NAME_LEN
                || !resource
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
                || !names.insert(&resource.name)
                || (resource.domains.is_empty() && resource.cidrs.is_empty())
                || resource.domains.len() > 1024
                || resource.cidrs.len() > 1024
                || resource.ports.len() > 128
                || resource.ports.contains(&0)
            {
                return Err(ClientAccessPolicyError::InvalidResource);
            }
            if resource.domains.iter().any(|domain| {
                domain.is_empty()
                    || domain.len() > MAX_DOMAIN_LEN
                    || domain.ends_with('.')
                    || domain.bytes().any(|byte| byte.is_ascii_uppercase())
                    || domain.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label.bytes().all(|byte| {
                                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                            })
                    })
            }) || resource.domains.windows(2).any(|pair| pair[0] == pair[1])
                || resource
                    .cidrs
                    .iter()
                    .any(|cidr| cidr.is_empty() || cidr.len() > MAX_CIDR_LEN)
                || resource.cidrs.windows(2).any(|pair| pair[0] == pair[1])
                || resource.ports.windows(2).any(|pair| pair[0] == pair[1])
            {
                return Err(ClientAccessPolicyError::InvalidResource);
            }
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<[u8; 32], ClientAccessPolicyError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ClientAccessPolicyError::InvalidPolicy)?;
        Ok(Sha256::digest(bytes).into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientAccessPolicyError {
    #[error("invalid terminal client access policy")]
    InvalidPolicy,
    #[error("invalid terminal client access resource")]
    InvalidResource,
    #[error("invalid terminal client access scope")]
    InvalidScope,
    #[error("terminal client access policy conflict")]
    Conflict,
    #[error("terminal client access policy database record is invalid")]
    InvalidRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAccessPolicyPublishOutcome {
    Published { policy_id: Uuid, replayed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAccessPolicyBindingOutcome {
    Bound { binding_id: Uuid, replayed: bool },
}

#[derive(Clone)]
pub struct ClientAccessPolicyRepository {
    pool: DbPool,
}

impl ClientAccessPolicyRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn publish(
        &self,
        policy: &ClientAccessPolicy,
        organization_id: Uuid,
        actor_id: Uuid,
        request_id: Uuid,
    ) -> Result<ClientAccessPolicyPublishOutcome, ClientAccessPolicyError> {
        policy.validate()?;
        if organization_id.is_nil() || actor_id.is_nil() || request_id.is_nil() {
            return Err(ClientAccessPolicyError::InvalidScope);
        }
        let content_hash = policy.content_hash()?;
        let request_hash = request_fingerprint(policy, organization_id, actor_id);
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let scope: Option<Uuid> = sqlx::query_scalar(
            "SELECT tenant.organization_id FROM tenants tenant JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' JOIN human_users user ON user.id = ? AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = tenant.organization_id AND membership.user_id = user.id AND membership.status = 'ACTIVE' WHERE tenant.id = ? FOR SHARE",
        )
        .bind(actor_id)
        .bind(policy.tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if scope != Some(organization_id) {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            return Err(ClientAccessPolicyError::InvalidScope);
        }
        let existing = sqlx::query(
            "SELECT id, request_hash FROM client_access_policies WHERE tenant_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(policy.tenant_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            let stored_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash {
                Ok(ClientAccessPolicyPublishOutcome::Published {
                    policy_id: stored_id,
                    replayed: true,
                })
            } else {
                Err(ClientAccessPolicyError::Conflict)
            };
        }
        sqlx::query("UPDATE client_access_policies SET status = 'SUPERSEDED' WHERE tenant_id = ? AND status = 'ACTIVE'")
            .bind(policy.tenant_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let document =
            serde_json::to_string(policy).map_err(|_| ClientAccessPolicyError::InvalidPolicy)?;
        sqlx::query(
            "INSERT INTO client_access_policies (id, organization_id, tenant_id, generation, request_id, request_hash, content_hash, policy_json, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), 'ACTIVE', ?)",
        )
        .bind(policy.policy_id)
        .bind(organization_id)
        .bind(policy.tenant_id)
        .bind(policy.generation)
        .bind(request_id)
        .bind(request_hash.as_slice())
        .bind(content_hash.as_slice())
        .bind(document)
        .bind(actor_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::Conflict)?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_ACCESS_POLICY_PUBLISHED', 'CLIENT_ACCESS_POLICY', ?, JSON_OBJECT('generation', ?, 'content_hash', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(policy.tenant_id)
        .bind(actor_id.to_string())
        .bind(policy.policy_id.to_string())
        .bind(policy.generation)
        .bind(hex_hash(&content_hash))
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        Ok(ClientAccessPolicyPublishOutcome::Published {
            policy_id: policy.policy_id,
            replayed: false,
        })
    }

    pub async fn bind_to_device(
        &self,
        policy_id: Uuid,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        client_device_id: Uuid,
        actor_id: Uuid,
        request_id: Uuid,
    ) -> Result<ClientAccessPolicyBindingOutcome, ClientAccessPolicyError> {
        if [
            policy_id,
            organization_id,
            tenant_id,
            user_id,
            client_device_id,
            actor_id,
            request_id,
        ]
        .into_iter()
        .any(|id| id.is_nil())
        {
            return Err(ClientAccessPolicyError::InvalidScope);
        }
        let request_hash = binding_fingerprint(
            policy_id,
            organization_id,
            tenant_id,
            user_id,
            client_device_id,
            actor_id,
        );
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let scope: Option<Uuid> = sqlx::query_scalar(
            "SELECT tenant.organization_id FROM tenants tenant JOIN organizations organization ON organization.id = tenant.organization_id AND organization.status = 'ACTIVE' JOIN human_users actor ON actor.id = ? AND actor.status = 'ACTIVE' JOIN organization_memberships actor_membership ON actor_membership.organization_id = tenant.organization_id AND actor_membership.user_id = actor.id AND actor_membership.status = 'ACTIVE' JOIN human_users user ON user.id = ? AND user.status = 'ACTIVE' JOIN client_devices device ON device.tenant_id = tenant.id AND device.organization_id = tenant.organization_id AND device.user_id = user.id AND device.id = ? AND device.status = 'ACTIVE' WHERE tenant.id = ? FOR SHARE",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(client_device_id)
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if scope != Some(organization_id) {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            return Err(ClientAccessPolicyError::InvalidScope);
        }
        let policy_active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM client_access_policies WHERE id = ? AND organization_id = ? AND tenant_id = ? AND status = 'ACTIVE')",
        )
        .bind(policy_id)
        .bind(organization_id)
        .bind(tenant_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if !policy_active {
            transaction
                .rollback()
                .await
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            return Err(ClientAccessPolicyError::Conflict);
        }
        let existing = sqlx::query(
            "SELECT id, request_hash FROM client_access_policy_bindings WHERE tenant_id = ? AND request_id = ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if let Some(row) = existing {
            let stored_hash: Vec<u8> = row
                .try_get("request_hash")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            let binding_id: Uuid = row
                .try_get("id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            transaction
                .rollback()
                .await
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
            return if stored_hash.as_slice() == request_hash {
                Ok(ClientAccessPolicyBindingOutcome::Bound {
                    binding_id,
                    replayed: true,
                })
            } else {
                Err(ClientAccessPolicyError::Conflict)
            };
        }
        sqlx::query(
            "INSERT INTO client_access_policy_bindings (id, organization_id, tenant_id, user_id, client_device_id, policy_id, request_id, request_hash, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(client_device_id)
        .bind(policy_id)
        .bind(request_id)
        .bind(request_hash.as_slice())
        .bind(actor_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::Conflict)?;
        let binding_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM client_access_policy_bindings WHERE tenant_id = ? AND request_id = ?",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        sqlx::query(
            "INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, ?, 'HUMAN', ?, 'CLIENT_ACCESS_POLICY_BOUND', 'CLIENT_ACCESS_POLICY', ?, JSON_OBJECT('client_device_id', ?, 'user_id', ?))",
        )
        .bind(Uuid::now_v7())
        .bind(organization_id)
        .bind(tenant_id)
        .bind(actor_id.to_string())
        .bind(policy_id.to_string())
        .bind(client_device_id.to_string())
        .bind(user_id.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        transaction
            .commit()
            .await
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        Ok(ClientAccessPolicyBindingOutcome::Bound {
            binding_id,
            replayed: false,
        })
    }

    pub async fn bound_policy(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        client_device_id: Uuid,
    ) -> Result<Option<ClientAccessPolicy>, ClientAccessPolicyError> {
        Ok(self
            .authorization_snapshot(organization_id, tenant_id, user_id, client_device_id)
            .await?
            .map(|snapshot| snapshot.policy))
    }

    pub async fn authorization_snapshot(
        &self,
        organization_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        client_device_id: Uuid,
    ) -> Result<Option<ClientAuthorizationSnapshot>, ClientAccessPolicyError> {
        if [organization_id, tenant_id, user_id, client_device_id]
            .into_iter()
            .any(|id| id.is_nil())
        {
            return Err(ClientAccessPolicyError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT device.organization_id AS organization_id, device.tenant_id AS tenant_id, device.user_id AS user_id, device.id AS client_device_id, device.generation AS device_generation, device.platform AS platform, device_key.device_key_id AS device_key_id, device_key.public_key AS public_key, policy.id AS policy_id, policy.generation AS policy_generation, policy.content_hash AS policy_content_hash, CAST(policy.policy_json AS CHAR) AS policy_json FROM client_devices device JOIN client_device_keys device_key ON device_key.client_device_id = device.id AND device_key.organization_id = device.organization_id AND device_key.tenant_id = device.tenant_id AND device_key.user_id = device.user_id AND device_key.status = 'ACTIVE' JOIN client_access_policy_bindings binding ON binding.client_device_id = device.id AND binding.organization_id = device.organization_id AND binding.tenant_id = device.tenant_id AND binding.user_id = device.user_id JOIN client_access_policies policy ON policy.id = binding.policy_id AND policy.organization_id = binding.organization_id AND policy.tenant_id = binding.tenant_id AND policy.status = 'ACTIVE' JOIN tenants tenant ON tenant.id = device.tenant_id AND tenant.organization_id = device.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = device.organization_id AND organization.status = 'ACTIVE' JOIN human_users user ON user.id = device.user_id AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = device.organization_id AND membership.user_id = device.user_id AND membership.status = 'ACTIVE' WHERE device.organization_id = ? AND device.tenant_id = ? AND device.user_id = ? AND device.id = ? AND device.status = 'ACTIVE'",
        )
        .bind(organization_id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(client_device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let Some(row) = row else {
            return Ok(None);
        };

        let platform: String = row
            .try_get("platform")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let platform = ClientPlatform::from_database_value(&platform)
            .ok_or(ClientAccessPolicyError::InvalidRecord)?;
        let public_key: Vec<u8> = row
            .try_get("public_key")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let public_key = fixed_hash::<32>(&public_key)?;
        let policy_content_hash: Vec<u8> = row
            .try_get("policy_content_hash")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let policy_content_hash = fixed_hash::<32>(&policy_content_hash)?;
        let policy_json: String = row
            .try_get("policy_json")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let policy: ClientAccessPolicy = serde_json::from_str(&policy_json)
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let snapshot = ClientAuthorizationSnapshot {
            organization_id: row
                .try_get("organization_id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            user_id: row
                .try_get("user_id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            client_device_id: row
                .try_get("client_device_id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            device_key_id: row
                .try_get("device_key_id")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            platform,
            device_generation: row
                .try_get("device_generation")
                .map_err(|_| ClientAccessPolicyError::InvalidRecord)?,
            public_key,
            policy,
            policy_content_hash,
        };
        let policy_id: Uuid = row
            .try_get("policy_id")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        let policy_generation: u64 = row
            .try_get("policy_generation")
            .map_err(|_| ClientAccessPolicyError::InvalidRecord)?;
        if snapshot.policy.policy_id != policy_id || snapshot.policy.generation != policy_generation
        {
            return Err(ClientAccessPolicyError::InvalidRecord);
        }
        snapshot.validate()?;
        Ok(Some(snapshot))
    }
}

fn fixed_hash<const N: usize>(value: &[u8]) -> Result<[u8; N], ClientAccessPolicyError> {
    value
        .try_into()
        .map_err(|_| ClientAccessPolicyError::InvalidRecord)
}

fn request_fingerprint(
    policy: &ClientAccessPolicy,
    organization_id: Uuid,
    actor_id: Uuid,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-access-policy/v1\0");
    hash.update(organization_id.as_bytes());
    hash.update(actor_id.as_bytes());
    hash.update(serde_json::to_vec(policy).expect("validated policy serializes"));
    hash.finalize().into()
}

fn binding_fingerprint(
    policy_id: Uuid,
    organization_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    client_device_id: Uuid,
    actor_id: Uuid,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy/terminal-client-access-policy-binding/v1\0");
    for id in [
        policy_id,
        organization_id,
        tenant_id,
        user_id,
        client_device_id,
        actor_id,
    ] {
        hash.update(id.as_bytes());
    }
    hash.finalize().into()
}

fn hex_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
