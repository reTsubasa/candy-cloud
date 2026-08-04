use candy_proto::{
    cloud_grant::{
        AccessGrantPayloadV1, DeviceId, DeviceKeyId, EnvironmentId, GrantId, IssuerId, NodePoolId,
        OperatorScopeType, OrganizationId, PolicyId, PolicyRefV1, ServiceClass as CoreServiceClass,
        SubscriptionId, TenantId,
    },
    features::FeatureSet,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    domain::{AuthorizationSnapshot, DomainError, GrantRequest, ServiceClass, MAX_REQUEST_ID_LEN},
    grants::{GrantIssueError, GrantSigner, IssuedGrant},
};

pub const PERMISSION_PRIVATE_CONNECT: u64 = 1 << 0;
pub const PERMISSION_PRIVATE_TUN_CONNECT: u64 = 1 << 1;
const REQUIRED_TUN_FEATURES: u64 = FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantQuota {
    pub allowed_features: u64,
    pub max_outer_connections_per_node: u64,
    pub max_outer_connections_per_pool: u64,
    pub max_active_sessions_per_connection: u64,
    pub max_udp_flows_per_connection: u64,
    pub max_pending_opens: u64,
    pub max_speculative_streams: u64,
    pub max_datagram_record: u64,
    pub upload_rate_bps: u64,
    pub download_rate_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateGrantMaterial {
    pub organization_id: Uuid,
    pub subscription_id: Uuid,
    pub device_key_id: Uuid,
    pub device_public_key: [u8; 32],
    pub assurance_level: u64,
    pub route_policy: Option<RoutePolicyBinding>,
    pub snapshot: AuthorizationSnapshot,
    pub quota: GrantQuota,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicyBinding {
    pub tenant_id: Uuid,
    pub segment_id: Uuid,
    pub attachment_id: Uuid,
    pub site_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub node_pool_id: Uuid,
    pub projection_id: Uuid,
    pub projection_generation: u64,
    pub projection_content_hash: [u8; 32],
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerConfig {
    pub issuer_id: Uuid,
    pub environment_id: Uuid,
}

pub struct PreparedGrant {
    pub grant_id: Uuid,
    pub authorization_generation: u64,
    pub request_fingerprint: [u8; 32],
    pub expires_at: u64,
    pub issued: IssuedGrant,
}

#[derive(Debug, thiserror::Error)]
pub enum PrepareGrantError {
    #[error("authorization denied")]
    Authorization(#[from] DomainError),
    #[error("unsupported service permission")]
    UnsupportedPermission,
    #[error("only private service is supported by this issuer")]
    UnsupportedServiceClass,
    #[error("TUN Grant requires a unique current route projection")]
    MissingRoutePolicy,
    #[error("TUN Grant route projection does not match the authorization snapshot")]
    RoutePolicyMismatch,
    #[error("TUN Grant quota lacks DATAGRAM or IP packet tunnel features")]
    MissingTunnelFeatures,
    #[error("Grant signing failed")]
    Signing(#[from] GrantIssueError),
}

pub fn prepare_private_grant(
    signer: &GrantSigner,
    issuer: &IssuerConfig,
    request_id: &str,
    request: &GrantRequest,
    material: &PrivateGrantMaterial,
    issued_at: u64,
) -> Result<PreparedGrant, PrepareGrantError> {
    prepare_private_grant_with_id(
        signer,
        issuer,
        Uuid::new_v4(),
        request_id,
        request,
        material,
        issued_at,
    )
}

pub fn prepare_private_grant_with_id(
    signer: &GrantSigner,
    issuer: &IssuerConfig,
    grant_id: Uuid,
    request_id: &str,
    request: &GrantRequest,
    material: &PrivateGrantMaterial,
    issued_at: u64,
) -> Result<PreparedGrant, PrepareGrantError> {
    if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_LEN {
        return Err(PrepareGrantError::Authorization(
            DomainError::InvalidRequestId,
        ));
    }
    material.snapshot.authorize(request)?;
    if material.device_key_id != request.device_key_id {
        return Err(PrepareGrantError::Authorization(
            DomainError::OperationalKeyMismatch,
        ));
    }
    if request.service_class != ServiceClass::Private {
        return Err(PrepareGrantError::UnsupportedServiceClass);
    }
    let (service_permissions, is_tun) = permission_bits(&request.service_permission)?;
    let route_policy = if is_tun {
        let binding = material
            .route_policy
            .as_ref()
            .ok_or(PrepareGrantError::MissingRoutePolicy)?;
        if binding.tenant_id != request.tenant_id
            || binding.device_id != request.device_id
            || binding.device_key_id != request.device_key_id
            || binding.node_pool_id != request.node_pool_id
            || binding.segment_id.is_nil()
            || binding.attachment_id.is_nil()
            || binding.site_id.is_nil()
            || binding.projection_id.is_nil()
            || binding.projection_generation == 0
            || binding.projection_content_hash == [0; 32]
            || binding.segment_generation == 0
            || binding.segment_content_hash == [0; 32]
        {
            return Err(PrepareGrantError::RoutePolicyMismatch);
        }
        if material.quota.allowed_features & REQUIRED_TUN_FEATURES != REQUIRED_TUN_FEATURES {
            return Err(PrepareGrantError::MissingTunnelFeatures);
        }
        Some(PolicyRefV1 {
            policy_id: PolicyId(*binding.projection_id.as_bytes()),
            generation: binding.projection_generation,
            content_hash: binding.projection_content_hash,
        })
    } else {
        None
    };
    let payload = AccessGrantPayloadV1 {
        grant_id: GrantId(*grant_id.as_bytes()),
        issuer_id: IssuerId(*issuer.issuer_id.as_bytes()),
        environment_id: EnvironmentId(*issuer.environment_id.as_bytes()),
        organization_id: OrganizationId(*material.organization_id.as_bytes()),
        tenant_id: TenantId(*request.tenant_id.as_bytes()),
        subscription_id: SubscriptionId(*material.subscription_id.as_bytes()),
        device_id: DeviceId(*request.device_id.as_bytes()),
        device_key_id: DeviceKeyId(*material.device_key_id.as_bytes()),
        device_public_key: material.device_public_key,
        assurance_level: material.assurance_level,
        node_pool_id: NodePoolId(*request.node_pool_id.as_bytes()),
        service_class: CoreServiceClass::CustomerPrivate,
        operator_scope_type: OperatorScopeType::Customer,
        operator_id: None,
        region_ids: Vec::new(),
        allowed_features: FeatureSet::from_bits(material.quota.allowed_features),
        service_permissions,
        route_policy,
        dns_policy: None,
        max_outer_connections_per_node: material.quota.max_outer_connections_per_node,
        max_outer_connections_per_pool: material.quota.max_outer_connections_per_pool,
        max_active_sessions_per_connection: material.quota.max_active_sessions_per_connection,
        max_udp_flows_per_connection: material.quota.max_udp_flows_per_connection,
        max_pending_opens: material.quota.max_pending_opens,
        max_speculative_streams: material.quota.max_speculative_streams,
        max_datagram_record: material.quota.max_datagram_record,
        upload_rate_bps: material.quota.upload_rate_bps,
        download_rate_bps: material.quota.download_rate_bps,
        issued_at: 0,
        not_before: 0,
        refresh_after: 0,
        expires_at: 0,
        policy_generation: material.snapshot.policy_generation,
        entitlement_generation: material.snapshot.entitlement.generation,
    };
    let issued = signer.issue_private(payload, issued_at)?;
    let request_fingerprint = request_fingerprint(
        request_id,
        request,
        material.snapshot.authorization_generation,
    );
    let expires_at = issued_at + crate::grants::PRIVATE_GRANT_TTL_SECS;
    Ok(PreparedGrant {
        grant_id,
        authorization_generation: material.snapshot.authorization_generation,
        request_fingerprint,
        expires_at,
        issued,
    })
}

fn permission_bits(permission: &str) -> Result<(u64, bool), PrepareGrantError> {
    match permission {
        "private.connect" => Ok((PERMISSION_PRIVATE_CONNECT, false)),
        "private.tun.connect" => Ok((PERMISSION_PRIVATE_TUN_CONNECT, true)),
        _ => Err(PrepareGrantError::UnsupportedPermission),
    }
}

fn request_fingerprint(
    request_id: &str,
    request: &GrantRequest,
    authorization_generation: u64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"candy-cloud/grant-request/v1");
    hash.update((request_id.len() as u64).to_be_bytes());
    hash.update(request_id.as_bytes());
    hash.update(request.tenant_id.as_bytes());
    hash.update(request.device_id.as_bytes());
    hash.update(request.device_key_id.as_bytes());
    hash.update(request.node_pool_id.as_bytes());
    hash.update([match request.service_class {
        ServiceClass::Private => 1,
        ServiceClass::CandyShared => 2,
        ServiceClass::CandyDedicated => 3,
        ServiceClass::Partner => 4,
    }]);
    hash.update((request.service_permission.len() as u64).to_be_bytes());
    hash.update(request.service_permission.as_bytes());
    hash.update(authorization_generation.to_be_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{DeviceStatus, EntitlementSnapshot, SnapshotDevice, SnapshotStatus};
    use ed25519_dalek::SigningKey;

    fn fixture() -> (GrantRequest, PrivateGrantMaterial) {
        let tenant_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let device_key_id = Uuid::new_v4();
        let node_pool_id = Uuid::new_v4();
        let request = GrantRequest {
            tenant_id,
            device_id,
            device_key_id,
            node_pool_id,
            service_class: ServiceClass::Private,
            service_permission: "private.connect".into(),
        };
        let material = PrivateGrantMaterial {
            organization_id: Uuid::new_v4(),
            subscription_id: Uuid::new_v4(),
            device_key_id,
            device_public_key: [8; 32],
            assurance_level: 2,
            route_policy: None,
            snapshot: AuthorizationSnapshot {
                tenant_id,
                authorization_generation: 7,
                device: SnapshotDevice {
                    id: device_id,
                    tenant_id,
                    status: DeviceStatus::Active,
                },
                subscription_status: SnapshotStatus::Active,
                entitlement: EntitlementSnapshot {
                    id: Uuid::new_v4(),
                    tenant_id,
                    node_pool_id,
                    service_class: ServiceClass::Private,
                    service_permission: "private.connect".into(),
                    status: SnapshotStatus::Active,
                    generation: 5,
                },
                policy_generation: 4,
                revocation_generation: 3,
            },
            quota: GrantQuota {
                allowed_features: 0,
                max_outer_connections_per_node: 2,
                max_outer_connections_per_pool: 4,
                max_active_sessions_per_connection: 128,
                max_udp_flows_per_connection: 256,
                max_pending_opens: 32,
                max_speculative_streams: 8,
                max_datagram_record: 1200,
                upload_rate_bps: 10_000_000,
                download_rate_bps: 20_000_000,
            },
        };
        (request, material)
    }

    #[test]
    fn prepares_core_grant_from_one_authorization_snapshot() {
        let (request, material) = fixture();
        let signer = GrantSigner::new("k1", SigningKey::from_bytes(&[3; 32]));
        let prepared = prepare_private_grant(
            &signer,
            &IssuerConfig {
                issuer_id: Uuid::new_v4(),
                environment_id: Uuid::new_v4(),
            },
            "request-1",
            &request,
            &material,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(prepared.authorization_generation, 7);
        assert_eq!(prepared.expires_at, 1_800_086_400);
        assert_ne!(prepared.request_fingerprint, [0; 32]);
    }

    #[test]
    fn rejects_unregistered_permission_before_signing() {
        let (mut request, mut material) = fixture();
        request.service_permission = "private.anything".into();
        material.snapshot.entitlement.service_permission = "private.anything".into();
        let signer = GrantSigner::new("k1", SigningKey::from_bytes(&[3; 32]));
        assert!(matches!(
            prepare_private_grant(
                &signer,
                &IssuerConfig {
                    issuer_id: Uuid::new_v4(),
                    environment_id: Uuid::new_v4()
                },
                "request-1",
                &request,
                &material,
                1_800_000_000
            ),
            Err(PrepareGrantError::UnsupportedPermission)
        ));
    }

    #[test]
    fn rejects_empty_idempotency_key() {
        let (request, material) = fixture();
        let signer = GrantSigner::new("k1", SigningKey::from_bytes(&[3; 32]));
        assert!(matches!(
            prepare_private_grant(
                &signer,
                &IssuerConfig {
                    issuer_id: Uuid::new_v4(),
                    environment_id: Uuid::new_v4()
                },
                "",
                &request,
                &material,
                1_800_000_000
            ),
            Err(PrepareGrantError::Authorization(
                DomainError::InvalidRequestId
            ))
        ));
    }

    #[test]
    fn tun_grant_requires_features_and_binds_exact_projection() {
        let (mut request, mut material) = fixture();
        request.service_permission = "private.tun.connect".into();
        material.snapshot.entitlement.service_permission = "private.tun.connect".into();
        material.quota.allowed_features = REQUIRED_TUN_FEATURES;
        let projection_id = Uuid::new_v4();
        material.route_policy = Some(RoutePolicyBinding {
            tenant_id: request.tenant_id,
            segment_id: Uuid::new_v4(),
            attachment_id: Uuid::new_v4(),
            site_id: Uuid::new_v4(),
            device_id: request.device_id,
            device_key_id: request.device_key_id,
            node_pool_id: request.node_pool_id,
            projection_id,
            projection_generation: 9,
            projection_content_hash: [7; 32],
            segment_generation: 4,
            segment_content_hash: [8; 32],
        });
        let signer = GrantSigner::new("k1", SigningKey::from_bytes(&[3; 32]));
        let prepared = prepare_private_grant(
            &signer,
            &IssuerConfig {
                issuer_id: Uuid::new_v4(),
                environment_id: Uuid::new_v4(),
            },
            "request-tun-1",
            &request,
            &material,
            1_800_000_000,
        )
        .unwrap();
        let payload = AccessGrantPayloadV1::decode(&prepared.issued.envelope().payload).unwrap();
        assert!(payload.allowed_features.contains(REQUIRED_TUN_FEATURES));
        assert_eq!(
            payload.route_policy,
            Some(PolicyRefV1 {
                policy_id: PolicyId(*projection_id.as_bytes()),
                generation: 9,
                content_hash: [7; 32],
            })
        );
    }

    #[test]
    fn non_tun_grant_retains_no_route_policy() {
        let (request, material) = fixture();
        let signer = GrantSigner::new("k1", SigningKey::from_bytes(&[3; 32]));
        let prepared = prepare_private_grant(
            &signer,
            &IssuerConfig {
                issuer_id: Uuid::new_v4(),
                environment_id: Uuid::new_v4(),
            },
            "request-proxy-1",
            &request,
            &material,
            1_800_000_000,
        )
        .unwrap();
        let payload = AccessGrantPayloadV1::decode(&prepared.issued.envelope().payload).unwrap();
        assert_eq!(payload.route_policy, None);
    }
}
