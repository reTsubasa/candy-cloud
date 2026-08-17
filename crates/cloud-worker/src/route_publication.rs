use cloud_core_module::{CoreModule, ObjectType};
use cloud_db::sdwan::{
    ExpansionObjectKind, ExpansionObjectPublicationWrite, PublicationOutcome, SdwanError,
    SdwanRepository, SegmentPublicationWrite, SignedObjectWrite, SiteProjectionPublicationWrite,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

use crate::route_types::{
    AttachmentId, AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1,
    DynamicRouteSnapshotV1, HubFabricAssignmentV1, Ipv4PrefixV1, MeshMembershipProjectionV1,
    PacketResourcePolicyV1, PathSelectionPolicyV1, PeerEndpointV1, PeerPathCandidateV1, PolicyId,
    RemoteRouteV1, SegmentAttachmentV1, SegmentId, SegmentRouteSnapshotV1, SegmentRouteV1,
    SharedHubAdmissionPolicyV1, SharedHubQuotaV1, SiteRouteProjectionV1, TenantId,
    TransportNodeIdentityV1,
};

#[derive(Clone)]
pub struct RouteSigner {
    key_id: Vec<u8>,
    signing_key: SigningKey,
    core: Arc<CoreModule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRouteObject<T> {
    pub source: T,
    pub content_hash: [u8; 32],
    pub envelope: Vec<u8>,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

fn policy_ref_json(policy: &crate::route_types::PolicyRefV1) -> Value {
    json!({
        "policy_id_hex": hex(&policy.policy_id.0),
        "generation": policy.generation,
        "content_hash_hex": hex(&policy.content_hash),
    })
}

fn prefix_json(prefix: &Ipv4PrefixV1) -> Value {
    json!({
        "network_hex": hex(&prefix.network),
        "prefix_len": prefix.prefix_len,
    })
}

fn principal_json(principal: &AttachmentPrincipalV1) -> Value {
    match principal {
        AttachmentPrincipalV1::Device {
            device_id,
            device_key_id,
        } => json!({
            "principal_type": "device",
            "device_id_hex": hex(&device_id.0),
            "device_key_id_hex": hex(&device_key_id.0),
        }),
        AttachmentPrincipalV1::Node {
            node_id,
            node_key_id,
        } => json!({
            "principal_type": "node",
            "node_id_hex": hex(&node_id.0),
            "node_key_id_hex": hex(&node_key_id.0),
        }),
    }
}

fn attachment_json(attachment: &SegmentAttachmentV1) -> Value {
    json!({
        "attachment_id_hex": hex(&attachment.attachment_id.0),
        "site_id_hex": attachment.site_id.map(|id| hex(&id.0)),
        "principal": principal_json(&attachment.principal),
        "overlay_router_ipv4_hex": hex(&attachment.overlay_router_ipv4),
        "local_prefixes": attachment.local_prefixes.iter().map(prefix_json).collect::<Vec<_>>(),
        "state": attachment.state as u64,
        "epoch_floor": attachment.epoch_floor,
    })
}

fn route_json(route: &SegmentRouteV1) -> Value {
    json!({
        "destination_prefix": prefix_json(&route.destination_prefix),
        "owner_site_id_hex": route.owner_site_id.map(|id| hex(&id.0)),
        "owner_attachment_ids_hex": route.owner_attachment_ids.iter().map(|id| hex(&id.0)).collect::<Vec<_>>(),
    })
}

fn segment_snapshot_json(object: &SegmentRouteSnapshotV1) -> Value {
    json!({
        "object_type": "segment_snapshot_v1",
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "segment_generation": object.segment_generation,
        "segment_overlay_prefix": prefix_json(&object.segment_overlay_prefix),
        "attachments": object.attachments.iter().map(attachment_json).collect::<Vec<_>>(),
        "routes": object.routes.iter().map(route_json).collect::<Vec<_>>(),
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "previous_hash_hex": hex(&object.previous_hash),
    })
}

fn endpoint_json(endpoint: &PeerEndpointV1) -> Value {
    match endpoint {
        PeerEndpointV1::Ipv4 { address, port } => json!({
            "address_family": "ipv4",
            "address_hex": hex(address),
            "port": port,
        }),
        PeerEndpointV1::Ipv6 { address, port } => json!({
            "address_family": "ipv6",
            "address_hex": hex(address),
            "port": port,
        }),
    }
}

fn peer_path_json(path: &PeerPathCandidateV1) -> Value {
    json!({
        "candidate_id_hex": hex(&path.candidate_id.0),
        "peer_site_id_hex": hex(&path.peer_site_id.0),
        "peer_attachment_id_hex": hex(&path.peer_attachment_id.0),
        "kind": path.kind as u64,
        "relay_node": path.relay_node.as_ref().map(|node| json!({
            "node_id_hex": hex(&node.node_id.0),
            "node_key_id_hex": hex(&node.node_key_id.0),
        })),
        "node_pool_id_hex": hex(&path.node_pool_id.0),
        "transport_node": {
            "node_id_hex": hex(&path.transport_node.node_id.0),
            "node_key_id_hex": hex(&path.transport_node.node_key_id.0),
        },
        "endpoint": endpoint_json(&path.endpoint),
        "server_name": path.server_name,
        "server_cert_sha256_hex": hex(&path.server_cert_sha256),
        "transport_preset": path.transport_preset as u64,
        "priority": path.priority,
        "authorization": policy_ref_json(&path.authorization),
    })
}

fn remote_route_json(route: &RemoteRouteV1) -> Value {
    json!({
        "destination_prefix": prefix_json(&route.destination_prefix),
        "owner_site_id_hex": hex(&route.owner_site_id.0),
        "owner_attachment_ids_hex": route.owner_attachment_ids.iter().map(|id| hex(&id.0)).collect::<Vec<_>>(),
    })
}

fn site_projection_json(object: &SiteRouteProjectionV1) -> Value {
    let manifest = &object.coherent_manifest;
    let resources = &object.resources;
    json!({
        "object_type": "site_projection_v1",
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "segment_generation": object.segment_generation,
        "segment_content_hash_hex": hex(&object.segment_content_hash),
        "site_id_hex": hex(&object.site_id.0),
        "attachment_id_hex": hex(&object.attachment_id.0),
        "device_id_hex": hex(&object.device_id.0),
        "device_key_id_hex": hex(&object.device_key_id.0),
        "local_transport_node": object.local_transport_node.as_ref().map(|node| json!({
            "node_id_hex": hex(&node.node_id.0),
            "node_key_id_hex": hex(&node.node_key_id.0),
        })),
        "overlay_router_ipv4_hex": hex(&object.overlay_router_ipv4),
        "local_prefixes": object.local_prefixes.iter().map(prefix_json).collect::<Vec<_>>(),
        "remote_routes": object.remote_routes.iter().map(remote_route_json).collect::<Vec<_>>(),
        "path_policy": object.path_policy as u64,
        "peer_paths": object.peer_paths.iter().map(peer_path_json).collect::<Vec<_>>(),
        "coherent_manifest": {
            "generation": manifest.generation,
            "dns_projection": manifest.dns_projection.as_ref().map(policy_ref_json),
            "egress_authorization": manifest.egress_authorization.as_ref().map(policy_ref_json),
        },
        "max_inner_mtu": object.max_inner_mtu,
        "resources": {
            "max_route_prefixes": resources.max_route_prefixes,
            "max_queue_packets": resources.max_queue_packets,
            "max_queue_bytes": resources.max_queue_bytes,
            "replay_window_packets": resources.replay_window_packets,
            "max_packets_per_second": resources.max_packets_per_second,
            "max_bytes_per_second": resources.max_bytes_per_second,
            "allowed_traffic_classes": resources.allowed_traffic_classes,
        },
        "epoch_floor": object.epoch_floor,
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "projection_id_hex": hex(&object.projection_id.0),
        "projection_generation": object.projection_generation,
        "previous_hash_hex": hex(&object.previous_hash),
    })
}

fn quota_json(quota: &SharedHubQuotaV1) -> Value {
    json!({
        "max_entities": quota.max_entities,
        "max_queue_packets": quota.max_queue_packets,
        "max_queue_bytes": quota.max_queue_bytes,
        "packets_per_second": quota.packets_per_second,
        "bytes_per_second": quota.bytes_per_second,
        "burst_packets": quota.burst_packets,
        "burst_bytes": quota.burst_bytes,
    })
}

fn shared_hub_admission_json(object: &SharedHubAdmissionPolicyV1) -> Value {
    json!({
        "object_type": "shared_hub_admission_v1",
        "node_id_hex": hex(&object.node_id.0),
        "node_key_id_hex": hex(&object.node_key_id.0),
        "node_pool_id_hex": hex(&object.node_pool_id.0),
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "segment_generation": object.segment_generation,
        "segment_content_hash_hex": hex(&object.segment_content_hash),
        "policy_id_hex": hex(&object.policy_id.0),
        "policy_generation": object.policy_generation,
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "previous_hash_hex": hex(&object.previous_hash),
        "node": quota_json(&object.node),
        "tenant": quota_json(&object.tenant),
        "site": quota_json(&object.site),
        "tunnel": quota_json(&object.tunnel),
    })
}

fn mesh_membership_json(object: &MeshMembershipProjectionV1) -> Value {
    json!({
        "object_type": "mesh_membership_v1",
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "segment_generation": object.segment_generation,
        "segment_content_hash_hex": hex(&object.segment_content_hash),
        "local_site_id_hex": hex(&object.local_site_id.0),
        "local_attachment_id_hex": hex(&object.local_attachment_id.0),
        "peers": object.peers.iter().map(|peer| json!({
            "site_id_hex": hex(&peer.site_id.0),
            "attachment_id_hex": hex(&peer.attachment_id.0),
            "epoch_floor": peer.epoch_floor,
        })).collect::<Vec<_>>(),
        "projection_id_hex": hex(&object.projection_id.0),
        "projection_generation": object.projection_generation,
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "previous_hash_hex": hex(&object.previous_hash),
    })
}

fn dynamic_route_snapshot_json(object: &DynamicRouteSnapshotV1) -> Value {
    json!({
        "object_type": "dynamic_route_snapshot_v1",
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "base_segment_generation": object.base_segment_generation,
        "base_segment_content_hash_hex": hex(&object.base_segment_content_hash),
        "routes": object.routes.iter().map(|route| json!({
            "prefix": prefix_json(&route.prefix),
            "owner_site_id_hex": hex(&route.owner_site_id.0),
            "owner_attachment_id_hex": hex(&route.owner_attachment_id.0),
            "metric": route.metric,
        })).collect::<Vec<_>>(),
        "policy_id_hex": hex(&object.policy_id.0),
        "generation": object.generation,
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "previous_hash_hex": hex(&object.previous_hash),
    })
}

fn fabric_assignment_json(object: &HubFabricAssignmentV1) -> Value {
    json!({
        "object_type": "fabric_assignment_v1",
        "tenant_id_hex": hex(&object.tenant_id.0),
        "segment_id_hex": hex(&object.segment_id.0),
        "segment_generation": object.segment_generation,
        "segment_content_hash_hex": hex(&object.segment_content_hash),
        "assignments": object.assignments.iter().map(|assignment| json!({
            "site_id_hex": hex(&assignment.site_id.0),
            "attachment_id_hex": hex(&assignment.attachment_id.0),
            "hub_node_id_hex": hex(&assignment.hub_node_id.0),
            "hub_node_key_id_hex": hex(&assignment.hub_node_key_id.0),
            "hub_attachment_id_hex": hex(&assignment.hub_attachment_id.0),
            "attachment_epoch": assignment.attachment_epoch,
        })).collect::<Vec<_>>(),
        "policy_id_hex": hex(&object.policy_id.0),
        "generation": object.generation,
        "not_before": object.not_before,
        "expires_at": object.expires_at,
        "stale_until": object.stale_until,
        "previous_hash_hex": hex(&object.previous_hash),
    })
}

fn module_seal<T>(
    core: &CoreModule,
    key_id: &[u8],
    signing_key: &SigningKey,
    object_type: ObjectType,
    source: T,
    object: Value,
) -> Result<SealedRouteObject<T>, RoutePublicationError> {
    let request = json!({
        "schema": "candy-core-cloud-build-v1",
        "signing_key_id_hex": hex(key_id),
        "object": object,
    });
    let request = serde_json::to_vec(&request)
        .map_err(|error| RoutePublicationError::Core(error.to_string()))?;
    let prepared = core
        .prepare(&request)
        .map_err(|error| RoutePublicationError::Core(error.to_string()))?;
    if prepared.object_type != object_type {
        return Err(RoutePublicationError::Core(format!(
            "Core returned object type {}, expected {}",
            prepared.object_type.0, object_type.0
        )));
    }
    let signature = ed25519_dalek::Signer::sign(signing_key, &prepared.signing_transcript);
    let content_hash = core
        .route_content_hash(object_type, &prepared.payload)
        .map_err(|error| RoutePublicationError::Core(error.to_string()))?;
    let raw = core
        .assemble(
            object_type,
            key_id,
            &prepared.payload,
            &signature.to_bytes(),
        )
        .map_err(|error| RoutePublicationError::Core(error.to_string()))?;
    let public_key = signing_key.verifying_key().to_bytes();
    core.validate(ObjectType::ROUTE_ENVELOPE_V1, &raw, Some(&public_key))
        .map_err(|error| RoutePublicationError::Core(error.to_string()))?;
    Ok(SealedRouteObject {
        source,
        content_hash,
        envelope: raw,
    })
}

impl RouteSigner {
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey, core: Arc<CoreModule>) -> Self {
        Self {
            key_id: key_id.into().into_bytes(),
            signing_key,
            core,
        }
    }

    pub fn ready(&self) -> bool {
        !self.key_id.is_empty() && self.key_id.len() <= 64
    }

    fn sign_segment_snapshot(
        &self,
        object: SegmentRouteSnapshotV1,
    ) -> Result<SealedRouteObject<SegmentRouteSnapshotV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::SEGMENT_SNAPSHOT_V1,
            object.clone(),
            segment_snapshot_json(&object),
        )
    }

    fn sign_site_projection(
        &self,
        object: SiteRouteProjectionV1,
    ) -> Result<SealedRouteObject<SiteRouteProjectionV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::SITE_PROJECTION_V1,
            object.clone(),
            site_projection_json(&object),
        )
    }

    pub fn sign_shared_hub_admission(
        &self,
        policy: SharedHubAdmissionPolicyV1,
    ) -> Result<SealedRouteObject<SharedHubAdmissionPolicyV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::SHARED_HUB_ADMISSION_V1,
            policy.clone(),
            shared_hub_admission_json(&policy),
        )
    }

    pub fn sign_mesh_membership(
        &self,
        projection: MeshMembershipProjectionV1,
    ) -> Result<SealedRouteObject<MeshMembershipProjectionV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::MESH_MEMBERSHIP_V1,
            projection.clone(),
            mesh_membership_json(&projection),
        )
    }

    pub fn sign_dynamic_route_snapshot(
        &self,
        snapshot: DynamicRouteSnapshotV1,
    ) -> Result<SealedRouteObject<DynamicRouteSnapshotV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::DYNAMIC_ROUTE_SNAPSHOT_V1,
            snapshot.clone(),
            dynamic_route_snapshot_json(&snapshot),
        )
    }

    pub fn sign_fabric_assignment(
        &self,
        assignment: HubFabricAssignmentV1,
    ) -> Result<SealedRouteObject<HubFabricAssignmentV1>, RoutePublicationError> {
        module_seal(
            &self.core,
            self.key_id.as_slice(),
            &self.signing_key,
            ObjectType::FABRIC_ASSIGNMENT_V1,
            assignment.clone(),
            fabric_assignment_json(&assignment),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProjectionInput {
    pub publication_id: Uuid,
    pub attachment_id: AttachmentId,
    pub projection_id: PolicyId,
    pub projection_generation: u64,
    pub previous_hash: [u8; 32],
    pub local_transport_node: Option<TransportNodeIdentityV1>,
    pub path_policy: PathSelectionPolicyV1,
    pub peer_paths: Vec<PeerPathCandidateV1>,
    pub coherent_manifest: CoherentPolicyManifestV1,
    pub max_inner_mtu: u16,
    pub resources: PacketResourcePolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePublicationInput {
    pub publication_id: Uuid,
    pub audit_event_id: Uuid,
    pub actor_id: String,
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub generation: u64,
    pub previous_hash: [u8; 32],
    pub segment_overlay_prefix: Ipv4PrefixV1,
    pub attachments: Vec<SegmentAttachmentV1>,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub projections: Vec<DeviceProjectionInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltDeviceProjection {
    pub publication_id: Uuid,
    pub sealed: SealedRouteObject<SiteRouteProjectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltRoutePublication {
    pub publication_id: Uuid,
    pub audit_event_id: Uuid,
    pub actor_id: String,
    pub segment: SealedRouteObject<SegmentRouteSnapshotV1>,
    pub projections: Vec<BuiltDeviceProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltExpansionPublication {
    SharedHub {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<SharedHubAdmissionPolicyV1>>,
    },
    Mesh {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<MeshMembershipProjectionV1>>,
    },
    DynamicRoute {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<DynamicRouteSnapshotV1>>,
    },
    FabricAssignment {
        publication_id: Uuid,
        sealed: Box<SealedRouteObject<HubFabricAssignmentV1>>,
    },
}

impl BuiltRoutePublication {
    pub fn database_write(&self) -> Result<SegmentPublicationWrite, RoutePublicationError> {
        self.database_write_with_expansions(&[])
    }

    pub fn database_write_with_expansions(
        &self,
        expansions: &[BuiltExpansionPublication],
    ) -> Result<SegmentPublicationWrite, RoutePublicationError> {
        let generation = self.segment.source.segment_generation;
        let expected_previous_generation = generation
            .checked_sub(1)
            .ok_or(RoutePublicationError::InvalidGeneration)?;
        Ok(SegmentPublicationWrite {
            publication_id: self.publication_id,
            tenant_id: uuid(self.segment.source.tenant_id.0),
            segment_id: uuid(self.segment.source.segment_id.0),
            expected_previous_generation,
            expected_previous_hash: self.segment.source.previous_hash,
            generation,
            snapshot: SignedObjectWrite {
                content_hash: self.segment.content_hash,
                signed_envelope: self.segment.envelope.clone(),
            },
            projections: self
                .projections
                .iter()
                .map(|built| {
                    let projection = &built.sealed.source;
                    Ok(SiteProjectionPublicationWrite {
                        publication_id: built.publication_id,
                        projection_id: uuid(projection.projection_id.0),
                        tenant_id: uuid(projection.tenant_id.0),
                        segment_id: uuid(projection.segment_id.0),
                        site_id: uuid(projection.site_id.0),
                        attachment_id: uuid(projection.attachment_id.0),
                        device_id: uuid(projection.device_id.0),
                        device_key_id: uuid(projection.device_key_id.0),
                        segment_generation: projection.segment_generation,
                        segment_content_hash: projection.segment_content_hash,
                        projection_generation: projection.projection_generation,
                        previous_hash: projection.previous_hash,
                        object: SignedObjectWrite {
                            content_hash: built.sealed.content_hash,
                            signed_envelope: built.sealed.envelope.clone(),
                        },
                        transport_nodes: {
                            let mut nodes = projection
                                .peer_paths
                                .iter()
                                .map(|path| {
                                    (
                                        uuid(path.transport_node.node_id.0),
                                        uuid(path.transport_node.node_key_id.0),
                                    )
                                })
                                .collect::<Vec<_>>();
                            nodes.sort_unstable();
                            nodes.dedup();
                            nodes
                        },
                    })
                })
                .collect::<Result<Vec<_>, RoutePublicationError>>()?,
            expansions: expansions
                .iter()
                .map(|expansion| self.expansion_write(expansion))
                .collect::<Result<Vec<_>, RoutePublicationError>>()?,
            audit_event_id: self.audit_event_id,
            actor_id: self.actor_id.clone(),
        })
    }

    fn expansion_write(
        &self,
        expansion: &BuiltExpansionPublication,
    ) -> Result<ExpansionObjectPublicationWrite, RoutePublicationError> {
        let segment = &self.segment.source;
        let (
            publication_id,
            kind,
            policy_id,
            generation,
            tenant_id,
            segment_id,
            segment_generation,
            segment_content_hash,
            site_id,
            attachment_id,
            content_hash,
            signed_envelope,
        ) = match expansion {
            BuiltExpansionPublication::SharedHub {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::SharedHubAdmission,
                sealed.source.policy_id,
                sealed.source.policy_generation,
                sealed.source.tenant_id,
                sealed.source.segment_id,
                sealed.source.segment_generation,
                sealed.source.segment_content_hash,
                None,
                None,
                sealed.content_hash,
                sealed.envelope.clone(),
            ),
            BuiltExpansionPublication::Mesh {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::MeshMembership,
                sealed.source.projection_id,
                sealed.source.projection_generation,
                sealed.source.tenant_id,
                sealed.source.segment_id,
                sealed.source.segment_generation,
                sealed.source.segment_content_hash,
                Some(sealed.source.local_site_id),
                Some(sealed.source.local_attachment_id),
                sealed.content_hash,
                sealed.envelope.clone(),
            ),
            BuiltExpansionPublication::DynamicRoute {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::DynamicRouteSnapshot,
                sealed.source.policy_id,
                sealed.source.generation,
                sealed.source.tenant_id,
                sealed.source.segment_id,
                sealed.source.base_segment_generation,
                sealed.source.base_segment_content_hash,
                None,
                None,
                sealed.content_hash,
                sealed.envelope.clone(),
            ),
            BuiltExpansionPublication::FabricAssignment {
                publication_id,
                sealed,
            } => (
                *publication_id,
                ExpansionObjectKind::FabricAssignment,
                sealed.source.policy_id,
                sealed.source.generation,
                sealed.source.tenant_id,
                sealed.source.segment_id,
                sealed.source.segment_generation,
                sealed.source.segment_content_hash,
                None,
                None,
                sealed.content_hash,
                sealed.envelope.clone(),
            ),
        };
        if publication_id.is_nil()
            || tenant_id != segment.tenant_id
            || segment_id != segment.segment_id
            || segment_generation != segment.segment_generation
            || segment_content_hash != self.segment.content_hash
        {
            return Err(RoutePublicationError::ExpansionScopeMismatch);
        }
        Ok(ExpansionObjectPublicationWrite {
            publication_id,
            kind,
            policy_id: uuid(policy_id.0),
            tenant_id: uuid(tenant_id.0),
            segment_id: uuid(segment_id.0),
            generation,
            segment_generation,
            segment_content_hash,
            site_id: site_id.map(|id| uuid(id.0)),
            attachment_id: attachment_id.map(|id| uuid(id.0)),
            object: SignedObjectWrite {
                content_hash,
                signed_envelope,
            },
        })
    }
}

#[derive(Debug, Error)]
pub enum RoutePublicationError {
    #[error("publication generation is invalid")]
    InvalidGeneration,
    #[error("a route owner is not ACTIVE")]
    InactiveOwner,
    #[error("route ownership overlaps across Sites")]
    OverlappingOwnership,
    #[error("every active DeviceAttachment requires exactly one projection")]
    IncompleteProjectionSet,
    #[error("projection does not bind the selected DeviceAttachment")]
    ProjectionAttachmentMismatch,
    #[error("expansion object does not bind the selected Segment publication")]
    ExpansionScopeMismatch,
    #[error("every device projection requires a reverse route")]
    MissingReverseRoute,
    #[error("Core module route operation failed: {0}")]
    Core(String),
    #[error("SD-WAN repository rejected the publication")]
    Repository(#[from] SdwanError),
}

pub fn build_route_publication(
    input: &RoutePublicationInput,
    signer: &RouteSigner,
) -> Result<BuiltRoutePublication, RoutePublicationError> {
    if input.generation == 0
        || input.publication_id.is_nil()
        || input.audit_event_id.is_nil()
        || input.actor_id.is_empty()
    {
        return Err(RoutePublicationError::InvalidGeneration);
    }

    let mut attachments = input.attachments.clone();
    attachments.sort_unstable_by_key(|attachment| attachment.attachment_id.0);
    let routes = compile_routes(&attachments)?;
    let device_attachments: Vec<&SegmentAttachmentV1> = attachments
        .iter()
        .filter(|attachment| {
            attachment.state == AttachmentState::Active
                && matches!(attachment.principal, AttachmentPrincipalV1::Device { .. })
        })
        .collect();
    if input.projections.len() != device_attachments.len() {
        return Err(RoutePublicationError::IncompleteProjectionSet);
    }

    let segment = signer.sign_segment_snapshot(SegmentRouteSnapshotV1 {
        tenant_id: input.tenant_id,
        segment_id: input.segment_id,
        segment_generation: input.generation,
        segment_overlay_prefix: input.segment_overlay_prefix,
        attachments: attachments.clone(),
        routes: routes.clone(),
        not_before: input.not_before,
        expires_at: input.expires_at,
        stale_until: input.stale_until,
        previous_hash: input.previous_hash,
    })?;

    let mut plans: Vec<&DeviceProjectionInput> = input.projections.iter().collect();
    plans.sort_unstable_by_key(|plan| plan.attachment_id.0);
    if plans
        .windows(2)
        .any(|pair| pair[0].attachment_id == pair[1].attachment_id)
    {
        return Err(RoutePublicationError::IncompleteProjectionSet);
    }
    let mut projections = Vec::with_capacity(plans.len());
    for plan in plans {
        let attachment = device_attachments
            .iter()
            .copied()
            .find(|attachment| attachment.attachment_id == plan.attachment_id)
            .ok_or(RoutePublicationError::ProjectionAttachmentMismatch)?;
        if plan.publication_id.is_nil() {
            return Err(RoutePublicationError::ProjectionAttachmentMismatch);
        }
        let (device_id, device_key_id) = match attachment.principal {
            AttachmentPrincipalV1::Device {
                device_id,
                device_key_id,
            } => (device_id, device_key_id),
            AttachmentPrincipalV1::Node { .. } => {
                return Err(RoutePublicationError::ProjectionAttachmentMismatch)
            }
        };
        let site_id = attachment
            .site_id
            .ok_or(RoutePublicationError::ProjectionAttachmentMismatch)?;
        let remote_routes: Vec<RemoteRouteV1> = routes
            .iter()
            .filter(|route| route.owner_site_id != Some(site_id))
            .map(|route| {
                Ok(RemoteRouteV1 {
                    destination_prefix: route.destination_prefix,
                    owner_site_id: route
                        .owner_site_id
                        .ok_or(RoutePublicationError::OverlappingOwnership)?,
                    owner_attachment_ids: route.owner_attachment_ids.clone(),
                })
            })
            .collect::<Result<Vec<_>, RoutePublicationError>>()?;
        if remote_routes.is_empty() {
            return Err(RoutePublicationError::MissingReverseRoute);
        }
        let sealed = signer.sign_site_projection(SiteRouteProjectionV1 {
            tenant_id: input.tenant_id,
            segment_id: input.segment_id,
            segment_generation: input.generation,
            segment_content_hash: segment.content_hash,
            site_id,
            attachment_id: attachment.attachment_id,
            device_id,
            device_key_id,
            local_transport_node: plan.local_transport_node.clone(),
            overlay_router_ipv4: attachment.overlay_router_ipv4,
            local_prefixes: attachment.local_prefixes.clone(),
            remote_routes,
            path_policy: plan.path_policy,
            peer_paths: plan.peer_paths.clone(),
            coherent_manifest: plan.coherent_manifest.clone(),
            max_inner_mtu: plan.max_inner_mtu,
            resources: plan.resources,
            epoch_floor: attachment.epoch_floor,
            not_before: input.not_before,
            expires_at: input.expires_at,
            stale_until: input.stale_until,
            projection_id: plan.projection_id,
            projection_generation: plan.projection_generation,
            previous_hash: plan.previous_hash,
        })?;
        projections.push(BuiltDeviceProjection {
            publication_id: plan.publication_id,
            sealed,
        });
    }

    Ok(BuiltRoutePublication {
        publication_id: input.publication_id,
        audit_event_id: input.audit_event_id,
        actor_id: input.actor_id.clone(),
        segment,
        projections,
    })
}

fn compile_routes(
    attachments: &[SegmentAttachmentV1],
) -> Result<Vec<SegmentRouteV1>, RoutePublicationError> {
    let mut routes: Vec<SegmentRouteV1> = Vec::new();
    for attachment in attachments {
        if !attachment.local_prefixes.is_empty() && attachment.state != AttachmentState::Active {
            return Err(RoutePublicationError::InactiveOwner);
        }
        if attachment.state != AttachmentState::Active {
            continue;
        }
        let Some(site_id) = attachment.site_id else {
            continue;
        };
        for prefix in &attachment.local_prefixes {
            if let Some(route) = routes
                .iter_mut()
                .find(|route| route.destination_prefix == *prefix)
            {
                if route.owner_site_id != Some(site_id) {
                    return Err(RoutePublicationError::OverlappingOwnership);
                }
                route.owner_attachment_ids.push(attachment.attachment_id);
            } else if routes
                .iter()
                .any(|route| route.destination_prefix.overlaps(prefix))
            {
                return Err(RoutePublicationError::OverlappingOwnership);
            } else {
                routes.push(SegmentRouteV1 {
                    destination_prefix: *prefix,
                    owner_site_id: Some(site_id),
                    owner_attachment_ids: vec![attachment.attachment_id],
                });
            }
        }
    }
    routes.sort_unstable_by_key(|route| route.destination_prefix);
    for route in &mut routes {
        route
            .owner_attachment_ids
            .sort_unstable_by_key(|attachment| attachment.0);
    }
    Ok(routes)
}

fn uuid(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

#[derive(Clone)]
pub struct RoutePublisher {
    repository: SdwanRepository,
    signer: RouteSigner,
}

impl RoutePublisher {
    pub fn new(repository: SdwanRepository, signer: RouteSigner) -> Self {
        Self { repository, signer }
    }

    pub async fn publish(
        &self,
        input: &RoutePublicationInput,
    ) -> Result<PublicationOutcome, RoutePublicationError> {
        let built = build_route_publication(input, &self.signer)?;
        Ok(self.repository.publish(&built.database_write()?).await?)
    }
}
