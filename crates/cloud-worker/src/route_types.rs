use thiserror::Error;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub [u8; 16]);
    };
}

id_type!(AttachmentId);
id_type!(DeviceId);
id_type!(DeviceKeyId);
id_type!(NodeId);
id_type!(NodeKeyId);
id_type!(NodePoolId);
id_type!(PathCandidateId);
id_type!(PolicyId);
id_type!(SegmentId);
id_type!(SiteId);
id_type!(TenantId);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AttachmentState {
    Active = 1,
    Draining = 2,
    Revoked = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PathSelectionPolicyV1 {
    DirectOnly = 1,
    DirectPreferred = 2,
    RelayRequired = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PeerPathKindV1 {
    Direct = 1,
    Relay = 2,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4PrefixV1 {
    pub network: [u8; 4],
    pub prefix_len: u8,
}

impl Ipv4PrefixV1 {
    pub fn new(network: [u8; 4], prefix_len: u8) -> Result<Self, RouteTypeError> {
        if prefix_len == 0 || prefix_len > 32 {
            return Err(RouteTypeError::InvalidIpv4Prefix);
        }
        let address = u32::from_be_bytes(network);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        if address & mask != address {
            return Err(RouteTypeError::InvalidIpv4Prefix);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        let prefix_len = self.prefix_len.min(other.prefix_len);
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        u32::from_be_bytes(self.network) & mask == u32::from_be_bytes(other.network) & mask
    }
}

#[derive(Debug, Error)]
pub enum RouteTypeError {
    #[error("invalid canonical IPv4 prefix")]
    InvalidIpv4Prefix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRefV1 {
    pub policy_id: PolicyId,
    pub generation: u64,
    pub content_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentPrincipalV1 {
    Device {
        device_id: DeviceId,
        device_key_id: DeviceKeyId,
    },
    Node {
        node_id: NodeId,
        node_key_id: NodeKeyId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentAttachmentV1 {
    pub attachment_id: AttachmentId,
    pub site_id: Option<SiteId>,
    pub principal: AttachmentPrincipalV1,
    pub overlay_router_ipv4: [u8; 4],
    pub local_prefixes: Vec<Ipv4PrefixV1>,
    pub state: AttachmentState,
    pub epoch_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentRouteV1 {
    pub destination_prefix: Ipv4PrefixV1,
    pub owner_site_id: Option<SiteId>,
    pub owner_attachment_ids: Vec<AttachmentId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentRouteSnapshotV1 {
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub segment_generation: u64,
    pub segment_overlay_prefix: Ipv4PrefixV1,
    pub attachments: Vec<SegmentAttachmentV1>,
    pub routes: Vec<SegmentRouteV1>,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub previous_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerEndpointV1 {
    Ipv4 { address: [u8; 4], port: u16 },
    Ipv6 { address: [u8; 16], port: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayNodeIdentityV1 {
    pub node_id: NodeId,
    pub node_key_id: NodeKeyId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportNodeIdentityV1 {
    pub node_id: NodeId,
    pub node_key_id: NodeKeyId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPresetV1 {
    Current = 1,
    BbrV1 = 2,
    Aggressive = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerPathCandidateV1 {
    pub candidate_id: PathCandidateId,
    pub peer_site_id: SiteId,
    pub peer_attachment_id: AttachmentId,
    pub kind: PeerPathKindV1,
    pub relay_node: Option<RelayNodeIdentityV1>,
    pub node_pool_id: NodePoolId,
    pub transport_node: TransportNodeIdentityV1,
    pub endpoint: PeerEndpointV1,
    pub server_name: String,
    pub server_cert_sha256: [u8; 32],
    pub transport_preset: TransportPresetV1,
    pub priority: u16,
    pub authorization: PolicyRefV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRouteV1 {
    pub destination_prefix: Ipv4PrefixV1,
    pub owner_site_id: SiteId,
    pub owner_attachment_ids: Vec<AttachmentId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoherentPolicyManifestV1 {
    pub generation: u64,
    pub peer_paths_hash: [u8; 32],
    pub dns_projection: Option<PolicyRefV1>,
    pub egress_authorization: Option<PolicyRefV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketResourcePolicyV1 {
    pub max_route_prefixes: u64,
    pub max_queue_packets: u64,
    pub max_queue_bytes: u64,
    pub replay_window_packets: u64,
    pub max_packets_per_second: u64,
    pub max_bytes_per_second: u64,
    pub allowed_traffic_classes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRouteProjectionV1 {
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub site_id: SiteId,
    pub attachment_id: AttachmentId,
    pub device_id: DeviceId,
    pub device_key_id: DeviceKeyId,
    pub local_transport_node: Option<TransportNodeIdentityV1>,
    pub overlay_router_ipv4: [u8; 4],
    pub local_prefixes: Vec<Ipv4PrefixV1>,
    pub remote_routes: Vec<RemoteRouteV1>,
    pub path_policy: PathSelectionPolicyV1,
    pub peer_paths: Vec<PeerPathCandidateV1>,
    pub coherent_manifest: CoherentPolicyManifestV1,
    pub max_inner_mtu: u16,
    pub resources: PacketResourcePolicyV1,
    pub epoch_floor: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub projection_id: PolicyId,
    pub projection_generation: u64,
    pub previous_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedHubQuotaV1 {
    pub max_entities: u64,
    pub max_queue_packets: u64,
    pub max_queue_bytes: u64,
    pub packets_per_second: u64,
    pub bytes_per_second: u64,
    pub burst_packets: u64,
    pub burst_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedHubAdmissionPolicyV1 {
    pub node_id: NodeId,
    pub node_key_id: NodeKeyId,
    pub node_pool_id: NodePoolId,
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub policy_id: PolicyId,
    pub policy_generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub previous_hash: [u8; 32],
    pub node: SharedHubQuotaV1,
    pub tenant: SharedHubQuotaV1,
    pub site: SharedHubQuotaV1,
    pub tunnel: SharedHubQuotaV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeshPeerRefV1 {
    pub site_id: SiteId,
    pub attachment_id: AttachmentId,
    pub epoch_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshMembershipProjectionV1 {
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub local_site_id: SiteId,
    pub local_attachment_id: AttachmentId,
    pub peers: Vec<MeshPeerRefV1>,
    pub projection_id: PolicyId,
    pub projection_generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub previous_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicRouteV1 {
    pub prefix: Ipv4PrefixV1,
    pub owner_site_id: SiteId,
    pub owner_attachment_id: AttachmentId,
    pub metric: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicRouteSnapshotV1 {
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub base_segment_generation: u64,
    pub base_segment_content_hash: [u8; 32],
    pub routes: Vec<DynamicRouteV1>,
    pub policy_id: PolicyId,
    pub generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub previous_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FabricAttachmentAssignmentV1 {
    pub site_id: SiteId,
    pub attachment_id: AttachmentId,
    pub hub_node_id: NodeId,
    pub hub_node_key_id: NodeKeyId,
    pub hub_attachment_id: AttachmentId,
    pub attachment_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HubFabricAssignmentV1 {
    pub tenant_id: TenantId,
    pub segment_id: SegmentId,
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub assignments: Vec<FabricAttachmentAssignmentV1>,
    pub policy_id: PolicyId,
    pub generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub stale_until: u64,
    pub previous_hash: [u8; 32],
}
