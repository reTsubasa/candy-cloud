use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const CONTROL_SCHEMA_V1: u16 = 1;
pub const ROUTE_CONTRACT_V1: u16 = 1;
pub const MAX_NAME_LEN: usize = 200;
pub const MAX_POLICY_RULES: usize = 512;
pub const MAX_DNS_RECORDS: usize = 4096;
pub const MIN_DNS_TTL_SECONDS: u32 = 5;
pub const MAX_DNS_TTL_SECONDS: u32 = 86_400;

pub fn runtime_path_candidate_id(path_resource_id: Uuid, endpoint_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"candy/path-endpoint-candidate-v1\0");
    hasher.update(path_resource_id.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceState {
    Active,
    Disabled,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceMetadataV1 {
    pub schema_version: u16,
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub revision: u64,
    pub state: ResourceState,
}

impl ResourceMetadataV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTROL_SCHEMA_V1
            || self.id.is_nil()
            || self.tenant_id.is_nil()
            || self.revision == 0
        {
            return Err(ContractError::InvalidMetadata);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodePlatformV1 {
    OpenWrt,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeV1 {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub site_id: Uuid,
    pub display_name: String,
    pub platform: NodePlatformV1,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentV1 {
    pub segment_id: Uuid,
    pub site_id: Uuid,
    pub node_id: Uuid,
    pub overlay_router_ipv4: Ipv4Addr,
    pub epoch_floor: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SiteKindV1 {
    Edge,
    PrivateCloud,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteV1 {
    pub name: String,
    pub kind: SiteKindV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Ipv4PrefixV1 {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Ipv4PrefixV1 {
    pub fn validate(self) -> Result<(), ContractError> {
        self.validate_with_default(false)
    }

    fn validate_with_default(self, allow_default: bool) -> Result<(), ContractError> {
        if self.prefix_len > 32 || (!allow_default && self.prefix_len == 0) {
            return Err(ContractError::InvalidPrefix);
        }
        let value = u32::from(self.network);
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        if value & !mask != 0 {
            return Err(ContractError::InvalidPrefix);
        }
        Ok(())
    }

    pub fn overlaps(self, other: Self) -> bool {
        let bits = self.prefix_len.min(other.prefix_len);
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        u32::from(self.network) & mask == u32::from(other.network) & mask
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SegmentV1 {
    pub name: String,
    pub overlay_prefix: Ipv4PrefixV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrefixV1 {
    pub site_id: Uuid,
    pub segment_id: Uuid,
    pub prefix: Ipv4PrefixV1,
    pub source: PrefixSourceV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrefixSourceV1 {
    Connected,
    Configured,
    ApprovedLearned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeerPathPolicyV1 {
    DirectOnly,
    DirectPreferred,
    RelayRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerV1 {
    pub segment_id: Uuid,
    pub site_a_id: Uuid,
    pub site_b_id: Uuid,
    pub path_policy: PeerPathPolicyV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayV1 {
    pub service_node_id: Uuid,
    pub name: String,
    pub region: String,
    pub max_sessions: u32,
    pub max_bits_per_second: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PathCandidateKindV1 {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PathCandidateV1 {
    pub segment_id: Uuid,
    pub peer_id: Uuid,
    pub source_attachment_id: Uuid,
    pub destination_attachment_id: Uuid,
    pub kind: PathCandidateKindV1,
    pub relay_id: Option<Uuid>,
    pub transport_node_id: Uuid,
    pub priority: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressV1 {
    pub name: String,
    pub site_id: Uuid,
    pub attachment_id: Uuid,
    pub max_sessions: u32,
    pub max_bits_per_second: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "type",
    content = "egress_id"
)]
pub enum PolicyActionV1 {
    LocalEgress,
    RemoteEgress(Uuid),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyRuleV1 {
    pub id: Uuid,
    pub priority: u32,
    pub source_site_ids: Vec<Uuid>,
    pub destination_prefixes: Vec<Ipv4PrefixV1>,
    pub domains: Vec<String>,
    pub traffic_classes: Vec<String>,
    pub action: PolicyActionV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyV1 {
    pub segment_id: Uuid,
    pub generation: u64,
    pub rules: Vec<ServicePolicyRuleV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "type", content = "value")]
pub enum DnsRecordDataV1 {
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Cname(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordV1 {
    pub name: String,
    pub ttl_seconds: u32,
    pub data: DnsRecordDataV1,
    pub required_prefix_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsIntentV1 {
    pub segment_id: Uuid,
    /// Legacy single-site scope. New documents use `site_ids`; `None` and an
    /// empty `site_ids` publish to every site in the segment.
    #[serde(default)]
    pub site_id: Option<Uuid>,
    #[serde(default)]
    pub site_ids: Vec<Uuid>,
    pub zone: String,
    pub records: Vec<DnsRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", content = "spec")]
pub enum ResourceSpecV1 {
    Node(NodeV1),
    Site(SiteV1),
    Segment(SegmentV1),
    Attachment(AttachmentV1),
    Prefix(PrefixV1),
    Peer(PeerV1),
    Relay(RelayV1),
    PathCandidate(PathCandidateV1),
    Egress(EgressV1),
    ServicePolicy(ServicePolicyV1),
    DnsIntent(DnsIntentV1),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlResourceV1 {
    pub metadata: ResourceMetadataV1,
    pub resource: ResourceSpecV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    Node,
    Site,
    Segment,
    Attachment,
    Prefix,
    Peer,
    Relay,
    PathCandidate,
    Egress,
    ServicePolicy,
    DnsIntent,
}

impl ResourceKind {
    pub fn api_collection(self) -> &'static str {
        match self {
            Self::Node => "nodes",
            Self::Site => "sites",
            Self::Segment => "segments",
            Self::Attachment => "attachments",
            Self::Prefix => "prefixes",
            Self::Peer => "peers",
            Self::Relay => "relays",
            Self::PathCandidate => "path-candidates",
            Self::Egress => "egresses",
            Self::ServicePolicy => "service-policies",
            Self::DnsIntent => "dns-intents",
        }
    }

    pub fn database_value(self) -> &'static str {
        match self {
            Self::Node => "NODE",
            Self::Site => "SITE",
            Self::Segment => "SEGMENT",
            Self::Attachment => "ATTACHMENT",
            Self::Prefix => "PREFIX",
            Self::Peer => "PEER",
            Self::Relay => "RELAY",
            Self::PathCandidate => "PATH_CANDIDATE",
            Self::Egress => "EGRESS",
            Self::ServicePolicy => "SERVICE_POLICY",
            Self::DnsIntent => "DNS_INTENT",
        }
    }

    pub fn parse_api_collection(value: &str) -> Option<Self> {
        [
            Self::Node,
            Self::Site,
            Self::Segment,
            Self::Attachment,
            Self::Prefix,
            Self::Peer,
            Self::Relay,
            Self::PathCandidate,
            Self::Egress,
            Self::ServicePolicy,
            Self::DnsIntent,
        ]
        .into_iter()
        .find(|kind| kind.api_collection() == value)
    }
}

impl ResourceSpecV1 {
    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::Node(_) => ResourceKind::Node,
            Self::Site(_) => ResourceKind::Site,
            Self::Segment(_) => ResourceKind::Segment,
            Self::Attachment(_) => ResourceKind::Attachment,
            Self::Prefix(_) => ResourceKind::Prefix,
            Self::Peer(_) => ResourceKind::Peer,
            Self::Relay(_) => ResourceKind::Relay,
            Self::PathCandidate(_) => ResourceKind::PathCandidate,
            Self::Egress(_) => ResourceKind::Egress,
            Self::ServicePolicy(_) => ResourceKind::ServicePolicy,
            Self::DnsIntent(_) => ResourceKind::DnsIntent,
        }
    }

    pub fn segment_id(&self) -> Option<Uuid> {
        match self {
            Self::Segment(_) => None,
            Self::Attachment(value) => Some(value.segment_id),
            Self::Prefix(value) => Some(value.segment_id),
            Self::Peer(value) => Some(value.segment_id),
            Self::PathCandidate(value) => Some(value.segment_id),
            Self::ServicePolicy(value) => Some(value.segment_id),
            Self::DnsIntent(value) => Some(value.segment_id),
            Self::Node(_) | Self::Site(_) | Self::Relay(_) | Self::Egress(_) => None,
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Node(value) => {
                require_ids([value.device_id, value.device_key_id, value.site_id])?;
                validate_name(&value.display_name)?;
                validate_token(&value.architecture, 80)
            }
            Self::Site(value) => validate_name(&value.name),
            Self::Segment(value) => {
                validate_name(&value.name)?;
                value.overlay_prefix.validate()
            }
            Self::Attachment(value) => {
                require_ids([value.segment_id, value.site_id, value.node_id])?;
                if value.overlay_router_ipv4.is_unspecified()
                    || value.overlay_router_ipv4.is_loopback()
                    || value.overlay_router_ipv4.is_multicast()
                    || value.overlay_router_ipv4.is_broadcast()
                    || value.epoch_floor == 0
                {
                    return Err(ContractError::InvalidAttachment);
                }
                Ok(())
            }
            Self::Prefix(value) => {
                require_ids([value.site_id, value.segment_id])?;
                value.prefix.validate()
            }
            Self::Peer(value) => {
                require_ids([value.segment_id, value.site_a_id, value.site_b_id])?;
                if value.site_a_id == value.site_b_id
                    || value.site_a_id.as_bytes() > value.site_b_id.as_bytes()
                {
                    return Err(ContractError::InvalidPeer);
                }
                Ok(())
            }
            Self::Relay(value) => {
                require_ids([value.service_node_id])?;
                validate_name(&value.name)?;
                validate_display_text(&value.region, 80)?;
                require_capacity(value.max_sessions, value.max_bits_per_second)
            }
            Self::PathCandidate(value) => {
                require_ids([
                    value.segment_id,
                    value.peer_id,
                    value.source_attachment_id,
                    value.destination_attachment_id,
                    value.transport_node_id,
                ])?;
                if value.source_attachment_id == value.destination_attachment_id
                    || value.priority == 0
                    || matches!(
                        (value.kind, value.relay_id),
                        (PathCandidateKindV1::Direct, Some(_)) | (PathCandidateKindV1::Relay, None)
                    )
                    || value.relay_id.is_some_and(|id| id.is_nil())
                {
                    return Err(ContractError::InvalidPathCandidate);
                }
                Ok(())
            }
            Self::Egress(value) => {
                require_ids([value.site_id, value.attachment_id])?;
                validate_name(&value.name)?;
                require_capacity(value.max_sessions, value.max_bits_per_second)
            }
            Self::ServicePolicy(value) => validate_service_policy(value),
            Self::DnsIntent(value) => validate_dns_intent(value),
        }
    }

    pub fn document_hash(&self) -> Result<[u8; 32], ContractError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ContractError::Serialization)?;
        Ok(Sha256::digest(bytes).into())
    }
}

impl ControlResourceV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.metadata.validate()?;
        self.resource.validate()
    }
}

fn validate_service_policy(value: &ServicePolicyV1) -> Result<(), ContractError> {
    require_ids([value.segment_id])?;
    if value.generation == 0 || value.rules.len() > MAX_POLICY_RULES {
        return Err(ContractError::InvalidServicePolicy);
    }
    let mut ids = std::collections::HashSet::new();
    let mut priorities = std::collections::HashSet::new();
    for rule in &value.rules {
        let unique_source_sites = rule
            .source_site_ids
            .iter()
            .collect::<std::collections::HashSet<_>>();
        if rule.id.is_nil()
            || !ids.insert(rule.id)
            || !priorities.insert(rule.priority)
            || rule.source_site_ids.iter().any(Uuid::is_nil)
            || rule.source_site_ids.len() > 256
            || unique_source_sites.len() != rule.source_site_ids.len()
            || rule.destination_prefixes.len() > 256
            || rule.domains.len() > 256
            || rule.traffic_classes.len() > 32
            || matches!(rule.action, PolicyActionV1::RemoteEgress(id) if id.is_nil())
        {
            return Err(ContractError::InvalidServicePolicy);
        }
        for prefix in &rule.destination_prefixes {
            prefix.validate_with_default(matches!(rule.action, PolicyActionV1::RemoteEgress(_)))?;
        }
        for domain in &rule.domains {
            validate_dns_name(domain)?;
        }
        for class in &rule.traffic_classes {
            validate_token(class, 40)?;
        }
    }
    Ok(())
}

fn validate_dns_intent(value: &DnsIntentV1) -> Result<(), ContractError> {
    require_ids([value.segment_id])?;
    if value.site_id.is_some_and(|site_id| site_id.is_nil())
        || value.site_ids.len() > 256
        || value.site_ids.iter().any(Uuid::is_nil)
        || value
            .site_ids
            .iter()
            .enumerate()
            .any(|(index, site_id)| value.site_ids[..index].contains(site_id))
        || (value.site_id.is_some() && !value.site_ids.is_empty())
    {
        return Err(ContractError::InvalidDnsIntent);
    }
    if value.records.len() > MAX_DNS_RECORDS {
        return Err(ContractError::InvalidDnsIntent);
    }
    validate_dns_name(&value.zone)?;
    let mut keys = std::collections::HashSet::new();
    for record in &value.records {
        validate_dns_name(&record.name)?;
        if record.ttl_seconds < MIN_DNS_TTL_SECONDS
            || record.ttl_seconds > MAX_DNS_TTL_SECONDS
            || record.required_prefix_id.is_some_and(|id| id.is_nil())
        {
            return Err(ContractError::InvalidDnsIntent);
        }
        if let DnsRecordDataV1::Cname(target) = &record.data {
            validate_dns_name(target)?;
        }
        let key = serde_json::to_string(record).map_err(|_| ContractError::Serialization)?;
        if !keys.insert(key) {
            return Err(ContractError::InvalidDnsIntent);
        }
    }
    Ok(())
}

fn require_ids<const N: usize>(ids: [Uuid; N]) -> Result<(), ContractError> {
    if ids.into_iter().any(|id| id.is_nil()) {
        Err(ContractError::InvalidReference)
    } else {
        Ok(())
    }
}

fn require_capacity(sessions: u32, bits_per_second: u64) -> Result<(), ContractError> {
    if sessions == 0 || bits_per_second == 0 {
        Err(ContractError::InvalidCapacity)
    } else {
        Ok(())
    }
}

fn validate_name(value: &str) -> Result<(), ContractError> {
    validate_display_text(value, MAX_NAME_LEN)
}

fn validate_display_text(value: &str, max_len: usize) -> Result<(), ContractError> {
    let trimmed = value.trim();
    if trimmed != value
        || value.is_empty()
        || value.chars().count() > max_len
        || value.chars().any(char::is_control)
    {
        Err(ContractError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_token(value: &str, max_len: usize) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ContractError::InvalidToken)
    } else {
        Ok(())
    }
}

fn validate_dns_name(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        Err(ContractError::InvalidDnsName)
    } else {
        Ok(())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("invalid resource metadata")]
    InvalidMetadata,
    #[error("invalid resource reference")]
    InvalidReference,
    #[error("invalid resource name")]
    InvalidName,
    #[error("invalid resource token")]
    InvalidToken,
    #[error("invalid IPv4 prefix")]
    InvalidPrefix,
    #[error("peer Sites must be distinct and canonically ordered")]
    InvalidPeer,
    #[error("invalid path candidate")]
    InvalidPathCandidate,
    #[error("invalid capacity")]
    InvalidCapacity,
    #[error("invalid segment attachment")]
    InvalidAttachment,
    #[error("invalid service policy")]
    InvalidServicePolicy,
    #[error("invalid DNS intent")]
    InvalidDnsIntent,
    #[error("invalid DNS name")]
    InvalidDnsName,
    #[error("resource serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    #[test]
    fn runtime_candidate_id_is_stable_across_publisher_and_telemetry_validation() {
        let path_resource_id = Uuid::parse_str("7395e28b-4418-54b8-a969-b4d3b18ca7f1").unwrap();
        let endpoint_id = Uuid::parse_str("01a017c4-3e22-7732-95ad-2a87cbff09cd").unwrap();
        assert_eq!(
            runtime_path_candidate_id(path_resource_id, endpoint_id),
            Uuid::parse_str("f86c8c0f-c44f-9391-9f2f-deb09859f093").unwrap()
        );
    }

    #[test]
    fn direct_peer_requires_no_relay_or_hub() {
        let peer = ResourceSpecV1::Peer(PeerV1 {
            segment_id: id(1),
            site_a_id: id(2),
            site_b_id: id(3),
            path_policy: PeerPathPolicyV1::DirectOnly,
        });
        assert_eq!(peer.validate(), Ok(()));
    }

    #[test]
    fn attachment_is_a_first_class_segment_resource() {
        let attachment = ResourceSpecV1::Attachment(AttachmentV1 {
            segment_id: id(1),
            site_id: id(2),
            node_id: id(3),
            overlay_router_ipv4: Ipv4Addr::new(100, 64, 0, 10),
            epoch_floor: 1,
        });
        assert_eq!(attachment.validate(), Ok(()));
        assert_eq!(attachment.segment_id(), Some(id(1)));
        assert_eq!(attachment.kind().api_collection(), "attachments");
    }

    #[test]
    fn relay_candidate_requires_a_relay_and_direct_forbids_it() {
        let base = PathCandidateV1 {
            segment_id: id(1),
            peer_id: id(2),
            source_attachment_id: id(3),
            destination_attachment_id: id(4),
            kind: PathCandidateKindV1::Direct,
            relay_id: Some(id(5)),
            transport_node_id: Uuid::new_v4(),
            priority: 10,
        };
        assert_eq!(
            ResourceSpecV1::PathCandidate(base.clone()).validate(),
            Err(ContractError::InvalidPathCandidate)
        );
        let relay = PathCandidateV1 {
            kind: PathCandidateKindV1::Relay,
            ..base
        };
        assert_eq!(ResourceSpecV1::PathCandidate(relay).validate(), Ok(()));
    }

    #[test]
    fn relay_region_accepts_localized_display_text() {
        let relay = ResourceSpecV1::Relay(RelayV1 {
            service_node_id: id(1),
            name: "美国搬瓦工".to_owned(),
            region: "美国".to_owned(),
            max_sessions: 10_000,
            max_bits_per_second: 1_000_000_000,
        });
        assert_eq!(relay.validate(), Ok(()));
    }

    #[test]
    fn dns_intent_binds_route_scope() {
        let intent = ResourceSpecV1::DnsIntent(DnsIntentV1 {
            segment_id: id(1),
            site_id: Some(id(2)),
            site_ids: Vec::new(),
            zone: "internal.example".into(),
            records: vec![DnsRecordV1 {
                name: "router.internal.example".into(),
                ttl_seconds: 30,
                data: DnsRecordDataV1::A(Ipv4Addr::new(10, 0, 0, 1)),
                required_prefix_id: None,
            }],
        });
        assert_eq!(intent.validate(), Ok(()));
        assert_ne!(intent.document_hash().unwrap(), [0; 32]);
    }

    #[test]
    fn policy_rejects_duplicate_source_sites() {
        let policy = ResourceSpecV1::ServicePolicy(ServicePolicyV1 {
            segment_id: id(1),
            generation: 1,
            rules: vec![ServicePolicyRuleV1 {
                id: id(2),
                priority: 100,
                source_site_ids: vec![id(3), id(3)],
                destination_prefixes: Vec::new(),
                domains: Vec::new(),
                traffic_classes: Vec::new(),
                action: PolicyActionV1::LocalEgress,
            }],
        });
        assert_eq!(policy.validate(), Err(ContractError::InvalidServicePolicy));
    }

    #[test]
    fn policy_allows_default_route_only_for_remote_egress() {
        let rule = |action| ServicePolicyRuleV1 {
            id: id(2),
            priority: 100,
            source_site_ids: vec![id(3)],
            destination_prefixes: vec![Ipv4PrefixV1 {
                network: Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
            }],
            domains: Vec::new(),
            traffic_classes: Vec::new(),
            action,
        };
        let policy = |rule| {
            ResourceSpecV1::ServicePolicy(ServicePolicyV1 {
                segment_id: id(1),
                generation: 1,
                rules: vec![rule],
            })
        };

        assert!(policy(rule(PolicyActionV1::RemoteEgress(id(4))))
            .validate()
            .is_ok());
        assert_eq!(
            policy(rule(PolicyActionV1::LocalEgress)).validate(),
            Err(ContractError::InvalidPrefix)
        );
    }

    #[test]
    fn prefix_must_be_canonical() {
        assert_eq!(
            Ipv4PrefixV1 {
                network: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24
            }
            .validate(),
            Err(ContractError::InvalidPrefix)
        );
    }

    #[test]
    fn overlap_is_total_even_for_unvalidated_default_routes() {
        let default = Ipv4PrefixV1 {
            network: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
        };
        let private = Ipv4PrefixV1 {
            network: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 8,
        };
        assert!(default.overlaps(private));
        assert!(private.overlaps(default));
    }
}
