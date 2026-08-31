use std::{collections::HashSet, net::Ipv4Addr};

use chrono::Utc;
use cloud_control::{ControlResourceV1, ResourceSpecV1, ResourceState, SiteKindV1};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::DbPool;

const MAX_SIGNED_ENVELOPE_LEN: usize = 1024 * 1024;
const MAX_ACTOR_ID_LEN: usize = 120;
const MAX_PROJECTIONS: usize = 4096;
const MAX_COMPATIBILITY_GENERATIONS: usize = 1;
const MAX_EXPANSION_OBJECTS: usize = 4096;
const MAX_RUNTIME_PATHS: usize = 256;
const MAX_RUNTIME_LOCAL_NETWORKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationLookup {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDeviceProfile {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub device_name: String,
    pub site_id: Option<Uuid>,
    pub site_name: Option<String>,
    pub segment_id: Option<Uuid>,
    pub segment_name: Option<String>,
    pub attachment_id: Option<Uuid>,
    pub peer_sites: Vec<RuntimePeerSiteProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePeerSiteProfile {
    pub site_id: Uuid,
    pub site_name: String,
}

impl RuntimeConfigurationLookup {
    fn validate(&self) -> Result<(), RuntimeConfigurationError> {
        if self.tenant_id.is_nil() || self.device_id.is_nil() || self.device_key_id.is_nil() {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationRecord {
    pub projection_publication_id: Uuid,
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
    pub projection_content_hash: [u8; 32],
    pub signed_segment_envelope: Vec<u8>,
    pub signed_projection_envelope: Vec<u8>,
    pub peer_projection_catalog: Vec<RuntimePeerProjection>,
    pub compatibility_generations: Vec<RuntimeCompatibilityGeneration>,
    pub activation_phase: RuntimeConfigurationActivationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationActivationPhase {
    Prepare,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePeerProjection {
    pub projection_id: Uuid,
    pub projection_generation: u64,
    pub projection_content_hash: [u8; 32],
    pub signed_projection_envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCompatibilityGeneration {
    pub segment_generation: u64,
    pub segment_content_hash: [u8; 32],
    pub signed_segment_envelope: Vec<u8>,
    pub peer_projection_catalog: Vec<RuntimePeerProjection>,
}

impl RuntimeConfigurationRecord {
    pub fn envelope_sha256(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"candy/runtime-configuration-v1\0");
        digest.update((self.signed_segment_envelope.len() as u64).to_be_bytes());
        digest.update(&self.signed_segment_envelope);
        digest.update((self.signed_projection_envelope.len() as u64).to_be_bytes());
        digest.update(&self.signed_projection_envelope);
        digest.update((self.peer_projection_catalog.len() as u64).to_be_bytes());
        for projection in &self.peer_projection_catalog {
            digest.update(projection.projection_id.as_bytes());
            digest.update(projection.projection_generation.to_be_bytes());
            digest.update(projection.projection_content_hash);
            digest.update((projection.signed_projection_envelope.len() as u64).to_be_bytes());
            digest.update(&projection.signed_projection_envelope);
        }
        digest.update((self.compatibility_generations.len() as u64).to_be_bytes());
        for generation in &self.compatibility_generations {
            digest.update(generation.segment_generation.to_be_bytes());
            digest.update(generation.segment_content_hash);
            digest.update((generation.signed_segment_envelope.len() as u64).to_be_bytes());
            digest.update(&generation.signed_segment_envelope);
            digest.update((generation.peer_projection_catalog.len() as u64).to_be_bytes());
            for projection in &generation.peer_projection_catalog {
                digest.update(projection.projection_id.as_bytes());
                digest.update(projection.projection_generation.to_be_bytes());
                digest.update(projection.projection_content_hash);
                digest.update((projection.signed_projection_envelope.len() as u64).to_be_bytes());
                digest.update(&projection.signed_projection_envelope);
            }
        }
        digest.finalize().into()
    }

    fn validate(
        &self,
        lookup: &RuntimeConfigurationLookup,
    ) -> Result<(), RuntimeConfigurationError> {
        if self.projection_publication_id.is_nil()
            || self.projection_id.is_nil()
            || self.segment_id.is_nil()
            || self.site_id.is_nil()
            || self.attachment_id.is_nil()
            || self.segment_generation == 0
            || self.projection_generation == 0
            || self.segment_content_hash == [0; 32]
            || self.projection_content_hash == [0; 32]
            || self.signed_segment_envelope.is_empty()
            || self.signed_segment_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
            || self.signed_projection_envelope.is_empty()
            || self.signed_projection_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
            || self.tenant_id != lookup.tenant_id
            || self.device_id != lookup.device_id
            || self.device_key_id != lookup.device_key_id
            || self.peer_projection_catalog.len() > MAX_PROJECTIONS
            || self.compatibility_generations.len() > MAX_COMPATIBILITY_GENERATIONS
            || self.peer_projection_catalog.iter().any(|projection| {
                projection.projection_id == self.projection_id
                    || projection.projection_id.is_nil()
                    || projection.projection_generation == 0
                    || projection.projection_content_hash == [0; 32]
                    || projection.signed_projection_envelope.is_empty()
                    || projection.signed_projection_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
            })
            || self.compatibility_generations.iter().any(|generation| {
                generation.segment_generation == 0
                    || generation.segment_generation.checked_add(1) != Some(self.segment_generation)
                    || generation.segment_content_hash == [0; 32]
                    || generation.signed_segment_envelope.is_empty()
                    || generation.signed_segment_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
                    || generation.peer_projection_catalog.is_empty()
                    || generation.peer_projection_catalog.len() > MAX_PROJECTIONS
                    || generation.peer_projection_catalog.iter().any(|projection| {
                        projection.projection_id == self.projection_id
                            || projection.projection_id.is_nil()
                            || projection.projection_generation == 0
                            || projection.projection_content_hash == [0; 32]
                            || projection.signed_projection_envelope.is_empty()
                            || projection.signed_projection_envelope.len() > MAX_SIGNED_ENVELOPE_LEN
                    })
            })
        {
            return Err(RuntimeConfigurationError::InvalidRecord);
        }
        Ok(())
    }
}

#[cfg(test)]
mod runtime_configuration_tests {
    use super::*;

    fn record(catalog: Vec<RuntimePeerProjection>) -> RuntimeConfigurationRecord {
        RuntimeConfigurationRecord {
            projection_publication_id: Uuid::from_bytes([1; 16]),
            projection_id: Uuid::from_bytes([2; 16]),
            tenant_id: Uuid::from_bytes([3; 16]),
            segment_id: Uuid::from_bytes([4; 16]),
            site_id: Uuid::from_bytes([5; 16]),
            attachment_id: Uuid::from_bytes([6; 16]),
            device_id: Uuid::from_bytes([7; 16]),
            device_key_id: Uuid::from_bytes([8; 16]),
            segment_generation: 1,
            segment_content_hash: [9; 32],
            projection_generation: 1,
            projection_content_hash: [10; 32],
            signed_segment_envelope: vec![11],
            signed_projection_envelope: vec![12],
            peer_projection_catalog: catalog,
            compatibility_generations: Vec::new(),
            activation_phase: RuntimeConfigurationActivationPhase::Commit,
        }
    }

    fn peer(byte: u8) -> RuntimePeerProjection {
        RuntimePeerProjection {
            projection_id: Uuid::from_bytes([byte; 16]),
            projection_generation: u64::from(byte),
            projection_content_hash: [byte; 32],
            signed_projection_envelope: vec![byte],
        }
    }

    #[test]
    fn runtime_configuration_hash_covers_ordered_peer_catalog() {
        let empty = record(Vec::new()).envelope_sha256();
        let one = record(vec![peer(1)]).envelope_sha256();
        let two = record(vec![peer(1), peer(2)]).envelope_sha256();
        let reordered = record(vec![peer(2), peer(1)]).envelope_sha256();
        assert_ne!(empty, one);
        assert_ne!(one, two);
        assert_ne!(two, reordered);

        let mut compatible = record(vec![peer(1)]);
        compatible.segment_generation = 2;
        compatible.compatibility_generations = vec![RuntimeCompatibilityGeneration {
            segment_generation: 1,
            segment_content_hash: [13; 32],
            signed_segment_envelope: vec![14],
            peer_projection_catalog: vec![peer(1)],
        }];
        assert_ne!(one, compatible.envelope_sha256());
        assert!(compatible
            .validate(&RuntimeConfigurationLookup {
                tenant_id: compatible.tenant_id,
                device_id: compatible.device_id,
                device_key_id: compatible.device_key_id,
            })
            .is_ok());

        compatible.compatibility_generations[0].peer_projection_catalog = vec![peer(2)];
        assert!(matches!(
            compatible.validate(&RuntimeConfigurationLookup {
                tenant_id: compatible.tenant_id,
                device_id: compatible.device_id,
                device_key_id: compatible.device_key_id,
            }),
            Err(RuntimeConfigurationError::InvalidRecord)
        ));
        compatible.compatibility_generations[0].peer_projection_catalog = vec![peer(1)];

        compatible.segment_generation = 3;
        assert!(matches!(
            compatible.validate(&RuntimeConfigurationLookup {
                tenant_id: compatible.tenant_id,
                device_id: compatible.device_id,
                device_key_id: compatible.device_key_id,
            }),
            Err(RuntimeConfigurationError::InvalidRecord)
        ));
    }

    #[test]
    fn compatibility_catalog_accepts_the_full_remote_peer_limit() {
        let remote_peers = (0..MAX_PROJECTIONS)
            .map(|index| RuntimePeerProjection {
                projection_id: Uuid::from_u128(u128::try_from(index).unwrap() + 1_000),
                projection_generation: u64::try_from(index + 1).unwrap(),
                projection_content_hash: [1; 32],
                signed_projection_envelope: vec![1],
            })
            .collect::<Vec<_>>();
        let mut configuration = record(Vec::new());
        configuration.segment_generation = 2;
        configuration.compatibility_generations = vec![RuntimeCompatibilityGeneration {
            segment_generation: 1,
            segment_content_hash: [13; 32],
            signed_segment_envelope: vec![14],
            peer_projection_catalog: remote_peers,
        }];
        let lookup = RuntimeConfigurationLookup {
            tenant_id: configuration.tenant_id,
            device_id: configuration.device_id,
            device_key_id: configuration.device_key_id,
        };
        assert!(configuration.validate(&lookup).is_ok());

        configuration.compatibility_generations[0]
            .peer_projection_catalog
            .push(peer(1));
        assert!(matches!(
            configuration.validate(&lookup),
            Err(RuntimeConfigurationError::InvalidRecord)
        ));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeConfigurationState {
    Unassigned,
    Current(Box<RuntimeConfigurationRecord>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigurationApplyState {
    Prepared,
    Active,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigurationStatusWrite {
    pub lookup: RuntimeConfigurationLookup,
    pub projection_publication_id: Uuid,
    pub projection_content_hash: [u8; 32],
    pub envelope_sha256: [u8; 32],
    pub apply_state: RuntimeConfigurationApplyState,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLifecycle {
    Starting,
    Active,
    Degraded,
    FailOpen,
    Stopped,
    Unknown,
}

impl RuntimeLifecycle {
    fn database_value(self) -> &'static str {
        match self {
            Self::Starting => "STARTING",
            Self::Active => "ACTIVE",
            Self::Degraded => "DEGRADED",
            Self::FailOpen => "FAIL_OPEN",
            Self::Stopped => "STOPPED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTelemetryWrite {
    pub lookup: RuntimeConfigurationLookup,
    pub boot_id: Uuid,
    pub sequence: u64,
    pub lifecycle: RuntimeLifecycle,
    pub configured_peers: u32,
    pub active_peers: u32,
    pub required_route_owners: u32,
    pub ready_route_owners: u32,
    pub fail_open_required: bool,
    pub last_error_code: Option<String>,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_ppm: Option<u32>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub reconnects: Option<u64>,
    pub path_changes: Option<u64>,
    pub paths: Vec<RuntimePathTelemetryWrite>,
    pub local_networks: Option<Vec<RuntimeLocalNetworkTelemetryWrite>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeLocalNetworkTelemetryWrite {
    pub network_id: String,
    pub interface_name: String,
    pub cidr: String,
    pub address: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimePathTelemetryWrite {
    pub peer_attachment_id: Uuid,
    pub candidate_id: Option<Uuid>,
    pub path_kind: RuntimePathKind,
    pub transport: String,
    pub connection_epoch: u64,
    pub rtt_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub packet_loss_ppm: Option<u32>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
    pub reconnects: u64,
    pub path_changes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePathKind {
    Direct,
    Relay,
}

impl RuntimePathKind {
    fn database_value(self) -> &'static str {
        match self {
            Self::Direct => "DIRECT",
            Self::Relay => "RELAY",
        }
    }
}

impl RuntimeTelemetryWrite {
    fn validate(&self) -> Result<(), RuntimeConfigurationError> {
        self.lookup.validate()?;
        let error_is_valid = self.last_error_code.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 80
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        });
        if self.boot_id.is_nil()
            || self.sequence == 0
            || self.active_peers > self.configured_peers
            || self.ready_route_owners > self.required_route_owners
            || self.ready_route_owners > self.active_peers
            || self.packet_loss_ppm.is_some_and(|value| value > 1_000_000)
            || matches!(self.lifecycle, RuntimeLifecycle::FailOpen) != self.fail_open_required
            || !error_is_valid
            || self.paths.len() > MAX_RUNTIME_PATHS
            || self
                .local_networks
                .as_ref()
                .is_some_and(|networks| networks.len() > MAX_RUNTIME_LOCAL_NETWORKS)
        {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        let mut peer_attachments = HashSet::with_capacity(self.paths.len());
        if self.paths.iter().any(|path| {
            path.peer_attachment_id.is_nil()
                || path.candidate_id.is_some_and(|value| value.is_nil())
                || path.transport != "quic_udp"
                || path.connection_epoch == 0
                || path.packet_loss_ppm.is_some_and(|value| value > 1_000_000)
                || !peer_attachments.insert(path.peer_attachment_id)
        }) {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        if self
            .local_networks
            .as_ref()
            .is_some_and(|networks| !validate_runtime_local_networks(networks))
        {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        Ok(())
    }
}

pub(crate) fn validate_runtime_local_networks(
    networks: &[RuntimeLocalNetworkTelemetryWrite],
) -> bool {
    if networks.len() > MAX_RUNTIME_LOCAL_NETWORKS {
        return false;
    }
    let mut network_ids = HashSet::with_capacity(networks.len());
    !networks.iter().any(|network| {
        network.network_id.len() != 64
            || !network
                .network_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !valid_runtime_token(&network.interface_name, 64, b"_.:-@")
            || network.kind != "direct_ipv4"
            || !valid_runtime_network(&network.cidr, &network.address)
            || !network_ids.insert(network.network_id.as_str())
    })
}

fn valid_runtime_token(value: &str, maximum: usize, punctuation: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || punctuation.contains(&byte))
}

fn valid_runtime_network(cidr: &str, address: &str) -> bool {
    if cidr.is_empty() || cidr.len() > 64 || address.is_empty() || address.len() > 45 {
        return false;
    }
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || prefix.bytes().any(|byte| !byte.is_ascii_digit()) {
        return false;
    }
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(address) = address.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(network);
    network == (u32::from(address) & mask) && network == (network & mask)
}

impl RuntimeConfigurationStatusWrite {
    fn validate(&self) -> Result<(), RuntimeConfigurationError> {
        self.lookup.validate()?;
        let error_is_valid = self.error_code.as_deref().is_none_or(|value| {
            !value.is_empty()
                && value.len() <= 80
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        });
        if self.projection_publication_id.is_nil()
            || self.projection_content_hash == [0; 32]
            || self.envelope_sha256 == [0; 32]
            || !error_is_valid
            || matches!(self.apply_state, RuntimeConfigurationApplyState::Rejected)
                == self.error_code.is_none()
        {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        Ok(())
    }
}

impl RuntimeConfigurationApplyState {
    fn database_value(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Active => "ACTIVE",
            Self::Rejected => "REJECTED",
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigurationError {
    #[error("invalid Runtime configuration scope")]
    InvalidScope,
    #[error("device has multiple active Runtime attachments or projections")]
    AmbiguousConfiguration,
    #[error("an active attachment has no projection for the current Segment publication")]
    MissingCurrentProjection,
    #[error("persisted Runtime configuration is invalid")]
    InvalidRecord,
    #[error("the reported Runtime configuration is no longer current")]
    StaleConfiguration,
    #[error("database error: {0}")]
    Database(String),
}

impl From<sqlx::Error> for RuntimeConfigurationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

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
    pub transport_nodes: Vec<(Uuid, Uuid)>,
    pub runtime_paths: Vec<RuntimeProjectionPathCatalogWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProjectionPathCatalogWrite {
    pub candidate_id: Uuid,
    pub peer_attachment_id: Uuid,
    pub path_kind: RuntimePathKind,
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
    pub expires_at: u64,
    pub stale_until: u64,
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
        if self.expires_at == 0 || self.stale_until <= self.expires_at {
            return Err(SdwanError::InvalidScope);
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
            let mut transport_nodes = HashSet::new();
            if projection.transport_nodes.is_empty()
                || projection
                    .transport_nodes
                    .iter()
                    .any(|(node_id, node_key_id)| {
                        node_id.is_nil()
                            || node_key_id.is_nil()
                            || !transport_nodes.insert((*node_id, *node_key_id))
                    })
            {
                return Err(SdwanError::InvalidScope);
            }
            if !row_ids.insert(projection.publication_id)
                || !projection_versions
                    .insert((projection.projection_id, projection.projection_generation))
                || !attachments.insert(projection.attachment_id)
                || !devices.insert((projection.device_id, projection.device_key_id))
            {
                return Err(SdwanError::DuplicateProjection);
            }
            let mut candidates = HashSet::new();
            if projection.runtime_paths.is_empty()
                || projection.runtime_paths.len() > MAX_RUNTIME_PATHS
                || projection.runtime_paths.iter().any(|path| {
                    path.candidate_id.is_nil()
                        || path.peer_attachment_id.is_nil()
                        || path.peer_attachment_id == projection.attachment_id
                        || !candidates.insert(path.candidate_id)
                })
            {
                return Err(SdwanError::InvalidScope);
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
    #[error("stored publication content hash is invalid")]
    InvalidContentHash,
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

fn decode_hash(value: &[u8]) -> Result<[u8; 32], SdwanError> {
    value.try_into().map_err(|_| SdwanError::InvalidContentHash)
}

#[derive(Clone)]
pub struct SdwanRepository {
    pool: DbPool,
}

impl SdwanRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn current_runtime_configuration(
        &self,
        lookup: &RuntimeConfigurationLookup,
    ) -> Result<RuntimeConfigurationState, RuntimeConfigurationError> {
        lookup.validate()?;
        let mut transaction = self.pool.begin().await?;
        let result = load_current_runtime_configuration(&mut transaction, lookup, false).await;
        match result {
            Ok(configuration) => {
                transaction.commit().await?;
                Ok(configuration)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    pub async fn runtime_device_profile(
        &self,
        lookup: &RuntimeConfigurationLookup,
    ) -> Result<RuntimeDeviceProfile, RuntimeConfigurationError> {
        lookup.validate()?;
        let rows = sqlx::query(
            "SELECT org.id AS organization_id, org.name AS organization_name, t.id AS tenant_id, t.name AS tenant_name, d.id AS device_id, dk.id AS device_key_id, d.display_name AS device_name, a.id AS attachment_id, a.site_id, s.name AS site_name, a.segment_id, seg.name AS segment_name FROM tenants t JOIN organizations org ON org.id = t.organization_id AND org.status = 'ACTIVE' JOIN devices d ON d.tenant_id = t.id AND d.id = ? AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.tenant_id = t.id AND dk.device_id = d.id AND dk.id = ? AND dk.status = 'ACTIVE' LEFT JOIN segment_attachments a ON a.tenant_id = t.id AND a.device_id = d.id AND a.device_key_id = dk.id AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY') LEFT JOIN sites s ON s.tenant_id = t.id AND s.id = a.site_id AND s.state = 'ACTIVE' LEFT JOIN segments seg ON seg.tenant_id = t.id AND seg.id = a.segment_id AND seg.state = 'ACTIVE' WHERE t.id = ? AND t.status = 'ACTIVE' ORDER BY a.id",
        )
        .bind(lookup.device_id)
        .bind(lookup.device_key_id)
        .bind(lookup.tenant_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.len() != 1 {
            return Err(if rows.is_empty() {
                RuntimeConfigurationError::InvalidScope
            } else {
                RuntimeConfigurationError::AmbiguousConfiguration
            });
        }
        let row = &rows[0];
        let site_id: Option<Uuid> = row.try_get("site_id")?;
        let segment_id: Option<Uuid> = row.try_get("segment_id")?;
        let peer_sites = if let (Some(site_id), Some(segment_id)) = (site_id, segment_id) {
            sqlx::query(
                "SELECT DISTINCT a.site_id, s.name AS site_name FROM segment_attachments a JOIN sites s ON s.tenant_id = a.tenant_id AND s.id = a.site_id AND s.state = 'ACTIVE' WHERE a.tenant_id = ? AND a.segment_id = ? AND a.site_id <> ? AND a.state IN ('ACTIVE','STANDBY') ORDER BY s.name, a.site_id LIMIT 4097",
            )
            .bind(lookup.tenant_id)
            .bind(segment_id)
            .bind(site_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|peer| {
                Ok(RuntimePeerSiteProfile {
                    site_id: peer.try_get("site_id")?,
                    site_name: peer.try_get("site_name")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?
        } else {
            Vec::new()
        };
        if peer_sites.len() > MAX_PROJECTIONS {
            return Err(RuntimeConfigurationError::InvalidScope);
        }
        Ok(RuntimeDeviceProfile {
            organization_id: row.try_get("organization_id")?,
            organization_name: row.try_get("organization_name")?,
            tenant_id: row.try_get("tenant_id")?,
            tenant_name: row.try_get("tenant_name")?,
            device_id: row.try_get("device_id")?,
            device_key_id: row.try_get("device_key_id")?,
            device_name: row.try_get("device_name")?,
            site_id,
            site_name: row.try_get("site_name")?,
            segment_id,
            segment_name: row.try_get("segment_name")?,
            attachment_id: row.try_get("attachment_id")?,
            peer_sites,
        })
    }

    pub async fn record_runtime_configuration_status(
        &self,
        status: &RuntimeConfigurationStatusWrite,
    ) -> Result<(), RuntimeConfigurationError> {
        status.validate()?;
        let mut transaction = self.pool.begin().await?;
        let configuration =
            load_current_runtime_configuration(&mut transaction, &status.lookup, true).await?;
        let RuntimeConfigurationState::Current(configuration) = configuration else {
            transaction.rollback().await?;
            return Err(RuntimeConfigurationError::StaleConfiguration);
        };
        if configuration.projection_publication_id != status.projection_publication_id
            || configuration.projection_content_hash != status.projection_content_hash
        {
            transaction.rollback().await?;
            return Err(RuntimeConfigurationError::StaleConfiguration);
        }
        let device_name: String = sqlx::query_scalar(
            "SELECT display_name FROM devices WHERE tenant_id = ? AND id = ? AND status = 'ACTIVE'",
        )
        .bind(status.lookup.tenant_id)
        .bind(status.lookup.device_id)
        .fetch_one(&mut *transaction)
        .await?;
        let previous_status: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT projection_publication_id, apply_state, error_code FROM runtime_configuration_status WHERE tenant_id = ? AND device_id = ? AND device_key_id = ? FOR UPDATE",
        )
        .bind(status.lookup.tenant_id)
        .bind(status.lookup.device_id)
        .bind(status.lookup.device_key_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO runtime_configuration_status (tenant_id, device_id, device_key_id, projection_publication_id, envelope_sha256, apply_state, error_code, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE projection_publication_id = VALUES(projection_publication_id), envelope_sha256 = VALUES(envelope_sha256), apply_state = VALUES(apply_state), error_code = VALUES(error_code), reported_at = VALUES(reported_at)",
        )
        .bind(status.lookup.tenant_id)
        .bind(status.lookup.device_id)
        .bind(status.lookup.device_key_id)
        .bind(configuration.projection_publication_id)
        .bind(status.envelope_sha256.as_slice())
        .bind(status.apply_state.database_value())
        .bind(status.error_code.as_deref())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let device_update = sqlx::query("UPDATE devices SET last_seen_at = ? WHERE tenant_id = ? AND id = ? AND status = 'ACTIVE'")
            .bind(now)
            .bind(status.lookup.tenant_id)
            .bind(status.lookup.device_id)
            .execute(&mut *transaction)
            .await?;
        if device_update.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(RuntimeConfigurationError::StaleConfiguration);
        }

        let apply_state = status.apply_state.database_value();
        let status_changed = previous_status.as_ref().is_none_or(
            |(publication_id, previous_state, previous_error)| {
                *publication_id != configuration.projection_publication_id
                    || previous_state != apply_state
                    || previous_error.as_deref() != status.error_code.as_deref()
            },
        );
        if status_changed {
            let action = match status.apply_state {
                RuntimeConfigurationApplyState::Prepared => "RUNTIME_CONFIGURATION_PREPARED",
                RuntimeConfigurationApplyState::Active => "RUNTIME_CONFIGURATION_ACTIVATED",
                RuntimeConfigurationApplyState::Rejected => "RUNTIME_CONFIGURATION_REJECTED",
            };
            sqlx::query(
                "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'DEVICE', ?, ?, 'DEVICE', ?, JSON_OBJECT('device_name', ?, 'projection_publication_id', ?, 'segment_generation', ?, 'projection_generation', ?, 'previous_state', ?, 'state', ?, 'error_code', ?))",
            )
            .bind(Uuid::now_v7())
            .bind(status.lookup.tenant_id)
            .bind(status.lookup.device_id.to_string())
            .bind(action)
            .bind(status.lookup.device_id.to_string())
            .bind(&device_name)
            .bind(configuration.projection_publication_id.to_string())
            .bind(configuration.segment_generation)
            .bind(configuration.projection_generation)
            .bind(previous_status.as_ref().map(|(_, state, _)| state.as_str()))
            .bind(apply_state)
            .bind(status.error_code.as_deref())
            .execute(&mut *transaction)
            .await?;
        }

        let rollout_member: Option<(u32, u32, String)> = sqlx::query_as(
            "SELECT member.rollout_ordinal, rollout.member_count, rollout.state FROM segment_route_publication_members member JOIN runtime_configuration_rollouts rollout ON rollout.tenant_id = member.tenant_id AND rollout.segment_id = ? AND rollout.segment_generation = ? WHERE member.tenant_id = ? AND member.projection_publication_id = ? FOR UPDATE",
        )
        .bind(configuration.segment_id)
        .bind(configuration.segment_generation)
        .bind(status.lookup.tenant_id)
        .bind(configuration.projection_publication_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((_ordinal, member_count, rollout_state)) = rollout_member {
            match status.apply_state {
                RuntimeConfigurationApplyState::Prepared if rollout_state == "PREPARING" => {
                    let prepared_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM segment_route_publication_members member JOIN site_route_projection_publications projection ON projection.id = member.projection_publication_id LEFT JOIN runtime_configuration_status status ON status.tenant_id = projection.tenant_id AND status.device_id = projection.device_id AND status.device_key_id = projection.device_key_id AND status.projection_publication_id = projection.id WHERE member.tenant_id = ? AND member.segment_publication_id = (SELECT id FROM segment_route_publications WHERE tenant_id = ? AND segment_id = ? AND generation = ?) AND status.apply_state = 'PREPARED'",
                    )
                    .bind(status.lookup.tenant_id)
                    .bind(status.lookup.tenant_id)
                    .bind(configuration.segment_id)
                    .bind(configuration.segment_generation)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if prepared_count == i64::from(member_count) {
                        sqlx::query(
                            "UPDATE runtime_configuration_rollouts SET state = 'COMMITTING' WHERE tenant_id = ? AND segment_id = ? AND segment_generation = ? AND state = 'PREPARING'",
                        )
                        .bind(status.lookup.tenant_id)
                        .bind(configuration.segment_id)
                        .bind(configuration.segment_generation)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                RuntimeConfigurationApplyState::Active if rollout_state == "COMMITTING" => {
                    let active_count: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM segment_route_publication_members member JOIN site_route_projection_publications projection ON projection.id = member.projection_publication_id LEFT JOIN runtime_configuration_status status ON status.tenant_id = projection.tenant_id AND status.device_id = projection.device_id AND status.device_key_id = projection.device_key_id AND status.projection_publication_id = projection.id WHERE member.tenant_id = ? AND member.segment_publication_id = (SELECT id FROM segment_route_publications WHERE tenant_id = ? AND segment_id = ? AND generation = ?) AND status.apply_state = 'ACTIVE'",
                    )
                    .bind(status.lookup.tenant_id)
                    .bind(status.lookup.tenant_id)
                    .bind(configuration.segment_id)
                    .bind(configuration.segment_generation)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if active_count == i64::from(member_count) {
                        sqlx::query(
                            "UPDATE runtime_configuration_rollouts SET state = 'COMPLETE' WHERE tenant_id = ? AND segment_id = ? AND segment_generation = ? AND state = 'COMMITTING'",
                        )
                        .bind(status.lookup.tenant_id)
                        .bind(configuration.segment_id)
                        .bind(configuration.segment_generation)
                        .execute(&mut *transaction)
                        .await?;
                    }
                }
                RuntimeConfigurationApplyState::Rejected => {
                    sqlx::query(
                        "UPDATE runtime_configuration_rollouts SET state = 'BLOCKED' WHERE tenant_id = ? AND segment_id = ? AND segment_generation = ? AND state IN ('PREPARING','COMMITTING')",
                    )
                    .bind(status.lookup.tenant_id)
                    .bind(configuration.segment_id)
                    .bind(configuration.segment_generation)
                    .execute(&mut *transaction)
                    .await?;
                }
                _ => {
                    transaction.rollback().await?;
                    return Err(RuntimeConfigurationError::StaleConfiguration);
                }
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn record_runtime_telemetry(
        &self,
        telemetry: &RuntimeTelemetryWrite,
    ) -> Result<(), RuntimeConfigurationError> {
        telemetry.validate()?;
        let mut transaction = self.pool.begin().await?;
        let device_name = sqlx::query_scalar::<_, String>(
            "SELECT d.display_name FROM devices d JOIN device_keys k ON k.tenant_id = d.tenant_id AND k.device_id = d.id WHERE d.tenant_id = ? AND d.id = ? AND d.status = 'ACTIVE' AND k.id = ? AND k.status = 'ACTIVE' LIMIT 1",
        )
        .bind(telemetry.lookup.tenant_id)
        .bind(telemetry.lookup.device_id)
        .bind(telemetry.lookup.device_key_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(device_name) = device_name else {
            transaction.rollback().await?;
            return Err(RuntimeConfigurationError::InvalidScope);
        };
        let mut persisted_paths = telemetry.paths.as_slice();
        if !telemetry.paths.is_empty() {
            let committed_projection: Option<(Uuid, Uuid)> = sqlx::query_as(
                "SELECT projection.id, projection.attachment_id FROM runtime_configuration_status status JOIN site_route_projection_publications projection ON projection.tenant_id = status.tenant_id AND projection.device_id = status.device_id AND projection.device_key_id = status.device_key_id AND projection.id = status.projection_publication_id JOIN segment_attachments attachment ON attachment.tenant_id = projection.tenant_id AND attachment.id = projection.attachment_id AND attachment.device_id = projection.device_id AND attachment.device_key_id = projection.device_key_id AND attachment.principal_kind = 'DEVICE' WHERE status.tenant_id = ? AND status.device_id = ? AND status.device_key_id = ? AND status.apply_state = 'ACTIVE' FOR SHARE",
            )
            .bind(telemetry.lookup.tenant_id)
            .bind(telemetry.lookup.device_id)
            .bind(telemetry.lookup.device_key_id)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some((projection_publication_id, local_attachment_id)) = committed_projection
            else {
                transaction.rollback().await?;
                return Err(RuntimeConfigurationError::InvalidScope);
            };
            let catalog = sqlx::query(
                "SELECT candidate_id, source_attachment_id, destination_attachment_id, path_kind FROM runtime_projection_path_catalog WHERE tenant_id = ? AND projection_publication_id = ?",
            )
            .bind(telemetry.lookup.tenant_id)
            .bind(projection_publication_id)
            .fetch_all(&mut *transaction)
            .await?;
            if catalog.is_empty() {
                // Publications created before the immutable path catalog cannot
                // safely authorize path identities. Preserve their aggregate
                // heartbeat during rolling activation, but retain no path data.
                persisted_paths = &[];
            } else {
                let mut authorized_candidates = HashSet::new();
                let mut authorized_peers = HashSet::new();
                for row in catalog {
                    let source_attachment_id: Uuid = row.try_get("source_attachment_id")?;
                    if source_attachment_id != local_attachment_id {
                        transaction.rollback().await?;
                        return Err(RuntimeConfigurationError::InvalidRecord);
                    }
                    let path_kind = match row.try_get::<String, _>("path_kind")?.as_str() {
                        "DIRECT" => RuntimePathKind::Direct,
                        "RELAY" => RuntimePathKind::Relay,
                        _ => {
                            transaction.rollback().await?;
                            return Err(RuntimeConfigurationError::InvalidRecord);
                        }
                    };
                    let peer_attachment_id: Uuid = row.try_get("destination_attachment_id")?;
                    authorized_peers.insert((peer_attachment_id, path_kind));
                    authorized_candidates.insert((
                        row.try_get::<Uuid, _>("candidate_id")?,
                        peer_attachment_id,
                        path_kind,
                    ));
                }
                for path in &telemetry.paths {
                    let Some(candidate_id) = path.candidate_id else {
                        if !authorized_peers.contains(&(path.peer_attachment_id, path.path_kind)) {
                            transaction.rollback().await?;
                            return Err(RuntimeConfigurationError::InvalidScope);
                        }
                        continue;
                    };
                    if !authorized_candidates.contains(&(
                        candidate_id,
                        path.peer_attachment_id,
                        path.path_kind,
                    )) {
                        transaction.rollback().await?;
                        return Err(RuntimeConfigurationError::InvalidScope);
                    }
                }
            }
        }
        let current: Option<(Uuid, u64, String, bool, Option<String>)> = sqlx::query_as(
            "SELECT boot_id, sequence, lifecycle, fail_open_required, last_error_code FROM runtime_telemetry_latest WHERE tenant_id = ? AND device_id = ? AND device_key_id = ? FOR UPDATE",
        )
        .bind(telemetry.lookup.tenant_id)
        .bind(telemetry.lookup.device_id)
        .bind(telemetry.lookup.device_key_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if current
            .as_ref()
            .is_some_and(|(boot_id, sequence, _, _, _)| {
                *boot_id == telemetry.boot_id && *sequence >= telemetry.sequence
            })
        {
            transaction.commit().await?;
            return Ok(());
        }
        let now = Utc::now();
        let paths_json = serde_json::to_string(persisted_paths)
            .map_err(|_| RuntimeConfigurationError::InvalidScope)?;
        let local_networks_present = telemetry.local_networks.is_some();
        let local_networks_json =
            serde_json::to_string(telemetry.local_networks.as_deref().unwrap_or(&[]))
                .map_err(|_| RuntimeConfigurationError::InvalidScope)?;
        sqlx::query(
            "INSERT INTO runtime_telemetry_latest (tenant_id, device_id, device_key_id, boot_id, sequence, lifecycle, configured_peers, active_peers, required_route_owners, ready_route_owners, fail_open_required, last_error_code, rtt_ms, jitter_ms, packet_loss_ppm, rx_bps, tx_bps, reconnects, path_changes, paths_json, local_networks_json, reported_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS JSON), IF(? = 1, CAST(? AS JSON), JSON_ARRAY()), ?) ON DUPLICATE KEY UPDATE boot_id = VALUES(boot_id), sequence = VALUES(sequence), lifecycle = VALUES(lifecycle), configured_peers = VALUES(configured_peers), active_peers = VALUES(active_peers), required_route_owners = VALUES(required_route_owners), ready_route_owners = VALUES(ready_route_owners), fail_open_required = VALUES(fail_open_required), last_error_code = VALUES(last_error_code), rtt_ms = VALUES(rtt_ms), jitter_ms = VALUES(jitter_ms), packet_loss_ppm = VALUES(packet_loss_ppm), rx_bps = VALUES(rx_bps), tx_bps = VALUES(tx_bps), reconnects = VALUES(reconnects), path_changes = VALUES(path_changes), paths_json = VALUES(paths_json), local_networks_json = IF(? = 1, VALUES(local_networks_json), local_networks_json), reported_at = VALUES(reported_at)",
        )
        .bind(telemetry.lookup.tenant_id)
        .bind(telemetry.lookup.device_id)
        .bind(telemetry.lookup.device_key_id)
        .bind(telemetry.boot_id)
        .bind(telemetry.sequence)
        .bind(telemetry.lifecycle.database_value())
        .bind(telemetry.configured_peers)
        .bind(telemetry.active_peers)
        .bind(telemetry.required_route_owners)
        .bind(telemetry.ready_route_owners)
        .bind(telemetry.fail_open_required)
        .bind(telemetry.last_error_code.as_deref())
        .bind(telemetry.rtt_ms)
        .bind(telemetry.jitter_ms)
        .bind(telemetry.packet_loss_ppm)
        .bind(telemetry.rx_bps)
        .bind(telemetry.tx_bps)
        .bind(telemetry.reconnects)
        .bind(telemetry.path_changes)
        .bind(paths_json)
        .bind(local_networks_present)
        .bind(local_networks_json)
        .bind(now)
        .bind(local_networks_present)
        .execute(&mut *transaction)
        .await?;
        let lifecycle = telemetry.lifecycle.database_value();
        let transition = current.as_ref().and_then(
            |(_, _, previous_lifecycle, previous_fail_open, previous_error)| {
                if *previous_fail_open != telemetry.fail_open_required {
                    Some(if telemetry.fail_open_required {
                        "RUNTIME_FAIL_OPEN_ENTERED"
                    } else {
                        "RUNTIME_FAIL_OPEN_RECOVERED"
                    })
                } else if previous_lifecycle != lifecycle
                    || previous_error.as_deref() != telemetry.last_error_code.as_deref()
                {
                    Some(if lifecycle == "ACTIVE" {
                        "RUNTIME_LIFECYCLE_RECOVERED"
                    } else {
                        "RUNTIME_LIFECYCLE_DEGRADED"
                    })
                } else {
                    None
                }
            },
        );
        let first_unhealthy = current.is_none()
            && (telemetry.fail_open_required
                || !matches!(telemetry.lifecycle, RuntimeLifecycle::Active));
        if let Some(action) =
            transition.or(first_unhealthy.then_some(if telemetry.fail_open_required {
                "RUNTIME_FAIL_OPEN_ENTERED"
            } else {
                "RUNTIME_LIFECYCLE_DEGRADED"
            }))
        {
            sqlx::query(
                "INSERT INTO audit_events (id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, 'DEVICE', ?, ?, 'DEVICE', ?, JSON_OBJECT('device_name', ?, 'previous_lifecycle', ?, 'lifecycle', ?, 'fail_open_required', ?, 'previous_error_code', ?, 'error_code', ?, 'configured_peers', ?, 'active_peers', ?, 'required_route_owners', ?, 'ready_route_owners', ?))",
            )
            .bind(Uuid::now_v7())
            .bind(telemetry.lookup.tenant_id)
            .bind(telemetry.lookup.device_id.to_string())
            .bind(action)
            .bind(telemetry.lookup.device_id.to_string())
            .bind(&device_name)
            .bind(current.as_ref().map(|(_, _, lifecycle, _, _)| lifecycle.as_str()))
            .bind(lifecycle)
            .bind(telemetry.fail_open_required)
            .bind(current.as_ref().and_then(|(_, _, _, _, error)| error.as_deref()))
            .bind(telemetry.last_error_code.as_deref())
            .bind(telemetry.configured_peers)
            .bind(telemetry.active_peers)
            .bind(telemetry.required_route_owners)
            .bind(telemetry.ready_route_owners)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE devices SET last_seen_at = ? WHERE tenant_id = ? AND id = ? AND status = 'ACTIVE'",
        )
        .bind(now)
        .bind(telemetry.lookup.tenant_id)
        .bind(telemetry.lookup.device_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn current_head(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> Result<(u64, [u8; 32]), SdwanError> {
        let row = sqlx::query(
            "SELECT current_generation, current_content_hash FROM segments WHERE tenant_id = ? AND id = ? AND state = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SdwanError::SegmentNotFound)?;
        let generation = row.try_get("current_generation")?;
        let hash = row.try_get::<Vec<u8>, _>("current_content_hash")?;
        let hash = decode_hash(&hash)?;
        if (generation == 0 && hash != [0; 32]) || (generation > 0 && hash == [0; 32]) {
            return Err(SdwanError::InvalidContentHash);
        }
        Ok((generation, hash))
    }

    pub async fn segment_head(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> Result<(u64, [u8; 32]), SdwanError> {
        self.current_head(tenant_id, segment_id).await
    }

    /// Materialize the management control graph into the route-contract tables.
    ///
    /// The management API owns `sdwan_control_resources`, while the signed route
    /// publisher and runtime readers intentionally use the older normalized route
    /// contract. Keeping this bridge in the repository makes first publication
    /// deterministic and avoids relying on out-of-band database repair.
    pub async fn ensure_control_topology(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        resources: &[ControlResourceV1],
    ) -> Result<(), SdwanError> {
        let segment = resources
            .iter()
            .find_map(|resource| {
                (resource.metadata.id == segment_id)
                    .then_some(match &resource.resource {
                        ResourceSpecV1::Segment(value) => Some((resource.metadata.state, value)),
                        _ => None,
                    })
                    .flatten()
            })
            .ok_or(SdwanError::SegmentNotFound)?;
        let mut transaction = self.pool.begin().await?;

        for resource in resources {
            if let ResourceSpecV1::Site(site) = &resource.resource {
                let state = route_state(resource.metadata.state);
                sqlx::query(
                    "INSERT INTO sites (id, tenant_id, name, kind, state) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), kind = VALUES(kind), state = VALUES(state)",
                )
                .bind(resource.metadata.id)
                .bind(tenant_id)
                .bind(&site.name)
                .bind(site_kind(site.kind))
                .bind(state)
                .execute(&mut *transaction)
                .await?;
            }
        }

        for resource in resources {
            let ResourceSpecV1::Prefix(prefix) = &resource.resource else {
                continue;
            };
            let state = if resource.metadata.state == ResourceState::Active {
                "ACTIVE"
            } else {
                "DISABLED"
            };
            sqlx::query(
                "INSERT INTO site_prefixes (id, tenant_id, site_id, network, prefix_len, state) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE site_id = VALUES(site_id), network = VALUES(network), prefix_len = VALUES(prefix_len), state = VALUES(state)",
            )
            .bind(resource.metadata.id)
            .bind(tenant_id)
            .bind(prefix.site_id)
            .bind(prefix.prefix.network.octets().as_slice())
            .bind(prefix.prefix.prefix_len)
            .bind(state)
            .execute(&mut *transaction)
            .await?;
        }

        let hub_pool_id: Uuid = if let Some(pool_id) = sqlx::query_scalar(
            "SELECT id FROM node_pools WHERE tenant_id = ? AND status = 'ACTIVE' ORDER BY created_at, id LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *transaction)
        .await?
        {
            pool_id
        } else {
            let pool_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO node_pools (id, tenant_id, service_class, name, audience, status) VALUES (?, ?, 'PRIVATE', ?, 'tenant-private', 'ACTIVE')",
            )
            .bind(pool_id)
            .bind(tenant_id)
            .bind(format!("cloud-private-{tenant_id}"))
            .execute(&mut *transaction)
            .await?;
            pool_id
        };

        for resource in resources {
            let ResourceSpecV1::Node(node) = &resource.resource else {
                continue;
            };
            let state = match resource.metadata.state {
                ResourceState::Active => "ACTIVE",
                ResourceState::Disabled => "DRAINING",
                ResourceState::Deleted => "REVOKED",
            };
            sqlx::query(
                "INSERT INTO nodes (id, tenant_id, node_pool_id, node_id, device_id, device_key_id, status) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE tenant_id = VALUES(tenant_id), node_pool_id = VALUES(node_pool_id), node_id = VALUES(node_id), device_id = VALUES(device_id), device_key_id = VALUES(device_key_id), status = VALUES(status)",
            )
            .bind(resource.metadata.id)
            .bind(tenant_id)
            .bind(hub_pool_id)
            .bind(resource.metadata.id.to_string())
            .bind(node.device_id)
            .bind(node.device_key_id)
            .bind(state)
            .execute(&mut *transaction)
            .await?;
        }

        let state = route_state(segment.0);
        sqlx::query(
            "INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len, state) VALUES (?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), hub_node_pool_id = VALUES(hub_node_pool_id), overlay_network = VALUES(overlay_network), overlay_prefix_len = VALUES(overlay_prefix_len), state = VALUES(state)",
        )
        .bind(segment_id)
        .bind(tenant_id)
        .bind(&segment.1.name)
        .bind(hub_pool_id)
        .bind(segment.1.overlay_prefix.network.octets().as_slice())
        .bind(segment.1.overlay_prefix.prefix_len)
        .bind(state)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "UPDATE segment_attachments SET state = 'REVOKED' WHERE tenant_id = ? AND segment_id = ? AND principal_kind = 'DEVICE' AND state IN ('ACTIVE','STANDBY')",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .execute(&mut *transaction)
        .await?;
        for resource in resources {
            let ResourceSpecV1::Attachment(attachment) = &resource.resource else {
                continue;
            };
            let Some(node) = resources.iter().find_map(|candidate| {
                (candidate.metadata.id == attachment.node_id)
                    .then_some(match &candidate.resource {
                        ResourceSpecV1::Node(value) => Some(value),
                        _ => None,
                    })
                    .flatten()
            }) else {
                return Err(SdwanError::InvalidScope);
            };
            let state = match resource.metadata.state {
                ResourceState::Active => "ACTIVE",
                ResourceState::Disabled => "DISABLED",
                ResourceState::Deleted => "REVOKED",
            };
            sqlx::query(
                "INSERT INTO segment_attachments (id, tenant_id, segment_id, site_id, principal_kind, device_id, device_key_id, overlay_router_ipv4, state, epoch_floor) VALUES (?, ?, ?, ?, 'DEVICE', ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE site_id = VALUES(site_id), device_id = VALUES(device_id), device_key_id = VALUES(device_key_id), overlay_router_ipv4 = VALUES(overlay_router_ipv4), state = VALUES(state), epoch_floor = VALUES(epoch_floor)",
            )
            .bind(resource.metadata.id)
            .bind(tenant_id)
            .bind(attachment.segment_id)
            .bind(attachment.site_id)
            .bind(node.device_id)
            .bind(node.device_key_id)
            .bind(attachment.overlay_router_ipv4.octets().as_slice())
            .bind(state)
            .bind(attachment.epoch_floor)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn published_generation(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        publication_id: Uuid,
    ) -> Result<Option<(u64, [u8; 32])>, SdwanError> {
        if tenant_id.is_nil() || segment_id.is_nil() || publication_id.is_nil() {
            return Err(SdwanError::InvalidScope);
        }
        let row = sqlx::query(
            "SELECT generation, content_hash FROM segment_route_publications WHERE id = ? AND tenant_id = ? AND segment_id = ?",
        )
        .bind(publication_id)
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let generation = row.try_get("generation")?;
        let hash = decode_hash(&row.try_get::<Vec<u8>, _>("content_hash")?)?;
        if generation == 0 || hash == [0; 32] {
            return Err(SdwanError::InvalidContentHash);
        }
        Ok(Some((generation, hash)))
    }

    pub async fn projection_head(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Option<(u64, [u8; 32])>, SdwanError> {
        let rows = sqlx::query(
            "SELECT projection_generation, previous_hash, content_hash FROM site_route_projection_publications WHERE tenant_id = ? AND segment_id = ? AND attachment_id = ? ORDER BY projection_generation ASC, created_at ASC FOR SHARE",
        )
        .bind(tenant_id)
        .bind(segment_id)
        .bind(attachment_id)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }

        let mut expected_generation = 1_u64;
        let mut previous_content_hash = [0_u8; 32];
        let mut head = None;
        for row in rows {
            let generation: u64 = row.try_get("projection_generation")?;
            let previous_hash = decode_hash(&row.try_get::<Vec<u8>, _>("previous_hash")?)?;
            let content_hash = decode_hash(&row.try_get::<Vec<u8>, _>("content_hash")?)?;
            if generation != expected_generation
                || (generation == 1 && previous_hash != [0; 32])
                || (generation > 1 && previous_hash != previous_content_hash)
                || content_hash == [0; 32]
            {
                return Err(SdwanError::InvalidContentHash);
            }
            previous_content_hash = content_hash;
            head = Some((generation, content_hash));
            expected_generation = expected_generation
                .checked_add(1)
                .ok_or(SdwanError::GenerationGap)?;
        }
        Ok(head)
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
        validate_projection_heads(&mut transaction, write).await?;

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
            "INSERT INTO segment_route_publications (id, tenant_id, segment_id, expected_previous_generation, expected_previous_hash, generation, content_hash, signed_envelope, expires_at, stale_until, audit_event_id, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(write.publication_id)
        .bind(write.tenant_id)
        .bind(write.segment_id)
        .bind(write.expected_previous_generation)
        .bind(write.expected_previous_hash.as_slice())
        .bind(write.generation)
        .bind(write.snapshot.content_hash.as_slice())
        .bind(&write.snapshot.signed_envelope)
        .bind(write.expires_at)
        .bind(write.stale_until)
        .bind(write.audit_event_id)
        .bind(&write.actor_id)
        .execute(&mut *transaction)
        .await?;

        for (index, projection) in write.projections.iter().enumerate() {
            let rollout_ordinal = u32::try_from(index + 1).map_err(|_| SdwanError::InvalidScope)?;
            insert_projection(
                &mut transaction,
                write.publication_id,
                projection,
                rollout_ordinal,
            )
            .await?;
        }
        for expansion in &write.expansions {
            insert_expansion(&mut transaction, write.publication_id, expansion).await?;
        }

        let member_count =
            u32::try_from(write.projections.len()).map_err(|_| SdwanError::InvalidScope)?;
        if member_count > 0 {
            sqlx::query(
                "INSERT INTO runtime_configuration_rollouts (tenant_id, segment_id, segment_generation, allowed_ordinal, member_count, state) VALUES (?, ?, ?, ?, ?, 'PREPARING')",
            )
            .bind(write.tenant_id)
            .bind(write.segment_id)
            .bind(write.generation)
            .bind(member_count)
            .bind(member_count)
            .execute(&mut *transaction)
            .await?;
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

fn route_state(state: ResourceState) -> &'static str {
    match state {
        ResourceState::Active => "ACTIVE",
        ResourceState::Disabled => "DISABLED",
        ResourceState::Deleted => "DELETED",
    }
}

fn site_kind(kind: SiteKindV1) -> &'static str {
    match kind {
        SiteKindV1::Edge => "EDGE",
        SiteKindV1::PrivateCloud => "PRIVATE_CLOUD",
    }
}

async fn load_current_runtime_configuration(
    transaction: &mut Transaction<'_, MySql>,
    lookup: &RuntimeConfigurationLookup,
    lock: bool,
) -> Result<RuntimeConfigurationState, RuntimeConfigurationError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let attachment_query = format!(
        "SELECT a.id FROM segment_attachments a JOIN tenants t ON t.id = a.tenant_id AND t.status = 'ACTIVE' JOIN organizations org ON org.id = t.organization_id AND org.status = 'ACTIVE' JOIN sites s ON s.id = a.site_id AND s.tenant_id = a.tenant_id AND s.state = 'ACTIVE' JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' JOIN devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.id = a.device_key_id AND dk.tenant_id = a.tenant_id AND dk.device_id = d.id AND dk.status = 'ACTIVE' WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY'){suffix}"
    );
    let attachments = sqlx::query(&attachment_query)
        .bind(lookup.tenant_id)
        .bind(lookup.device_id)
        .bind(lookup.device_key_id)
        .fetch_all(&mut **transaction)
        .await?;
    match attachments.len() {
        0 => return Ok(RuntimeConfigurationState::Unassigned),
        1 => {}
        _ => return Err(RuntimeConfigurationError::AmbiguousConfiguration),
    }

    let rollout_query = format!(
        "SELECT seg.current_generation, member.rollout_ordinal, rollout.allowed_ordinal, rollout.state FROM segment_attachments a JOIN tenants t ON t.id = a.tenant_id AND t.status = 'ACTIVE' JOIN organizations org ON org.id = t.organization_id AND org.status = 'ACTIVE' JOIN sites s ON s.id = a.site_id AND s.tenant_id = a.tenant_id AND s.state = 'ACTIVE' JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id AND p.segment_generation = seg.current_generation AND p.segment_content_hash = seg.current_content_hash JOIN segment_route_publications publication ON publication.id = p.publication_id AND publication.tenant_id = p.tenant_id AND publication.segment_id = p.segment_id AND publication.generation = p.segment_generation AND publication.content_hash = p.segment_content_hash JOIN segment_route_publication_members member ON member.tenant_id = p.tenant_id AND member.segment_publication_id = publication.id AND member.projection_publication_id = p.id AND member.projection_id = p.projection_id AND member.attachment_id = p.attachment_id JOIN runtime_configuration_rollouts rollout ON rollout.tenant_id = p.tenant_id AND rollout.segment_id = p.segment_id AND rollout.segment_generation = p.segment_generation WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY'){suffix}"
    );
    let rollout_position: Option<(u64, u32, u32, String)> = sqlx::query_as(&rollout_query)
        .bind(lookup.tenant_id)
        .bind(lookup.device_id)
        .bind(lookup.device_key_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some((current_generation, rollout_ordinal, allowed_ordinal, rollout_state)) =
        rollout_position
    else {
        return Err(RuntimeConfigurationError::MissingCurrentProjection);
    };
    let delivery_generation = if rollout_state == "BLOCKED" {
        current_generation
            .checked_sub(1)
            .ok_or(RuntimeConfigurationError::MissingCurrentProjection)?
    } else if rollout_ordinal <= allowed_ordinal {
        current_generation
    } else {
        current_generation
            .checked_sub(1)
            .ok_or(RuntimeConfigurationError::MissingCurrentProjection)?
    };

    let projection_query = format!(
        "SELECT p.id AS projection_publication_id, p.projection_id, p.tenant_id, p.segment_id, p.site_id, p.attachment_id, p.device_id, p.device_key_id, p.segment_generation, p.segment_content_hash, p.projection_generation, p.content_hash AS projection_content_hash, publication.signed_envelope AS signed_segment_envelope, p.signed_envelope AS signed_projection_envelope FROM segment_attachments a JOIN tenants t ON t.id = a.tenant_id AND t.status = 'ACTIVE' JOIN organizations org ON org.id = t.organization_id AND org.status = 'ACTIVE' JOIN sites s ON s.id = a.site_id AND s.tenant_id = a.tenant_id AND s.state = 'ACTIVE' JOIN segments seg ON seg.id = a.segment_id AND seg.tenant_id = a.tenant_id AND seg.state = 'ACTIVE' JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id AND p.segment_generation = ? JOIN segment_route_publications publication ON publication.id = p.publication_id AND publication.tenant_id = p.tenant_id AND publication.segment_id = p.segment_id AND publication.generation = p.segment_generation AND publication.content_hash = p.segment_content_hash JOIN segment_route_publication_members member ON member.tenant_id = p.tenant_id AND member.segment_publication_id = publication.id AND member.projection_publication_id = p.id AND member.projection_id = p.projection_id AND member.attachment_id = p.attachment_id JOIN runtime_configuration_rollouts rollout ON rollout.tenant_id = p.tenant_id AND rollout.segment_id = p.segment_id AND rollout.segment_generation = p.segment_generation WHERE a.tenant_id = ? AND a.device_id = ? AND a.device_key_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY') AND member.rollout_ordinal <= rollout.allowed_ordinal AND (? = seg.current_generation OR publication.stale_until >= UNIX_TIMESTAMP()){suffix}"
    );
    let mut rows = sqlx::query(&projection_query)
        .bind(delivery_generation)
        .bind(lookup.tenant_id)
        .bind(lookup.device_id)
        .bind(lookup.device_key_id)
        .bind(delivery_generation)
        .fetch_all(&mut **transaction)
        .await?;
    // A device enrolled after a rollout was blocked has no projection for the
    // previous generation.  It must still receive the current projection;
    // otherwise the configuration endpoint returns 204 forever and the new
    // device can never participate in the rollout.
    if rows.is_empty() && delivery_generation != current_generation {
        rows = sqlx::query(&projection_query)
            .bind(current_generation)
            .bind(lookup.tenant_id)
            .bind(lookup.device_id)
            .bind(lookup.device_key_id)
            .bind(current_generation)
            .fetch_all(&mut **transaction)
            .await?;
    }
    if rows.is_empty() {
        return Err(RuntimeConfigurationError::MissingCurrentProjection);
    }
    if rows.len() != 1 {
        return Err(RuntimeConfigurationError::AmbiguousConfiguration);
    }
    let row = &rows[0];
    let tenant_id: Uuid = row.try_get("tenant_id")?;
    let segment_id: Uuid = row.try_get("segment_id")?;
    let projection_id: Uuid = row.try_get("projection_id")?;
    let segment_generation: u64 = row.try_get("segment_generation")?;
    let catalog_rows = sqlx::query(
        "SELECT p.projection_id, p.projection_generation, p.content_hash AS projection_content_hash, p.signed_envelope FROM nodes n JOIN runtime_projection_transport_catalog catalog ON catalog.transport_node_id = n.id AND catalog.transport_node_key_id = n.device_key_id AND catalog.tenant_id = n.tenant_id JOIN site_route_projection_publications p ON p.id = catalog.projection_publication_id AND p.tenant_id = catalog.tenant_id AND p.segment_id = catalog.segment_id AND p.segment_generation = catalog.segment_generation AND p.projection_id = catalog.projection_id WHERE n.tenant_id = ? AND n.device_id = ? AND n.device_key_id = ? AND n.status = 'ACTIVE' AND catalog.segment_id = ? AND catalog.segment_generation = ? AND p.projection_id <> ? ORDER BY p.projection_id, p.projection_generation",
    )
    .bind(lookup.tenant_id)
    .bind(lookup.device_id)
    .bind(lookup.device_key_id)
    .bind(segment_id)
    .bind(segment_generation)
    .bind(projection_id)
    .fetch_all(&mut **transaction)
    .await?;
    if catalog_rows.len() > MAX_PROJECTIONS {
        return Err(RuntimeConfigurationError::AmbiguousConfiguration);
    }
    let mut peer_projection_catalog = Vec::with_capacity(catalog_rows.len());
    let mut catalog_ids = HashSet::new();
    for catalog in catalog_rows {
        let projection_id: Uuid = catalog.try_get("projection_id")?;
        if !catalog_ids.insert(projection_id) {
            return Err(RuntimeConfigurationError::AmbiguousConfiguration);
        }
        peer_projection_catalog.push(RuntimePeerProjection {
            projection_id,
            projection_generation: catalog.try_get("projection_generation")?,
            projection_content_hash: decode_hash(
                &catalog.try_get::<Vec<u8>, _>("projection_content_hash")?,
            )
            .map_err(|_| RuntimeConfigurationError::InvalidRecord)?,
            signed_projection_envelope: catalog.try_get("signed_envelope")?,
        });
    }
    let previous_generation = segment_generation.checked_sub(1);
    // A server may have been enrolled after the previous Segment generation
    // was published. Its transport node therefore has no row in the
    // previous-generation transport catalog, even though the peer
    // projections are still valid during the compatibility window. Select
    // the previous Segment publication independently; Core will validate that
    // each returned peer projection has a path to this server's current
    // transport identity.
    let compatibility_publication = sqlx::query(
        "SELECT publication.generation AS segment_generation, publication.content_hash AS segment_content_hash, publication.signed_envelope AS signed_segment_envelope FROM nodes n JOIN runtime_projection_transport_catalog current_catalog ON current_catalog.transport_node_id = n.id AND current_catalog.transport_node_key_id = n.device_key_id AND current_catalog.tenant_id = n.tenant_id AND current_catalog.segment_id = ? AND current_catalog.segment_generation = ? AND current_catalog.projection_id <> ? JOIN segment_route_publications publication ON publication.tenant_id = current_catalog.tenant_id AND publication.segment_id = current_catalog.segment_id WHERE n.tenant_id = ? AND n.device_id = ? AND n.device_key_id = ? AND n.status = 'ACTIVE' AND publication.generation = ? AND publication.stale_until >= UNIX_TIMESTAMP() LIMIT 1",
    )
    .bind(segment_id)
    .bind(segment_generation)
    .bind(projection_id)
    .bind(lookup.tenant_id)
    .bind(lookup.device_id)
    .bind(lookup.device_key_id)
    .bind(previous_generation.unwrap_or_default())
    .fetch_optional(&mut **transaction)
    .await?;
    let mut compatibility_generations = Vec::new();
    if let Some(publication) = compatibility_publication {
        let compatible_generation: u64 = publication.try_get("segment_generation")?;
        let compatible_catalog_rows = sqlx::query(
            "SELECT p.projection_id, p.projection_generation, p.content_hash AS projection_content_hash, p.signed_envelope FROM segment_attachments a JOIN sites s ON s.id = a.site_id AND s.tenant_id = a.tenant_id AND s.state = 'ACTIVE' JOIN devices d ON d.id = a.device_id AND d.tenant_id = a.tenant_id AND d.status = 'ACTIVE' JOIN device_keys dk ON dk.id = a.device_key_id AND dk.tenant_id = a.tenant_id AND dk.device_id = d.id AND dk.status = 'ACTIVE' JOIN site_route_projection_publications p ON p.tenant_id = a.tenant_id AND p.segment_id = a.segment_id AND p.site_id = a.site_id AND p.attachment_id = a.id AND p.device_id = a.device_id AND p.device_key_id = a.device_key_id AND p.segment_generation = ? JOIN segment_route_publications publication ON publication.id = p.publication_id AND publication.tenant_id = p.tenant_id AND publication.segment_id = p.segment_id AND publication.generation = p.segment_generation AND publication.stale_until >= UNIX_TIMESTAMP() JOIN segment_route_publication_members member ON member.tenant_id = p.tenant_id AND member.segment_publication_id = publication.id AND member.projection_publication_id = p.id AND member.projection_id = p.projection_id AND member.attachment_id = p.attachment_id WHERE a.tenant_id = ? AND a.segment_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE','STANDBY') AND p.projection_id <> ? ORDER BY p.projection_id, p.projection_generation",
        )
        .bind(compatible_generation)
        .bind(lookup.tenant_id)
        .bind(segment_id)
        .bind(projection_id)
        .fetch_all(&mut **transaction)
        .await?;
        if compatible_catalog_rows.len() > MAX_PROJECTIONS {
            return Err(RuntimeConfigurationError::AmbiguousConfiguration);
        }
        let mut compatible_catalog = Vec::with_capacity(compatible_catalog_rows.len());
        let mut compatible_ids = HashSet::with_capacity(compatible_catalog_rows.len());
        for catalog in compatible_catalog_rows {
            let compatible_projection_id: Uuid = catalog.try_get("projection_id")?;
            if !compatible_ids.insert(compatible_projection_id) {
                return Err(RuntimeConfigurationError::AmbiguousConfiguration);
            }
            compatible_catalog.push(RuntimePeerProjection {
                projection_id: compatible_projection_id,
                projection_generation: catalog.try_get("projection_generation")?,
                projection_content_hash: decode_hash(
                    &catalog.try_get::<Vec<u8>, _>("projection_content_hash")?,
                )
                .map_err(|_| RuntimeConfigurationError::InvalidRecord)?,
                signed_projection_envelope: catalog.try_get("signed_envelope")?,
            });
        }
        if !compatible_catalog.is_empty() {
            compatibility_generations.push(RuntimeCompatibilityGeneration {
                segment_generation: compatible_generation,
                segment_content_hash: decode_hash(
                    &publication.try_get::<Vec<u8>, _>("segment_content_hash")?,
                )
                .map_err(|_| RuntimeConfigurationError::InvalidRecord)?,
                signed_segment_envelope: publication.try_get("signed_segment_envelope")?,
                peer_projection_catalog: compatible_catalog,
            });
        }
    }
    let record = RuntimeConfigurationRecord {
        projection_publication_id: row.try_get("projection_publication_id")?,
        projection_id,
        tenant_id,
        segment_id,
        site_id: row.try_get("site_id")?,
        attachment_id: row.try_get("attachment_id")?,
        device_id: row.try_get("device_id")?,
        device_key_id: row.try_get("device_key_id")?,
        segment_generation,
        segment_content_hash: decode_hash(&row.try_get::<Vec<u8>, _>("segment_content_hash")?)
            .map_err(|_| RuntimeConfigurationError::InvalidRecord)?,
        projection_generation: row.try_get("projection_generation")?,
        projection_content_hash: decode_hash(
            &row.try_get::<Vec<u8>, _>("projection_content_hash")?,
        )
        .map_err(|_| RuntimeConfigurationError::InvalidRecord)?,
        signed_segment_envelope: row.try_get("signed_segment_envelope")?,
        signed_projection_envelope: row.try_get("signed_projection_envelope")?,
        peer_projection_catalog,
        compatibility_generations,
        activation_phase: if matches!(
            rollout_state.as_str(),
            "COMMITTING" | "COMPLETE" | "BLOCKED"
        ) {
            RuntimeConfigurationActivationPhase::Commit
        } else {
            RuntimeConfigurationActivationPhase::Prepare
        },
    };
    record.validate(lookup)?;
    Ok(RuntimeConfigurationState::Current(Box::new(record)))
}

async fn validate_projection_ownership(
    transaction: &mut Transaction<'_, MySql>,
    write: &SegmentPublicationWrite,
) -> Result<(), SdwanError> {
    let required_route_owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT a.id FROM segment_attachments a JOIN site_prefixes prefix ON prefix.tenant_id = a.tenant_id AND prefix.site_id = a.site_id AND prefix.state = 'ACTIVE' WHERE a.tenant_id = ? AND a.segment_id = ? AND a.principal_kind = 'DEVICE' AND a.state IN ('ACTIVE', 'STANDBY') ORDER BY a.id",
    )
    .bind(write.tenant_id)
    .bind(write.segment_id)
    .fetch_all(&mut **transaction)
    .await?;
    if required_route_owners.is_empty() {
        return Err(SdwanError::MissingProjection);
    }
    let projected_attachments = write
        .projections
        .iter()
        .map(|projection| projection.attachment_id)
        .collect::<HashSet<_>>();
    if required_route_owners
        .iter()
        .any(|attachment_id| !projected_attachments.contains(attachment_id))
    {
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

async fn validate_projection_heads(
    transaction: &mut Transaction<'_, MySql>,
    write: &SegmentPublicationWrite,
) -> Result<(), SdwanError> {
    for projection in &write.projections {
        let row = sqlx::query(
            "SELECT projection_generation, content_hash FROM site_route_projection_publications WHERE tenant_id = ? AND segment_id = ? AND attachment_id = ? ORDER BY projection_generation DESC LIMIT 1 FOR UPDATE",
        )
        .bind(projection.tenant_id)
        .bind(projection.segment_id)
        .bind(projection.attachment_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(row) = row else {
            if projection.projection_generation != 1 || projection.previous_hash != [0; 32] {
                return Err(SdwanError::GenerationGap);
            }
            continue;
        };
        let previous_generation: u64 = row.try_get("projection_generation")?;
        let previous_content_hash = decode_hash(&row.try_get::<Vec<u8>, _>("content_hash")?)?;
        let expected_generation = previous_generation
            .checked_add(1)
            .ok_or(SdwanError::GenerationGap)?;
        if projection.projection_generation != expected_generation
            || projection.previous_hash != previous_content_hash
        {
            return Err(SdwanError::GenerationGap);
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
            "SELECT tenant_id, segment_id, expected_previous_generation, expected_previous_hash, generation, content_hash, signed_envelope, expires_at, stale_until, audit_event_id, actor_id FROM segment_route_publications WHERE id = ? FOR SHARE",
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
        || row.try_get::<u64, _>("expires_at")? != write.expires_at
        || row.try_get::<u64, _>("stale_until")? != write.stale_until
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
        let persisted_paths = sqlx::query(
            "SELECT candidate_id, source_attachment_id, destination_attachment_id, path_kind FROM runtime_projection_path_catalog WHERE tenant_id = ? AND projection_publication_id = ? ORDER BY candidate_id",
        )
        .bind(projection.tenant_id)
        .bind(projection.publication_id)
        .fetch_all(&mut **transaction)
        .await?;
        if persisted_paths.len() != projection.runtime_paths.len() {
            return Ok(false);
        }
        let mut expected_paths: Vec<&RuntimeProjectionPathCatalogWrite> =
            projection.runtime_paths.iter().collect();
        expected_paths.sort_unstable_by_key(|path| path.candidate_id);
        for (row, path) in persisted_paths.into_iter().zip(expected_paths) {
            if row.try_get::<Uuid, _>("candidate_id")? != path.candidate_id
                || row.try_get::<Uuid, _>("source_attachment_id")? != projection.attachment_id
                || row.try_get::<Uuid, _>("destination_attachment_id")? != path.peer_attachment_id
                || row.try_get::<String, _>("path_kind")? != path.path_kind.database_value()
            {
                return Ok(false);
            }
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
    rollout_ordinal: u32,
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
        "INSERT INTO segment_route_publication_members (tenant_id, segment_publication_id, projection_publication_id, projection_id, attachment_id, rollout_ordinal) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(projection.tenant_id)
    .bind(segment_publication_id)
    .bind(projection.publication_id)
    .bind(projection.projection_id)
    .bind(projection.attachment_id)
    .bind(rollout_ordinal)
    .execute(&mut **transaction)
    .await?;
    for (transport_node_id, transport_node_key_id) in &projection.transport_nodes {
        sqlx::query(
            "INSERT INTO runtime_projection_transport_catalog (tenant_id, segment_id, segment_generation, transport_node_id, transport_node_key_id, projection_publication_id, projection_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(projection.tenant_id)
        .bind(projection.segment_id)
        .bind(projection.segment_generation)
        .bind(transport_node_id)
        .bind(transport_node_key_id)
        .bind(projection.publication_id)
        .bind(projection.projection_id)
        .execute(&mut **transaction)
        .await?;
    }
    for path in &projection.runtime_paths {
        sqlx::query(
            "INSERT INTO runtime_projection_path_catalog (tenant_id, projection_publication_id, candidate_id, source_attachment_id, destination_attachment_id, path_kind) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(projection.tenant_id)
        .bind(projection.publication_id)
        .bind(path.candidate_id)
        .bind(projection.attachment_id)
        .bind(path.peer_attachment_id)
        .bind(path.path_kind.database_value())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}
