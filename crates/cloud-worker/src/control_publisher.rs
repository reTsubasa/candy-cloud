use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use candy_proto::{
    cloud_grant::{DeviceId, DeviceKeyId, PolicyId, PolicyRefV1, TenantId},
    ip_tunnel::{AttachmentId, SegmentId, SiteId},
    route_contract::{
        AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1, Ipv4PrefixV1,
        PacketResourcePolicyV1, PathCandidateId, PathSelectionPolicyV1, PeerEndpointV1,
        PeerPathCandidateV1, PeerPathKindV1, SegmentAttachmentV1,
    },
};
use cloud_control::{PathCandidateKindV1, PeerPathPolicyV1, ResourceSpecV1, ResourceState};
use cloud_db::{
    control::SegmentControlSnapshot,
    sdwan::{SdwanError, SdwanRepository},
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    generation_loop::{PublicationFailure, PublishedGeneration, SegmentGenerationPublisher},
    route_publication::{
        build_route_publication, DeviceProjectionInput, RoutePublicationInput, RouteSigner,
    },
};

pub struct ControlRoutePublisher {
    pub routes: SdwanRepository,
    pub signer: RouteSigner,
}

impl ControlRoutePublisher {
    pub fn new(routes: SdwanRepository, signing_key_id: String, signing_key: SigningKey) -> Self {
        Self {
            routes,
            signer: RouteSigner::new(signing_key_id, signing_key),
        }
    }

    async fn build_input(
        &self,
        snapshot: &SegmentControlSnapshot,
    ) -> Result<RoutePublicationInput> {
        let (current_generation, current_hash) = self
            .routes
            .segment_head(snapshot.tenant_id, snapshot.segment_id)
            .await
            .context("load segment publication head")?;
        let generation = current_generation
            .checked_add(1)
            .context("segment generation overflow")?;
        if snapshot.desired_revision != generation
            || (current_generation == 0 && current_hash != [0; 32])
            || (current_generation != 0 && current_hash == [0; 32])
        {
            bail!(
                "route publication revision {} is not adjacent to current head {}",
                snapshot.desired_revision,
                current_generation
            );
        }
        let mut segment = None;
        let mut attachments = Vec::new();
        let mut prefixes = Vec::new();
        let mut peers = Vec::new();
        let mut paths = Vec::new();
        let mut relays = HashMap::new();
        let mut nodes = HashMap::new();
        for resource in &snapshot.resources {
            match &resource.resource {
                ResourceSpecV1::Segment(value) if resource.metadata.id == snapshot.segment_id => {
                    segment = Some(value.clone())
                }
                ResourceSpecV1::Node(value) => {
                    nodes.insert(resource.metadata.id, value.clone());
                }
                ResourceSpecV1::Attachment(value) if value.segment_id == snapshot.segment_id => {
                    attachments.push((resource, value.clone()));
                }
                ResourceSpecV1::Prefix(value) if value.segment_id == snapshot.segment_id => {
                    prefixes.push((resource, value.clone()));
                }
                ResourceSpecV1::Peer(value) if value.segment_id == snapshot.segment_id => {
                    peers.push((resource, value.clone()));
                }
                ResourceSpecV1::PathCandidate(value) if value.segment_id == snapshot.segment_id => {
                    paths.push((resource, value.clone()));
                }
                ResourceSpecV1::Relay(value) => {
                    relays.insert(resource.metadata.id, value.clone());
                }
                _ => {}
            }
        }
        let segment = segment.context("control snapshot is missing its Segment resource")?;
        let mut core_attachments = Vec::with_capacity(attachments.len());
        for (resource, value) in &attachments {
            let node = nodes
                .get(&value.node_id)
                .context("Attachment references a missing Node")?;
            let state = if resource.metadata.state == ResourceState::Active {
                AttachmentState::Active
            } else {
                AttachmentState::Revoked
            };
            let local_prefixes = prefixes
                .iter()
                .filter(|(_, prefix)| prefix.site_id == value.site_id)
                .map(|(_, prefix)| {
                    Ipv4PrefixV1::new(prefix.prefix.network.octets(), prefix.prefix.prefix_len)
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            core_attachments.push(SegmentAttachmentV1 {
                attachment_id: AttachmentId(resource.metadata.id.into_bytes()),
                site_id: Some(SiteId(value.site_id.into_bytes())),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId(node.device_id.into_bytes()),
                    device_key_id: DeviceKeyId(node.device_key_id.into_bytes()),
                },
                overlay_router_ipv4: value.overlay_router_ipv4.octets(),
                local_prefixes,
                state,
                epoch_floor: value.epoch_floor,
            });
        }
        let attachment_ids: HashMap<Uuid, (SiteId, AttachmentId)> = attachments
            .iter()
            .map(|(resource, value)| {
                (
                    resource.metadata.id,
                    (
                        SiteId(value.site_id.into_bytes()),
                        AttachmentId(resource.metadata.id.into_bytes()),
                    ),
                )
            })
            .collect();
        let path_candidates = paths
            .iter()
            .map(|(resource, value)| {
                let (_, peer_attachment) = attachment_ids
                    .get(&value.destination_attachment_id)
                    .copied()
                    .context("Path candidate references a missing destination Attachment")?;
                let peer_site = attachments
                    .iter()
                    .find(|(item, _)| item.metadata.id == value.destination_attachment_id)
                    .map(|(_, item)| SiteId(item.site_id.into_bytes()))
                    .context("Path candidate destination site is missing")?;
                let endpoint: SocketAddr =
                    value.endpoint.parse().context("invalid path endpoint")?;
                let endpoint = match endpoint {
                    SocketAddr::V4(value) => PeerEndpointV1::Ipv4 {
                        address: value.ip().octets(),
                        port: value.port(),
                    },
                    SocketAddr::V6(value) => PeerEndpointV1::Ipv6 {
                        address: value.ip().octets(),
                        port: value.port(),
                    },
                };
                let kind = match value.kind {
                    PathCandidateKindV1::Direct => PeerPathKindV1::Direct,
                    PathCandidateKindV1::Relay => PeerPathKindV1::Relay,
                };
                let relay_node = if let Some(relay_id) = value.relay_id {
                    let relay = relays
                        .get(&relay_id)
                        .context("relay path references a missing Relay")?;
                    let node = nodes
                        .get(&relay.service_node_id)
                        .context("Relay references a missing service Node")?;
                    Some(candy_proto::route_contract::RelayNodeIdentityV1 {
                        node_id: candy_proto::route_contract::NodeId(
                            relay.service_node_id.into_bytes(),
                        ),
                        node_key_id: candy_proto::route_contract::NodeKeyId(
                            node.device_key_id.into_bytes(),
                        ),
                    })
                } else {
                    None
                };
                if (value.kind == PathCandidateKindV1::Relay) != relay_node.is_some() {
                    bail!("path candidate relay binding does not match its kind");
                }
                let authorization_hash = resource
                    .resource
                    .document_hash()
                    .map_err(|_| anyhow::anyhow!("path candidate hash failed"))?;
                Ok((
                    resource.metadata.id,
                    PeerPathCandidateV1 {
                        candidate_id: PathCandidateId(resource.metadata.id.into_bytes()),
                        peer_site_id: peer_site,
                        peer_attachment_id: peer_attachment,
                        kind,
                        relay_node,
                        endpoint,
                        priority: value.priority,
                        authorization: PolicyRefV1 {
                            policy_id: PolicyId(resource.metadata.id.into_bytes()),
                            generation: resource.metadata.revision,
                            content_hash: authorization_hash,
                        },
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let path_map: HashMap<Uuid, PeerPathCandidateV1> = path_candidates.into_iter().collect();
        let policy_for = |site_a: SiteId, site_b: SiteId| -> Result<PathSelectionPolicyV1> {
            let peer = peers
                .iter()
                .find(|(_, peer)| {
                    let a = SiteId(peer.site_a_id.into_bytes());
                    let b = SiteId(peer.site_b_id.into_bytes());
                    (a == site_a && b == site_b) || (a == site_b && b == site_a)
                })
                .context("Attachment pair has no Peer policy")?;
            Ok(match peer.1.path_policy {
                PeerPathPolicyV1::DirectOnly => PathSelectionPolicyV1::DirectOnly,
                PeerPathPolicyV1::DirectPreferred => PathSelectionPolicyV1::DirectPreferred,
                PeerPathPolicyV1::RelayRequired => PathSelectionPolicyV1::RelayRequired,
            })
        };
        let mut projections = Vec::new();
        for (resource, attachment) in &attachments {
            if resource.metadata.state != ResourceState::Active {
                continue;
            }
            let node = nodes
                .get(&attachment.node_id)
                .context("Attachment Node is missing")?;
            let site = SiteId(attachment.site_id.into_bytes());
            let mut peer_paths = Vec::new();
            for (path_resource, path) in &paths {
                if path.source_attachment_id == resource.metadata.id {
                    peer_paths.push(
                        path_map
                            .get(&path_resource.metadata.id)
                            .cloned()
                            .context("path candidate conversion failed")?,
                    );
                }
            }
            if peer_paths.is_empty() {
                bail!("active Attachment has no signed path candidates")
            }
            peer_paths.sort_unstable_by_key(|candidate| {
                (
                    candidate.peer_site_id.0,
                    candidate.peer_attachment_id.0,
                    candidate.kind as u8,
                    candidate.priority,
                    candidate.candidate_id.0,
                )
            });
            let remote_site = peer_paths[0].peer_site_id;
            let projection_id = PolicyId(resource.metadata.id.into_bytes());
            let (projection_generation, previous_hash) = match self
                .routes
                .projection_head(
                    snapshot.tenant_id,
                    snapshot.segment_id,
                    resource.metadata.id,
                )
                .await
                .context("load site projection head")?
            {
                Some((generation, hash)) => (
                    generation
                        .checked_add(1)
                        .context("projection generation overflow")?,
                    hash,
                ),
                None => (1, [0; 32]),
            };
            projections.push(DeviceProjectionInput {
                publication_id: stable_uuid(
                    snapshot.segment_id,
                    resource.metadata.id,
                    snapshot.desired_revision,
                ),
                attachment_id: AttachmentId(resource.metadata.id.into_bytes()),
                projection_id,
                projection_generation,
                previous_hash,
                path_policy: policy_for(site, remote_site)?,
                peer_paths,
                coherent_manifest: CoherentPolicyManifestV1 {
                    generation,
                    peer_paths_hash: [0; 32],
                    dns_projection: None,
                    egress_authorization: None,
                },
                max_inner_mtu: 1300,
                resources: PacketResourcePolicyV1 {
                    max_route_prefixes: 4096,
                    max_queue_packets: 4096,
                    max_queue_bytes: 16 * 1024 * 1024,
                    replay_window_packets: 4096,
                    max_packets_per_second: 100_000,
                    max_bytes_per_second: 1_000_000_000,
                    allowed_traffic_classes: 1,
                },
            });
            let _ = node;
        }
        let not_before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_secs();
        Ok(RoutePublicationInput {
            publication_id: stable_uuid(
                snapshot.tenant_id,
                snapshot.segment_id,
                snapshot.desired_revision,
            ),
            audit_event_id: stable_uuid(
                snapshot.segment_id,
                snapshot.tenant_id,
                snapshot.desired_revision ^ 0xa5a5,
            ),
            actor_id: "cloud-worker".into(),
            tenant_id: TenantId(snapshot.tenant_id.into_bytes()),
            segment_id: SegmentId(snapshot.segment_id.into_bytes()),
            generation,
            previous_hash: current_hash,
            segment_overlay_prefix: Ipv4PrefixV1::new(
                segment.overlay_prefix.network.octets(),
                segment.overlay_prefix.prefix_len,
            )?,
            attachments: core_attachments,
            not_before,
            expires_at: not_before + 3_600,
            stale_until: not_before + 7_200,
            projections,
        })
    }
}

#[async_trait::async_trait]
impl SegmentGenerationPublisher for ControlRoutePublisher {
    fn ready(&self) -> bool {
        self.signer.ready()
    }

    async fn publish_snapshot(
        &self,
        snapshot: &SegmentControlSnapshot,
    ) -> std::result::Result<PublishedGeneration, PublicationFailure> {
        let input = self
            .build_input(snapshot)
            .await
            .map_err(classify_input_error)?;
        let built = build_route_publication(&input, &self.signer).map_err(|error| {
            PublicationFailure::Permanent {
                code: format!("ROUTE_BUILD_{error}"),
            }
        })?;
        let content_hash = built.segment.object.content_hash;
        let write = built
            .database_write()
            .map_err(|error| PublicationFailure::Permanent {
                code: format!("ROUTE_DB_WRITE_{error}"),
            })?;
        self.routes
            .publish(&write)
            .await
            .map_err(classify_publish_error)?;
        Ok(PublishedGeneration {
            generation: built.segment.object.segment_generation,
            content_hash,
        })
    }
}

fn classify_publish_error(error: SdwanError) -> PublicationFailure {
    match error {
        SdwanError::Database(_) => PublicationFailure::Retryable {
            code: format!("ROUTE_DB_{error}"),
            retry_after: std::time::Duration::from_secs(5),
        },
        _ => PublicationFailure::Permanent {
            code: format!("ROUTE_DB_{error}"),
        },
    }
}

fn classify_input_error(error: anyhow::Error) -> PublicationFailure {
    let retryable = error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<SdwanError>(),
            Some(SdwanError::Database(_))
        )
    });
    if retryable {
        PublicationFailure::Retryable {
            code: format!("ROUTE_INPUT_{error}"),
            retry_after: std::time::Duration::from_secs(5),
        }
    } else {
        PublicationFailure::Permanent {
            code: format!("ROUTE_INPUT_{error}"),
        }
    }
}

fn stable_uuid(a: Uuid, b: Uuid, generation: u64) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(a.as_bytes());
    hasher.update(b.as_bytes());
    hasher.update(generation.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}
