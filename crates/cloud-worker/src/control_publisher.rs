use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use cloud_control::{PathCandidateKindV1, PeerPathPolicyV1, ResourceSpecV1, ResourceState};
use cloud_core_module::CoreModule;
use cloud_db::{
    control::SegmentControlSnapshot,
    sdwan::{SdwanError, SdwanRepository},
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    generation_loop::{PublicationFailure, PublishedGeneration, SegmentGenerationPublisher},
    route_publication::{
        build_route_publication, DeviceProjectionInput, RoutePublicationInput, RouteSigner,
    },
    route_types::{
        AttachmentId, AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1, DeviceId,
        DeviceKeyId, Ipv4PrefixV1, NodeId, NodeKeyId, NodePoolId, PacketResourcePolicyV1,
        PathCandidateId, PathSelectionPolicyV1, PeerEndpointV1, PeerPathCandidateV1,
        PeerPathKindV1, PolicyId, PolicyRefV1, RelayNodeIdentityV1, SegmentAttachmentV1, SegmentId,
        SiteId, TenantId, TransportNodeIdentityV1, TransportPresetV1,
    },
};

pub struct ControlRoutePublisher {
    pub routes: SdwanRepository,
    pub signer: RouteSigner,
}

impl ControlRoutePublisher {
    pub fn new(
        routes: SdwanRepository,
        signing_key_id: String,
        signing_key: SigningKey,
        core: Arc<CoreModule>,
    ) -> Self {
        Self {
            routes,
            signer: RouteSigner::new(signing_key_id, signing_key, core),
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
        let attachment_nodes = attachments
            .iter()
            .map(|(resource, attachment)| (resource.metadata.id, attachment.node_id))
            .collect::<HashMap<_, _>>();
        let known_nodes = nodes.keys().copied().collect::<HashSet<_>>();
        let path_values = paths
            .iter()
            .map(|(_, path)| path.clone())
            .collect::<Vec<_>>();
        validate_direct_dialers(&path_values, &attachment_nodes, &known_nodes)?;
        let mut path_map: HashMap<Uuid, Vec<PeerPathCandidateV1>> = HashMap::new();
        for (resource, value) in &paths {
            let (_, peer_attachment) = attachment_ids
                .get(&value.destination_attachment_id)
                .copied()
                .context("Path candidate references a missing destination Attachment")?;
            let peer_site = attachments
                .iter()
                .find(|(item, _)| item.metadata.id == value.destination_attachment_id)
                .map(|(_, item)| SiteId(item.site_id.into_bytes()))
                .context("Path candidate destination site is missing")?;
            let transports = snapshot
                .transport_bindings
                .get(&resource.metadata.id)
                .context("path candidate has no active Candy QUIC/UDP transport identity")?;
            let kind = match value.kind {
                PathCandidateKindV1::Direct => PeerPathKindV1::Direct,
                PathCandidateKindV1::Relay => PeerPathKindV1::Relay,
            };
            if let Some(relay_id) = value.relay_id {
                let relay = relays
                    .get(&relay_id)
                    .context("relay path references a missing Relay")?;
                nodes
                    .get(&relay.service_node_id)
                    .context("Relay references a missing service Node")?;
            }
            if (value.kind == PathCandidateKindV1::Relay) != value.relay_id.is_some() {
                bail!("path candidate relay binding does not match its kind");
            }
            let authorization_hash = resource
                .resource
                .document_hash()
                .map_err(|_| anyhow::anyhow!("path candidate hash failed"))?;
            let mut expanded = Vec::with_capacity(transports.len());
            for transport in transports {
                if transport.candidate_id != resource.metadata.id {
                    bail!("transport binding does not match its path resource");
                }
                let endpoint = match transport.endpoint {
                    SocketAddr::V4(value) => PeerEndpointV1::Ipv4 {
                        address: value.ip().octets(),
                        port: value.port(),
                    },
                    SocketAddr::V6(value) => PeerEndpointV1::Ipv6 {
                        address: value.ip().octets(),
                        port: value.port(),
                    },
                };
                let transport_node = TransportNodeIdentityV1 {
                    node_id: NodeId(transport.service_node_id.into_bytes()),
                    node_key_id: NodeKeyId(transport.service_node_key_id.into_bytes()),
                };
                let relay_node =
                    (value.kind == PathCandidateKindV1::Relay).then_some(RelayNodeIdentityV1 {
                        node_id: transport_node.node_id,
                        node_key_id: transport_node.node_key_id,
                    });
                expanded.push(PeerPathCandidateV1 {
                    candidate_id: PathCandidateId(stable_candidate_id(
                        resource.metadata.id,
                        transport.endpoint_id,
                    )),
                    peer_site_id: peer_site,
                    peer_attachment_id: peer_attachment,
                    kind,
                    relay_node,
                    node_pool_id: NodePoolId(transport.node_pool_id.into_bytes()),
                    transport_node,
                    endpoint,
                    server_name: transport.server_name.clone(),
                    server_cert_sha256: transport.server_cert_sha256,
                    transport_preset: match transport.transport_preset {
                        cloud_db::control::RuntimeTransportPreset::Current => {
                            TransportPresetV1::Current
                        }
                        cloud_db::control::RuntimeTransportPreset::BbrV1 => {
                            TransportPresetV1::BbrV1
                        }
                        cloud_db::control::RuntimeTransportPreset::Aggressive => {
                            TransportPresetV1::Aggressive
                        }
                    },
                    priority: value.priority,
                    authorization: PolicyRefV1 {
                        policy_id: PolicyId(resource.metadata.id.into_bytes()),
                        generation: resource.metadata.revision,
                        content_hash: authorization_hash,
                    },
                });
            }
            path_map.insert(resource.metadata.id, expanded);
        }
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
                    peer_paths.extend(
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
                local_transport_node: snapshot
                    .transport_bindings
                    .values()
                    .flatten()
                    .find(|binding| {
                        binding.service_device_id == node.device_id
                            && binding.service_device_key_id == node.device_key_id
                    })
                    .map(|binding| TransportNodeIdentityV1 {
                        node_id: NodeId(binding.service_node_id.into_bytes()),
                        node_key_id: NodeKeyId(binding.service_node_key_id.into_bytes()),
                    }),
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

fn validate_direct_dialers(
    paths: &[cloud_control::PathCandidateV1],
    attachment_nodes: &HashMap<Uuid, Uuid>,
    nodes: &HashSet<Uuid>,
) -> Result<()> {
    let mut direct_peers = HashMap::<Uuid, (Uuid, bool)>::new();
    for path in paths {
        if path.kind != PathCandidateKindV1::Direct {
            continue;
        }
        let source_node = attachment_nodes
            .get(&path.source_attachment_id)
            .context("direct path source Attachment is missing")?;
        let destination_node = attachment_nodes
            .get(&path.destination_attachment_id)
            .context("direct path destination Attachment is missing")?;
        if path.transport_node_id != *source_node && path.transport_node_id != *destination_node {
            bail!("direct path transport Node is not one of its endpoint Nodes");
        }
        if !nodes.contains(&path.transport_node_id) {
            bail!("direct path transport Node is missing");
        }
        match direct_peers.entry(path.peer_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((
                    path.transport_node_id,
                    path.transport_node_id != *source_node,
                ));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let (transport_node_id, has_dialer) = entry.get_mut();
                if *transport_node_id != path.transport_node_id {
                    bail!("direct peer has conflicting transport Nodes");
                }
                *has_dialer |= path.transport_node_id != *source_node;
            }
        }
    }
    if direct_peers
        .values()
        .any(|(_, has_dialer)| !has_dialer)
    {
        bail!("direct peer must use one transport Node with exactly one outbound side");
    }
    Ok(())
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
        let publication_id = stable_uuid(
            snapshot.tenant_id,
            snapshot.segment_id,
            snapshot.desired_revision,
        );
        if let Some((generation, content_hash)) = self
            .routes
            .published_generation(snapshot.tenant_id, snapshot.segment_id, publication_id)
            .await
            .map_err(classify_publish_error)?
        {
            if generation != snapshot.desired_revision {
                return Err(PublicationFailure::Permanent {
                    code: "ROUTE_REPLAY_GENERATION_MISMATCH".into(),
                });
            }
            return Ok(PublishedGeneration {
                generation,
                content_hash,
            });
        }
        let input = self
            .build_input(snapshot)
            .await
            .map_err(classify_input_error)?;
        let built = build_route_publication(&input, &self.signer).map_err(|error| {
            PublicationFailure::Permanent {
                code: format!("ROUTE_BUILD_{error}"),
            }
        })?;
        let content_hash = built.segment.content_hash;
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
            generation: built.segment.source.segment_generation,
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

fn stable_candidate_id(path_resource_id: Uuid, endpoint_id: Uuid) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"candy/path-endpoint-candidate-v1\0");
    hasher.update(path_resource_id.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_path(
        peer_id: Uuid,
        source_attachment_id: Uuid,
        destination_attachment_id: Uuid,
        transport_node_id: Uuid,
    ) -> cloud_control::PathCandidateV1 {
        cloud_control::PathCandidateV1 {
            segment_id: Uuid::from_bytes([1; 16]),
            peer_id,
            source_attachment_id,
            destination_attachment_id,
            kind: PathCandidateKindV1::Direct,
            relay_id: None,
            transport_node_id,
            priority: 100,
        }
    }

    #[test]
    fn direct_peer_requires_at_least_one_outbound_dialer() {
        let peer = Uuid::from_bytes([2; 16]);
        let attachment_a = Uuid::from_bytes([3; 16]);
        let attachment_b = Uuid::from_bytes([4; 16]);
        let node_a = Uuid::from_bytes([5; 16]);
        let node_b = Uuid::from_bytes([6; 16]);
        let attachment_nodes = HashMap::from([(attachment_a, node_a), (attachment_b, node_b)]);
        let nodes = HashSet::from([node_a, node_b]);

        let listener_only = vec![
            direct_path(peer, attachment_a, attachment_b, node_a),
            direct_path(peer, attachment_b, attachment_a, node_b),
        ];
        assert!(validate_direct_dialers(&listener_only, &attachment_nodes, &nodes).is_err());

        let full_duplex = vec![
            direct_path(peer, attachment_a, attachment_b, node_b),
            direct_path(peer, attachment_b, attachment_a, node_b),
        ];
        assert!(validate_direct_dialers(&full_duplex, &attachment_nodes, &nodes).is_ok());

        let duplicate_full_duplex = vec![
            direct_path(peer, attachment_a, attachment_b, node_b),
            direct_path(peer, attachment_b, attachment_a, node_a),
        ];
        assert!(validate_direct_dialers(&duplicate_full_duplex, &attachment_nodes, &nodes).is_err());
    }

    #[test]
    fn direct_peer_rejects_unrelated_transport_node() {
        let attachment_a = Uuid::from_bytes([3; 16]);
        let attachment_b = Uuid::from_bytes([4; 16]);
        let node_a = Uuid::from_bytes([5; 16]);
        let node_b = Uuid::from_bytes([6; 16]);
        let unrelated = Uuid::from_bytes([7; 16]);
        let attachment_nodes = HashMap::from([(attachment_a, node_a), (attachment_b, node_b)]);
        let nodes = HashSet::from([node_a, node_b, unrelated]);
        assert!(validate_direct_dialers(
            &[direct_path(
                Uuid::from_bytes([2; 16]),
                attachment_a,
                attachment_b,
                unrelated,
            )],
            &attachment_nodes,
            &nodes,
        )
        .is_err());
    }
}
