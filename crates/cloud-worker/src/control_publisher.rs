use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use cloud_control::{
    runtime_path_candidate_id, PathCandidateKindV1, PeerPathPolicyV1, PolicyActionV1,
    ResourceSpecV1, ResourceState, ServicePolicyRuleV1,
};
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
        PeerPathKindV1, PolicyId, PolicyRefV1, RelayNodeIdentityV1, RemoteRouteV1,
        SegmentAttachmentV1, SegmentId, SiteId, TenantId, TransportNodeIdentityV1,
        TransportPresetV1, ROUTE_PUBLICATION_STALE_SECONDS, ROUTE_PUBLICATION_VALIDITY_SECONDS,
    },
};

pub struct ControlRoutePublisher {
    pub routes: SdwanRepository,
    pub signer: RouteSigner,
}

#[derive(Debug, thiserror::Error)]
enum InputReadinessError {
    #[error("active attachment has no path candidates")]
    PathCandidates,
    #[error("path candidate has no active transport identity")]
    TransportIdentity,
    #[error("attachment pair has no peer policy")]
    PeerPolicy,
}

#[derive(Clone)]
struct QuotaBoundPeerPathCandidate {
    peer_path: PeerPathCandidateV1,
    entitlement_rate_limit: cloud_db::control::BytesPerSecond,
}

#[derive(Clone, Debug)]
struct EffectiveRemoteEgressRule {
    policy_ref: PolicyRefV1,
    priority: u32,
    source_site_id: Uuid,
    destination: Ipv4PrefixV1,
    egress_id: Uuid,
}

impl InputReadinessError {
    fn code(&self) -> &'static str {
        match self {
            Self::PathCandidates => "ROUTE_INPUT_WAITING_FOR_PATHS",
            Self::TransportIdentity => "ROUTE_INPUT_WAITING_FOR_TRANSPORT",
            Self::PeerPolicy => "ROUTE_INPUT_WAITING_FOR_PEER_POLICY",
        }
    }
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
        if (current_generation == 0 && current_hash != [0; 32])
            || (current_generation != 0 && current_hash == [0; 32])
        {
            bail!("segment publication head {current_generation} has an invalid content hash");
        }
        let mut segment = None;
        let mut attachments = Vec::new();
        let mut prefixes = Vec::new();
        let mut peers = Vec::new();
        let mut paths = Vec::new();
        let mut relays = HashMap::new();
        let mut nodes = HashMap::new();
        let mut egresses = HashMap::new();
        let mut service_policy_rules = Vec::new();
        for resource in &snapshot.resources {
            match &resource.resource {
                ResourceSpecV1::Segment(value) if resource.metadata.id == snapshot.segment_id => {
                    segment = Some(value.clone())
                }
                ResourceSpecV1::Node(value) if resource.metadata.state == ResourceState::Active => {
                    nodes.insert(resource.metadata.id, value.clone());
                }
                ResourceSpecV1::Attachment(value) if value.segment_id == snapshot.segment_id => {
                    attachments.push((resource, value.clone()));
                }
                ResourceSpecV1::Prefix(value)
                    if value.segment_id == snapshot.segment_id
                        && resource.metadata.state == ResourceState::Active =>
                {
                    prefixes.push((resource, value.clone()));
                }
                ResourceSpecV1::Peer(value)
                    if value.segment_id == snapshot.segment_id
                        && resource.metadata.state == ResourceState::Active =>
                {
                    peers.push((resource, value.clone()));
                }
                ResourceSpecV1::PathCandidate(value)
                    if value.segment_id == snapshot.segment_id
                        && resource.metadata.state == ResourceState::Active =>
                {
                    paths.push((resource, value.clone()));
                }
                ResourceSpecV1::Relay(value)
                    if resource.metadata.state == ResourceState::Active =>
                {
                    relays.insert(resource.metadata.id, value.clone());
                }
                ResourceSpecV1::Egress(value)
                    if resource.metadata.state == ResourceState::Active =>
                {
                    egresses.insert(resource.metadata.id, value.clone());
                }
                ResourceSpecV1::ServicePolicy(policy)
                    if resource.metadata.state == ResourceState::Active
                        && policy.segment_id == snapshot.segment_id =>
                {
                    let content_hash = resource
                        .resource
                        .document_hash()
                        .context("service policy hash failed")?;
                    let policy_ref = PolicyRefV1 {
                        policy_id: PolicyId(resource.metadata.id.into_bytes()),
                        generation: resource.metadata.revision,
                        content_hash,
                    };
                    for rule in &policy.rules {
                        if matches!(rule.action, PolicyActionV1::RemoteEgress(_))
                            && rule.destination_prefixes.is_empty()
                        {
                            bail!("remote egress policy requires explicit signed destination prefixes");
                        }
                        service_policy_rules.push((policy_ref.clone(), rule.clone()));
                    }
                }
                _ => {}
            }
        }
        let segment = segment.context("control snapshot is missing its Segment resource")?;
        let mut remote_egress_policy_for_site: HashMap<Uuid, PolicyRefV1> = HashMap::new();
        let mut remote_egress_routes_for_site: HashMap<Uuid, Vec<RemoteRouteV1>> = HashMap::new();
        let mut remote_egress_destinations_for_site: HashMap<Uuid, Vec<Ipv4PrefixV1>> =
            HashMap::new();
        let mut remote_egress_gateway_sites = HashSet::new();
        let attachment_sites = attachments
            .iter()
            .map(|(_, attachment)| attachment.site_id)
            .collect::<HashSet<_>>();
        let effective_remote_egress_rules =
            select_remote_egress_rules(service_policy_rules, &attachment_sites, &egresses)?;
        for effective in effective_remote_egress_rules {
            let EffectiveRemoteEgressRule {
                policy_ref,
                source_site_id,
                destination,
                egress_id,
                ..
            } = effective;
            let egress = egresses
                .get(&egress_id)
                .context("remote egress rule references an inactive Egress")?;
            if remote_egress_policy_for_site
                .get(&egress.site_id)
                .is_some_and(|existing| existing != &policy_ref)
            {
                bail!("Egress Site has conflicting remote egress policies");
            }
            remote_egress_policy_for_site
                .entry(egress.site_id)
                .or_insert_with(|| policy_ref.clone());
            remote_egress_gateway_sites.insert(egress.site_id);
            let signed_destinations = [destination];
            merge_egress_destinations(
                remote_egress_destinations_for_site
                    .entry(egress.site_id)
                    .or_default(),
                &signed_destinations,
            )?;
            if remote_egress_policy_for_site
                .get(&source_site_id)
                .is_some_and(|existing| existing != &policy_ref)
            {
                bail!("source Site has conflicting effective remote egress policies");
            }
            remote_egress_policy_for_site
                .entry(source_site_id)
                .or_insert_with(|| policy_ref.clone());
            merge_egress_destinations(
                remote_egress_destinations_for_site
                    .entry(source_site_id)
                    .or_default(),
                &signed_destinations,
            )?;
            let routes = remote_egress_routes_for_site
                .entry(source_site_id)
                .or_default();
            let addition = RemoteRouteV1 {
                destination_prefix: destination,
                owner_site_id: SiteId(egress.site_id.into_bytes()),
                owner_attachment_ids: vec![AttachmentId(egress.attachment_id.into_bytes())],
            };
            if routes.iter().any(|existing| {
                existing
                    .destination_prefix
                    .overlaps(&addition.destination_prefix)
                    && existing.owner_attachment_ids != addition.owner_attachment_ids
            }) {
                bail!("source Site has overlapping effective remote egress destinations");
            }
            if !routes.contains(&addition) {
                routes.push(addition);
            }
        }
        let active_peer_ids = peers
            .iter()
            .map(|(resource, _)| resource.metadata.id)
            .collect::<HashSet<_>>();
        paths.retain(|(_, path)| active_peer_ids.contains(&path.peer_id));
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
        let route_owner_attachment_ids = core_attachments
            .iter()
            .filter(|attachment| {
                attachment.state == AttachmentState::Active && !attachment.local_prefixes.is_empty()
            })
            .map(|attachment| Uuid::from_bytes(attachment.attachment_id.0))
            .collect::<HashSet<_>>();
        let path_values = paths
            .iter()
            .map(|(_, path)| path.clone())
            .collect::<Vec<_>>();
        validate_direct_dialers(&path_values, &attachment_nodes, &known_nodes)?;
        let route_owner_paths = paths
            .iter()
            .filter(|(_, path)| path_targets_route_owner(path, &route_owner_attachment_ids))
            .collect::<Vec<_>>();
        let participating_attachment_ids = participating_attachments(
            &route_owner_attachment_ids,
            route_owner_paths.iter().map(|item| &item.1),
        );
        for attachment in &mut core_attachments {
            if attachment.state == AttachmentState::Active
                && !participating_attachment_ids
                    .contains(&Uuid::from_bytes(attachment.attachment_id.0))
            {
                attachment.state = AttachmentState::Revoked;
            }
        }
        let participating_paths = paths
            .iter()
            .filter(|(_, path)| path_connects_participants(path, &participating_attachment_ids))
            .collect::<Vec<_>>();
        let omitted_paths = paths.len().saturating_sub(participating_paths.len());
        if omitted_paths > 0 {
            tracing::info!(
                event = "route_publication_non_participant_paths_omitted",
                tenant_id = %snapshot.tenant_id,
                segment_id = %snapshot.segment_id,
                omitted_paths,
                "omitted peer paths outside the published attachment set"
            );
        }
        let mut path_map: HashMap<Uuid, Vec<QuotaBoundPeerPathCandidate>> = HashMap::new();
        for (resource, value) in &participating_paths {
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
                .ok_or(InputReadinessError::TransportIdentity)?;
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
                expanded.push(QuotaBoundPeerPathCandidate {
                    peer_path: PeerPathCandidateV1 {
                        candidate_id: PathCandidateId(
                            runtime_path_candidate_id(resource.metadata.id, transport.endpoint_id)
                                .into_bytes(),
                        ),
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
                    },
                    entitlement_rate_limit: transport.entitlement_rate_limit,
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
                .ok_or(InputReadinessError::PeerPolicy)?;
            Ok(match peer.1.path_policy {
                PeerPathPolicyV1::DirectOnly => PathSelectionPolicyV1::DirectOnly,
                PeerPathPolicyV1::DirectPreferred => PathSelectionPolicyV1::DirectPreferred,
                PeerPathPolicyV1::RelayRequired => PathSelectionPolicyV1::RelayRequired,
            })
        };
        let mut projections = Vec::new();
        for (resource, attachment) in &attachments {
            if resource.metadata.state != ResourceState::Active
                || !participating_attachment_ids.contains(&resource.metadata.id)
            {
                continue;
            }
            let node = nodes
                .get(&attachment.node_id)
                .context("Attachment Node is missing")?;
            let site = SiteId(attachment.site_id.into_bytes());
            let mut peer_paths = Vec::new();
            let mut outbound_rate_limits_bytes_per_second = Vec::new();
            for (path_resource, path) in &participating_paths {
                if path_belongs_to_projection(
                    resource.metadata.id,
                    path,
                    &participating_attachment_ids,
                ) {
                    let candidates = path_map
                        .get(&path_resource.metadata.id)
                        .context("path candidate conversion failed")?;
                    peer_paths.extend(candidates.iter().map(|item| item.peer_path.clone()));
                    outbound_rate_limits_bytes_per_second.extend(
                        candidates
                            .iter()
                            .map(|item| item.entitlement_rate_limit.get()),
                    );
                }
            }
            if peer_paths.is_empty() {
                return Err(InputReadinessError::PathCandidates.into());
            }
            peer_paths.sort_unstable_by_key(|candidate| {
                (
                    candidate.peer_site_id.0,
                    candidate.peer_attachment_id.0,
                    candidate.priority,
                    candidate.kind as u8,
                    candidate.candidate_id.0,
                )
            });
            let remote_site = peer_paths[0].peer_site_id;
            let max_bytes_per_second =
                effective_projection_rate_limit(outbound_rate_limits_bytes_per_second.into_iter())?;
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
                egress_routes: remote_egress_routes_for_site
                    .get(&Uuid::from_bytes(site.0))
                    .cloned()
                    .unwrap_or_default(),
                egress_destination_prefixes: remote_egress_destinations_for_site
                    .get(&Uuid::from_bytes(site.0))
                    .cloned()
                    .unwrap_or_default(),
                coherent_manifest: CoherentPolicyManifestV1 {
                    generation,
                    peer_paths_hash: [0; 32],
                    dns_projection: None,
                    egress_authorization: remote_egress_policy_for_site
                        .get(&Uuid::from_bytes(site.0))
                        .cloned(),
                    egress_gateway: remote_egress_gateway_sites.contains(&Uuid::from_bytes(site.0)),
                },
                max_inner_mtu: 1300,
                resources: PacketResourcePolicyV1 {
                    max_route_prefixes: 4096,
                    max_queue_packets: 4096,
                    max_queue_bytes: 16 * 1024 * 1024,
                    replay_window_packets: 4096,
                    max_packets_per_second: 100_000,
                    max_bytes_per_second,
                    allowed_traffic_classes: 1,
                },
            });
            if let Some(projection) = projections.last() {
                tracing::info!(
                    event = "route_projection_input_summary",
                    tenant_id = %snapshot.tenant_id,
                    segment_id = %snapshot.segment_id,
                    desired_revision = snapshot.desired_revision,
                    attachment_id = %resource.metadata.id,
                    site_id = %Uuid::from_bytes(site.0),
                    local_transport_node = ?projection.local_transport_node.as_ref().map(|node| Uuid::from_bytes(node.node_id.0)),
                    peer_path_count = projection.peer_paths.len(),
                    remote_route_count = projection.egress_routes.len(),
                    egress_prefix_count = projection.egress_destination_prefixes.len(),
                    egress_prefixes = ?projection.egress_destination_prefixes,
                    egress_authorization = ?projection.coherent_manifest.egress_authorization,
                    egress_gateway = projection.coherent_manifest.egress_gateway,
                    "constructed site projection input"
                );
            }
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
            expires_at: not_before + ROUTE_PUBLICATION_VALIDITY_SECONDS,
            stale_until: not_before + ROUTE_PUBLICATION_STALE_SECONDS,
            projections,
        })
    }
}

fn select_remote_egress_rules(
    mut rules: Vec<(PolicyRefV1, ServicePolicyRuleV1)>,
    attachment_sites: &HashSet<Uuid>,
    egresses: &HashMap<Uuid, cloud_control::EgressV1>,
) -> Result<Vec<EffectiveRemoteEgressRule>> {
    rules.sort_unstable_by_key(|(policy_ref, rule)| {
        (rule.priority, policy_ref.policy_id.0, rule.id.into_bytes())
    });
    let mut decisions = BTreeMap::<(Uuid, Ipv4PrefixV1), (u32, Option<Uuid>)>::new();
    let mut selected = Vec::new();
    for (policy_ref, rule) in rules {
        let destinations = normalized_policy_destinations(&rule.destination_prefixes);
        let remote_egress = match rule.action {
            PolicyActionV1::LocalEgress => None,
            PolicyActionV1::RemoteEgress(egress_id) => Some(
                egresses
                    .get(&egress_id)
                    .map(|egress| (egress_id, egress))
                    .context("remote egress rule references an inactive Egress")?,
            ),
        };
        let mut source_sites = if rule.source_site_ids.is_empty() {
            attachment_sites.iter().copied().collect::<Vec<_>>()
        } else {
            rule.source_site_ids.clone()
        };
        if let Some((_, egress)) = remote_egress {
            source_sites.retain(|site_id| *site_id != egress.site_id);
        }
        for source_site_id in source_sites {
            for prefix in &destinations {
                let destination = Ipv4PrefixV1::new_egress_destination(
                    prefix.network.octets(),
                    prefix.prefix_len,
                )
                .expect("validated control prefix must convert");
                let key = (source_site_id, destination);
                let action = remote_egress.map(|(egress_id, _)| egress_id);
                if let Some((priority, existing_action)) = decisions.get(&key) {
                    if *priority == rule.priority && *existing_action != action {
                        bail!(
                                "service policy has equal-priority conflicting actions for source Site {source_site_id} and destination {}/{}",
                                std::net::Ipv4Addr::from(destination.network),
                                destination.prefix_len
                            );
                    }
                    continue;
                }
                decisions.insert(key, (rule.priority, action));
                let Some((egress_id, _)) = remote_egress else {
                    continue;
                };
                selected.push(EffectiveRemoteEgressRule {
                    policy_ref: policy_ref.clone(),
                    priority: rule.priority,
                    source_site_id,
                    destination,
                    egress_id,
                });
            }
        }
    }
    selected.sort_unstable_by_key(|rule| {
        (
            rule.source_site_id,
            rule.destination,
            rule.priority,
            rule.egress_id,
        )
    });
    Ok(selected)
}

fn normalized_policy_destinations(
    prefixes: &[cloud_control::Ipv4PrefixV1],
) -> Vec<cloud_control::Ipv4PrefixV1> {
    let legacy_default = [
        (std::net::Ipv4Addr::UNSPECIFIED, 1),
        (std::net::Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    if prefixes.len() == legacy_default.len()
        && legacy_default.iter().all(|(network, prefix_len)| {
            prefixes
                .iter()
                .any(|prefix| prefix.network == *network && prefix.prefix_len == *prefix_len)
        })
    {
        return vec![cloud_control::Ipv4PrefixV1 {
            network: std::net::Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
        }];
    }
    prefixes.to_vec()
}

fn merge_egress_destinations(
    destinations: &mut Vec<Ipv4PrefixV1>,
    additions: &[Ipv4PrefixV1],
) -> Result<()> {
    for addition in additions {
        if destinations.contains(addition) {
            continue;
        }
        if destinations
            .iter()
            .any(|existing| existing.overlaps(addition))
        {
            bail!("remote egress policy contains overlapping destination prefixes");
        }
        destinations.push(*addition);
    }
    destinations.sort_unstable();
    Ok(())
}

fn effective_projection_rate_limit(
    limits_bytes_per_second: impl Iterator<Item = u64>,
) -> Result<u64> {
    let mut effective = None;
    for limit in limits_bytes_per_second {
        if limit == 0 {
            bail!("projection contains a zero outbound entitlement rate limit");
        }
        effective = Some(effective.map_or(limit, |current: u64| current.min(limit)));
    }
    effective.context("projection has no outbound entitlement rate limit")
}

fn path_targets_route_owner(
    path: &cloud_control::PathCandidateV1,
    route_owner_attachment_ids: &HashSet<Uuid>,
) -> bool {
    route_owner_attachment_ids.contains(&path.destination_attachment_id)
}

fn path_belongs_to_projection(
    source_attachment_id: Uuid,
    path: &cloud_control::PathCandidateV1,
    participating_attachment_ids: &HashSet<Uuid>,
) -> bool {
    path.source_attachment_id == source_attachment_id
        && path_connects_participants(path, participating_attachment_ids)
}

fn path_connects_participants(
    path: &cloud_control::PathCandidateV1,
    participating_attachment_ids: &HashSet<Uuid>,
) -> bool {
    participating_attachment_ids.contains(&path.source_attachment_id)
        && participating_attachment_ids.contains(&path.destination_attachment_id)
}

fn participating_attachments<'a>(
    route_owner_attachment_ids: &HashSet<Uuid>,
    route_owner_paths: impl Iterator<Item = &'a cloud_control::PathCandidateV1>,
) -> HashSet<Uuid> {
    let mut participants = route_owner_attachment_ids.clone();
    let mut destinations_by_source = HashMap::<Uuid, HashSet<Uuid>>::new();
    for path in route_owner_paths {
        if route_owner_attachment_ids.contains(&path.destination_attachment_id) {
            destinations_by_source
                .entry(path.source_attachment_id)
                .or_default()
                .insert(path.destination_attachment_id);
        }
    }
    for (source, destinations) in destinations_by_source {
        if !route_owner_attachment_ids.contains(&source)
            && route_owner_attachment_ids
                .iter()
                .all(|owner| destinations.contains(owner))
        {
            participants.insert(source);
        }
    }
    participants
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
    if direct_peers.values().any(|(_, has_dialer)| !has_dialer) {
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
        self.routes
            .ensure_control_topology(snapshot.tenant_id, snapshot.segment_id, &snapshot.resources)
            .await
            .map_err(classify_publish_error)?;
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
            return Ok(PublishedGeneration {
                generation,
                content_hash,
            });
        }
        let input = self.build_input(snapshot).await.map_err(|error| {
            tracing::error!(
                event = "route_publication_input_failed",
                tenant_id = %snapshot.tenant_id,
                segment_id = %snapshot.segment_id,
                desired_revision = snapshot.desired_revision,
                error = %format_args!("{error:#}"),
                "could not construct the Core route publication input"
            );
            classify_input_error(error)
        })?;
        let built = build_route_publication(&input, &self.signer).map_err(|error| {
            tracing::error!(
                event = "route_publication_core_failed",
                tenant_id = %snapshot.tenant_id,
                segment_id = %snapshot.segment_id,
                desired_revision = snapshot.desired_revision,
                error = %error,
                "Core rejected the route publication"
            );
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
    let code = match &error {
        SdwanError::InvalidScope => "ROUTE_DB_INVALID_SCOPE",
        SdwanError::ScopeMismatch => "ROUTE_DB_SCOPE_MISMATCH",
        SdwanError::InvalidPrefix => "ROUTE_DB_INVALID_PREFIX",
        SdwanError::OverlappingPrefix => "ROUTE_DB_OVERLAPPING_PREFIX",
        SdwanError::DuplicateRouterAddress => "ROUTE_DB_DUPLICATE_ROUTER_ADDRESS",
        SdwanError::PrincipalMismatch => "ROUTE_DB_PRINCIPAL_MISMATCH",
        SdwanError::UnsignedObject => "ROUTE_DB_UNSIGNED_OBJECT",
        SdwanError::GenerationGap => "ROUTE_DB_GENERATION_GAP",
        SdwanError::MissingProjection => "ROUTE_DB_MISSING_PROJECTION",
        SdwanError::DuplicateProjection => "ROUTE_DB_DUPLICATE_PROJECTION",
        SdwanError::DivergentReplay => "ROUTE_DB_DIVERGENT_REPLAY",
        SdwanError::InvalidContentHash => "ROUTE_DB_INVALID_CONTENT_HASH",
        SdwanError::SegmentNotFound => "ROUTE_DB_SEGMENT_NOT_FOUND",
        SdwanError::Database(_) => "ROUTE_DB_DATABASE",
    };
    match error {
        SdwanError::Database(_) => PublicationFailure::Retryable {
            code: code.into(),
            retry_after: std::time::Duration::from_secs(5),
        },
        _ => PublicationFailure::Permanent { code: code.into() },
    }
}

fn classify_input_error(error: anyhow::Error) -> PublicationFailure {
    if let Some(readiness) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<InputReadinessError>())
    {
        return PublicationFailure::Retryable {
            code: readiness.code().into(),
            retry_after: std::time::Duration::from_secs(5),
        };
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_ref(seed: u8) -> PolicyRefV1 {
        PolicyRefV1 {
            policy_id: PolicyId([seed; 16]),
            generation: 1,
            content_hash: [seed; 32],
        }
    }

    fn policy_rule(
        seed: u8,
        priority: u32,
        source_site_id: Uuid,
        action: PolicyActionV1,
    ) -> ServicePolicyRuleV1 {
        ServicePolicyRuleV1 {
            id: Uuid::from_bytes([seed; 16]),
            priority,
            source_site_ids: vec![source_site_id],
            destination_prefixes: vec![cloud_control::Ipv4PrefixV1 {
                network: "0.0.0.0".parse().unwrap(),
                prefix_len: 1,
            }],
            domains: Vec::new(),
            traffic_classes: Vec::new(),
            action,
        }
    }

    fn egress(site_id: Uuid, attachment_id: Uuid) -> cloud_control::EgressV1 {
        cloud_control::EgressV1 {
            name: "test egress".into(),
            site_id,
            attachment_id,
            max_sessions: 100,
            max_bits_per_second: 1_000_000,
        }
    }

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
        assert!(
            validate_direct_dialers(&duplicate_full_duplex, &attachment_nodes, &nodes).is_err()
        );
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

    #[test]
    fn lower_priority_number_wins_for_identical_source_and_destination() {
        let source = Uuid::from_bytes([1; 16]);
        let us_site = Uuid::from_bytes([2; 16]);
        let hk_site = Uuid::from_bytes([3; 16]);
        let us_egress = Uuid::from_bytes([4; 16]);
        let hk_egress = Uuid::from_bytes([5; 16]);
        let egresses = HashMap::from([
            (us_egress, egress(us_site, Uuid::from_bytes([6; 16]))),
            (hk_egress, egress(hk_site, Uuid::from_bytes([7; 16]))),
        ]);
        let selected = select_remote_egress_rules(
            vec![
                (
                    policy_ref(10),
                    policy_rule(10, 100, source, PolicyActionV1::RemoteEgress(hk_egress)),
                ),
                (
                    policy_ref(11),
                    policy_rule(11, 99, source, PolicyActionV1::RemoteEgress(us_egress)),
                ),
            ],
            &HashSet::from([source, us_site, hk_site]),
            &egresses,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].priority, 99);
        assert_eq!(selected[0].egress_id, us_egress);
    }

    #[test]
    fn legacy_default_slices_publish_as_one_default_route() {
        let prefixes = [
            cloud_control::Ipv4PrefixV1 {
                network: std::net::Ipv4Addr::UNSPECIFIED,
                prefix_len: 1,
            },
            cloud_control::Ipv4PrefixV1 {
                network: std::net::Ipv4Addr::new(128, 0, 0, 0),
                prefix_len: 1,
            },
        ];

        assert_eq!(
            normalized_policy_destinations(&prefixes),
            vec![cloud_control::Ipv4PrefixV1 {
                network: std::net::Ipv4Addr::UNSPECIFIED,
                prefix_len: 0,
            }]
        );
    }

    #[test]
    fn equal_priority_conflicting_egresses_are_rejected() {
        let source = Uuid::from_bytes([1; 16]);
        let us_egress = Uuid::from_bytes([4; 16]);
        let hk_egress = Uuid::from_bytes([5; 16]);
        let egresses = HashMap::from([
            (
                us_egress,
                egress(Uuid::from_bytes([2; 16]), Uuid::from_bytes([6; 16])),
            ),
            (
                hk_egress,
                egress(Uuid::from_bytes([3; 16]), Uuid::from_bytes([7; 16])),
            ),
        ]);
        let error = select_remote_egress_rules(
            vec![
                (
                    policy_ref(10),
                    policy_rule(10, 99, source, PolicyActionV1::RemoteEgress(hk_egress)),
                ),
                (
                    policy_ref(11),
                    policy_rule(11, 99, source, PolicyActionV1::RemoteEgress(us_egress)),
                ),
            ],
            &HashSet::from([source]),
            &egresses,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("equal-priority conflicting actions"));
    }

    #[test]
    fn higher_priority_local_rule_suppresses_remote_egress() {
        let source = Uuid::from_bytes([1; 16]);
        let remote_egress = Uuid::from_bytes([4; 16]);
        let egresses = HashMap::from([(
            remote_egress,
            egress(Uuid::from_bytes([2; 16]), Uuid::from_bytes([6; 16])),
        )]);
        let selected = select_remote_egress_rules(
            vec![
                (
                    policy_ref(10),
                    policy_rule(10, 10, source, PolicyActionV1::LocalEgress),
                ),
                (
                    policy_ref(11),
                    policy_rule(11, 99, source, PolicyActionV1::RemoteEgress(remote_egress)),
                ),
            ],
            &HashSet::from([source]),
            &egresses,
        )
        .unwrap();

        assert!(selected.is_empty());
    }

    #[test]
    fn three_attachment_projections_keep_full_paths_between_participants() {
        let hangzhou = Uuid::from_bytes([3; 16]);
        let hong_kong = Uuid::from_bytes([4; 16]);
        let no_prefix_node = Uuid::from_bytes([5; 16]);
        let transport_node = Uuid::from_bytes([6; 16]);
        let peer = Uuid::from_bytes([2; 16]);
        let route_owners = HashSet::from([hangzhou, hong_kong]);
        let paths = [
            direct_path(peer, hangzhou, hong_kong, transport_node),
            direct_path(peer, hong_kong, hangzhou, transport_node),
            direct_path(peer, hangzhou, no_prefix_node, transport_node),
            direct_path(peer, no_prefix_node, hangzhou, transport_node),
            direct_path(peer, hong_kong, no_prefix_node, transport_node),
            direct_path(peer, no_prefix_node, hong_kong, transport_node),
        ];
        let all_participants = HashSet::from([hangzhou, hong_kong, no_prefix_node]);
        let destinations_for = |source| {
            paths
                .iter()
                .filter(|path| path_belongs_to_projection(source, path, &all_participants))
                .map(|path| path.destination_attachment_id)
                .collect::<HashSet<_>>()
        };

        assert_eq!(
            destinations_for(hangzhou),
            HashSet::from([hong_kong, no_prefix_node])
        );
        assert_eq!(
            destinations_for(hong_kong),
            HashSet::from([hangzhou, no_prefix_node])
        );
        assert_eq!(
            destinations_for(no_prefix_node),
            HashSet::from([hangzhou, hong_kong])
        );
        assert_eq!(
            participating_attachments(
                &route_owners,
                paths
                    .iter()
                    .filter(|path| path_targets_route_owner(path, &route_owners)),
            ),
            HashSet::from([hangzhou, hong_kong, no_prefix_node])
        );

        let partial_non_owner_paths = paths[..4]
            .iter()
            .filter(|path| path_targets_route_owner(path, &route_owners));
        assert_eq!(
            participating_attachments(&route_owners, partial_non_owner_paths),
            HashSet::from([hangzhou, hong_kong])
        );

        let active_paths = paths[..2].iter();
        assert_eq!(
            participating_attachments(&route_owners, active_paths),
            HashSet::from([hangzhou, hong_kong])
        );
    }

    #[test]
    fn incomplete_control_topology_is_retryable_with_a_persistable_code() {
        let failure = classify_input_error(InputReadinessError::PathCandidates.into());
        assert!(matches!(
            failure,
            PublicationFailure::Retryable { code, retry_after }
                if code == "ROUTE_INPUT_WAITING_FOR_PATHS"
                    && retry_after == std::time::Duration::from_secs(5)
        ));
    }

    #[test]
    fn database_publication_failures_use_a_stable_error_code() {
        let failure = classify_publish_error(SdwanError::Database("private detail".into()));
        assert!(matches!(
            failure,
            PublicationFailure::Retryable { code, .. } if code == "ROUTE_DB_DATABASE"
        ));
    }

    #[test]
    fn projection_uses_the_safe_minimum_across_outbound_candidates() {
        assert_eq!(
            effective_projection_rate_limit([2_500_000, 1_250_000, 5_000_000].into_iter()).unwrap(),
            1_250_000
        );
    }

    #[test]
    fn projection_rejects_missing_or_zero_candidate_quotas() {
        assert!(effective_projection_rate_limit(std::iter::empty()).is_err());
        assert!(effective_projection_rate_limit([1_250_000, 0].into_iter()).is_err());
    }
}
