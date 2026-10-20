use cloud_core_module::{CoreModule, ModuleRequirements, ObjectType, VerifiedModuleSpec};
use cloud_worker::route_publication::{
    build_route_publication, DeviceProjectionInput, RoutePublicationError, RoutePublicationInput,
    RouteSigner,
};
use cloud_worker::route_types::{
    AttachmentId, AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1, DeviceId,
    DeviceKeyId, Ipv4PrefixV1, NodeId, NodeKeyId, NodePoolId, PacketResourcePolicyV1,
    PathCandidateId, PathSelectionPolicyV1, PeerEndpointV1, PeerPathCandidateV1, PeerPathKindV1,
    PolicyId, PolicyRefV1, RemoteRouteV1, SegmentAttachmentV1, SegmentId,
    SharedHubAdmissionPolicyV1, SharedHubQuotaV1, SiteId, TenantId, TransportNodeIdentityV1,
    TransportPresetV1,
};
use ed25519_dalek::SigningKey;
use sha2::Digest;
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn real_core() -> Arc<CoreModule> {
    let path = PathBuf::from(
        std::env::var("CANDY_CORE_INTEROP_MODULE")
            .expect("CANDY_CORE_INTEROP_MODULE is required for this ignored test"),
    );
    let root = path.parent().unwrap().to_path_buf();
    let digest = sha2::Sha256::digest(fs::read(&path).unwrap());
    let owner_uid = fs::metadata(&root).unwrap().uid();
    Arc::new(
        CoreModule::load(
            &VerifiedModuleSpec::new(root, path, digest.into(), owner_uid),
            &ModuleRequirements {
                wire_protocol: Some("0.3".into()),
                required_objects: [
                    "route-envelope-v1",
                    "segment-snapshot-v1",
                    "site-projection-v1",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                ..ModuleRequirements::default()
            },
        )
        .unwrap(),
    )
}

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4PrefixV1 {
    Ipv4PrefixV1::new(network, prefix_len).unwrap()
}

fn resources() -> PacketResourcePolicyV1 {
    PacketResourcePolicyV1 {
        max_route_prefixes: 256,
        max_queue_packets: 1024,
        max_queue_bytes: 4 * 1024 * 1024,
        replay_window_packets: 1024,
        max_packets_per_second: 100_000,
        max_bytes_per_second: 100_000_000,
        allowed_traffic_classes: 1,
    }
}

fn peer(site: SiteId, attachment: AttachmentId, candidate: u8, policy: u8) -> PeerPathCandidateV1 {
    PeerPathCandidateV1 {
        candidate_id: PathCandidateId([candidate; 16]),
        peer_site_id: site,
        peer_attachment_id: attachment,
        kind: PeerPathKindV1::Direct,
        relay_node: None,
        node_pool_id: NodePoolId([candidate.wrapping_add(2); 16]),
        transport_node: TransportNodeIdentityV1 {
            node_id: NodeId([candidate.wrapping_add(3); 16]),
            node_key_id: NodeKeyId([candidate.wrapping_add(4); 16]),
        },
        endpoint: PeerEndpointV1::Ipv4 {
            address: [203, 0, 113, candidate],
            port: 18_443,
        },
        server_name: format!("node-{candidate}.candy.invalid-net"),
        server_cert_sha256: [candidate.wrapping_add(5); 32],
        transport_preset: TransportPresetV1::Current,
        priority: 100,
        authorization: PolicyRefV1 {
            policy_id: PolicyId([policy; 16]),
            generation: 1,
            content_hash: [policy.wrapping_add(1); 32],
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn projection(
    publication: u8,
    attachment: AttachmentId,
    _site: SiteId,
    _peer_site: SiteId,
    _peer_attachment: AttachmentId,
    _device: DeviceId,
    _device_key: DeviceKeyId,
    policy: u8,
    path: PeerPathCandidateV1,
) -> DeviceProjectionInput {
    DeviceProjectionInput {
        publication_id: Uuid::from_bytes([publication; 16]),
        attachment_id: attachment,
        projection_id: PolicyId([policy; 16]),
        projection_generation: 1,
        previous_hash: [0; 32],
        local_transport_node: None,
        path_policy: PathSelectionPolicyV1::DirectPreferred,
        peer_paths: vec![path],
        egress_routes: Vec::new(),
        egress_destination_prefixes: Vec::new(),
        coherent_manifest: CoherentPolicyManifestV1 {
            generation: 1,
            peer_paths_hash: [0; 32],
            dns_projection: None,
            egress_authorization: None,
            egress_gateway: false,
        },
        max_inner_mtu: 1180,
        resources: resources(),
    }
}

fn fixture() -> RoutePublicationInput {
    let tenant = TenantId([1; 16]);
    let segment = SegmentId([2; 16]);
    let local_site = SiteId([0x20; 16]);
    let remote_site = SiteId([0x21; 16]);
    let tunnel_host_site = SiteId([0x22; 16]);
    let local_attachment = AttachmentId([0x10; 16]);
    let remote_attachment = AttachmentId([0x11; 16]);
    let tunnel_host_attachment = AttachmentId([0x12; 16]);
    RoutePublicationInput {
        publication_id: Uuid::from_bytes([0x70; 16]),
        audit_event_id: Uuid::from_bytes([0x71; 16]),
        actor_id: "route-worker".into(),
        tenant_id: tenant,
        segment_id: segment,
        generation: 1,
        previous_hash: [0; 32],
        segment_overlay_prefix: prefix([100, 64, 0, 0], 24),
        attachments: vec![
            SegmentAttachmentV1 {
                attachment_id: local_attachment,
                site_id: Some(local_site),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId([0x30; 16]),
                    device_key_id: DeviceKeyId([0x40; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 10],
                local_prefixes: vec![prefix([10, 0, 0, 0], 24)],
                state: AttachmentState::Active,
                epoch_floor: 1,
            },
            SegmentAttachmentV1 {
                attachment_id: remote_attachment,
                site_id: Some(remote_site),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId([0x31; 16]),
                    device_key_id: DeviceKeyId([0x41; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 11],
                local_prefixes: vec![prefix([10, 1, 0, 0], 24)],
                state: AttachmentState::Active,
                epoch_floor: 2,
            },
            SegmentAttachmentV1 {
                attachment_id: tunnel_host_attachment,
                site_id: Some(tunnel_host_site),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId([0x32; 16]),
                    device_key_id: DeviceKeyId([0x42; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 12],
                local_prefixes: vec![],
                state: AttachmentState::Active,
                epoch_floor: 3,
            },
        ],
        not_before: 1_800_000_000,
        expires_at: 1_800_003_600,
        stale_until: 1_800_007_200,
        projections: vec![
            {
                let mut projection = projection(
                    0x80,
                    local_attachment,
                    local_site,
                    remote_site,
                    remote_attachment,
                    DeviceId([0x30; 16]),
                    DeviceKeyId([0x40; 16]),
                    0x60,
                    peer(remote_site, remote_attachment, 0x90, 0x61),
                );
                projection.peer_paths.push(peer(
                    tunnel_host_site,
                    tunnel_host_attachment,
                    0x94,
                    0x67,
                ));
                projection
            },
            {
                let mut projection = projection(
                    0x81,
                    remote_attachment,
                    remote_site,
                    local_site,
                    local_attachment,
                    DeviceId([0x31; 16]),
                    DeviceKeyId([0x41; 16]),
                    0x62,
                    peer(local_site, local_attachment, 0x91, 0x63),
                );
                projection.peer_paths.push(peer(
                    tunnel_host_site,
                    tunnel_host_attachment,
                    0x95,
                    0x68,
                ));
                projection
            },
            DeviceProjectionInput {
                publication_id: Uuid::from_bytes([0x82; 16]),
                attachment_id: tunnel_host_attachment,
                projection_id: PolicyId([0x64; 16]),
                projection_generation: 1,
                previous_hash: [0; 32],
                local_transport_node: None,
                path_policy: PathSelectionPolicyV1::DirectPreferred,
                peer_paths: vec![
                    peer(local_site, local_attachment, 0x92, 0x65),
                    peer(remote_site, remote_attachment, 0x93, 0x66),
                ],
                egress_routes: Vec::new(),
                egress_destination_prefixes: Vec::new(),
                coherent_manifest: CoherentPolicyManifestV1 {
                    generation: 1,
                    peer_paths_hash: [0; 32],
                    dns_projection: None,
                    egress_authorization: None,
                    egress_gateway: false,
                },
                max_inner_mtu: 1180,
                resources: resources(),
            },
        ],
    }
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn builds_and_verifies_multi_owner_tunnel_host_publication() {
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let core = real_core();
    let built = build_route_publication(
        &fixture(),
        &RouteSigner::new("route-key-1", key.clone(), core.clone()),
    )
    .unwrap();
    core.validate(
        ObjectType::ROUTE_ENVELOPE_V1,
        &built.segment.envelope,
        Some(&key.verifying_key().to_bytes()),
    )
    .unwrap();
    assert_eq!(built.segment.source.attachments.len(), 3);
    for projection in &built.projections {
        core.validate(
            ObjectType::ROUTE_ENVELOPE_V1,
            &projection.sealed.envelope,
            Some(&key.verifying_key().to_bytes()),
        )
        .unwrap();
    }
    let tunnel_host = built
        .projections
        .iter()
        .find(|projection| projection.sealed.source.local_prefixes.is_empty())
        .unwrap();
    assert_eq!(tunnel_host.sealed.source.peer_paths.len(), 2);
    for route_owner in built
        .projections
        .iter()
        .filter(|projection| !projection.sealed.source.local_prefixes.is_empty())
    {
        assert!(route_owner
            .sealed
            .source
            .peer_paths
            .iter()
            .any(|path| { path.peer_attachment_id == tunnel_host.sealed.source.attachment_id }));
    }
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn rejects_incomplete_or_cross_bound_peer_path_sets_before_signing() {
    let signer = RouteSigner::new(
        "route-key-1",
        SigningKey::from_bytes(&[0x77; 32]),
        real_core(),
    );
    let mut input = fixture();
    input.projections.pop();
    assert!(matches!(
        build_route_publication(&input, &signer),
        Err(RoutePublicationError::IncompleteProjectionSet)
    ));

    let mut input = fixture();
    input.projections[0].peer_paths[0].peer_attachment_id = AttachmentId([0x99; 16]);
    assert!(build_route_publication(&input, &signer).is_err());
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn database_write_binds_projection_to_exact_segment_hash() {
    let signer = RouteSigner::new(
        "route-key-1",
        SigningKey::from_bytes(&[0x77; 32]),
        real_core(),
    );
    let built = build_route_publication(&fixture(), &signer).unwrap();
    let write = built.database_write().unwrap();
    assert_eq!(write.projections.len(), 3);
    assert_eq!(write.snapshot.content_hash, built.segment.content_hash);
    assert!(write
        .projections
        .iter()
        .all(|projection| projection.segment_content_hash == write.snapshot.content_hash));
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn signs_explicit_remote_egress_source_and_gateway_roles() {
    let signer = RouteSigner::new(
        "route-key-1",
        SigningKey::from_bytes(&[0x77; 32]),
        real_core(),
    );
    let mut input = fixture();
    let authorization = PolicyRefV1 {
        policy_id: PolicyId([0xa1; 16]),
        generation: 1,
        content_hash: [0xa2; 32],
    };
    let peer = input.projections[0].peer_paths[0].clone();
    input.projections[0].coherent_manifest.egress_authorization = Some(authorization.clone());
    input.projections[0].egress_destination_prefixes =
        vec![Ipv4PrefixV1::new_egress_destination([0, 0, 0, 0], 0).unwrap()];
    input.projections[0].egress_routes = vec![RemoteRouteV1 {
        destination_prefix: Ipv4PrefixV1::new_egress_destination([0, 0, 0, 0], 0).unwrap(),
        owner_site_id: peer.peer_site_id,
        owner_attachment_ids: vec![peer.peer_attachment_id],
    }];
    let gateway = input
        .projections
        .iter_mut()
        .find(|projection| projection.attachment_id == peer.peer_attachment_id)
        .unwrap();
    gateway.coherent_manifest.egress_authorization = Some(authorization);
    gateway.coherent_manifest.egress_gateway = true;
    gateway.egress_destination_prefixes =
        vec![Ipv4PrefixV1::new_egress_destination([0, 0, 0, 0], 0).unwrap()];

    let built = build_route_publication(&input, &signer).unwrap();
    let source = built
        .projections
        .iter()
        .find(|projection| {
            projection.sealed.source.attachment_id == input.projections[0].attachment_id
        })
        .unwrap();
    assert_eq!(
        source
            .sealed
            .source
            .remote_routes
            .iter()
            .filter(|route| route.destination_prefix.prefix_len == 0)
            .count(),
        1
    );
    assert!(built.projections.iter().any(|projection| {
        projection.sealed.source.attachment_id == peer.peer_attachment_id
            && projection.sealed.source.coherent_manifest.egress_gateway
            && projection.sealed.source.egress_destination_prefixes.len() == 1
    }));
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn expansion_write_binds_to_core_segment_hash() {
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let signer = RouteSigner::new("route-key-1", key, real_core());
    let built = build_route_publication(&fixture(), &signer).unwrap();
    let quota = |max_entities| SharedHubQuotaV1 {
        max_entities,
        max_queue_packets: 1024,
        max_queue_bytes: 4 * 1024 * 1024,
        packets_per_second: 100_000,
        bytes_per_second: 100_000_000,
        burst_packets: 1000,
        burst_bytes: 1_000_000,
    };
    let sealed = signer
        .sign_shared_hub_admission(SharedHubAdmissionPolicyV1 {
            node_id: cloud_worker::route_types::NodeId([0x91; 16]),
            node_key_id: cloud_worker::route_types::NodeKeyId([0x92; 16]),
            node_pool_id: cloud_worker::route_types::NodePoolId([0x93; 16]),
            tenant_id: built.segment.source.tenant_id,
            segment_id: built.segment.source.segment_id,
            segment_generation: built.segment.source.segment_generation,
            segment_content_hash: built.segment.content_hash,
            policy_id: PolicyId([0x94; 16]),
            policy_generation: 1,
            not_before: 1_800_000_000,
            expires_at: 1_800_003_600,
            stale_until: 1_800_007_200,
            previous_hash: [0; 32],
            node: quota(64),
            tenant: quota(32),
            site: quota(16),
            tunnel: quota(1),
        })
        .unwrap();
    let expansion = cloud_worker::route_publication::BuiltExpansionPublication::SharedHub {
        publication_id: Uuid::from_bytes([0x95; 16]),
        sealed: Box::new(sealed),
    };
    let write = built.database_write_with_expansions(&[expansion]).unwrap();
    assert_eq!(
        write.expansions[0].segment_content_hash,
        built.segment.content_hash
    );
}

/// Real cross-repository bridge fixture. This signs with the locally built Core
/// ABI, persists those exact bytes in MySQL, and emits the Runtime API payload.
/// It does not claim to exercise a live TUN or packet forwarding.
#[tokio::test]
#[ignore = "requires DATABASE_URL, CANDY_CORE_INTEROP_MODULE and CANDY_POLICY_FIXTURE_OUTPUT_DIR"]
async fn signed_database_policy_catalog_bridge() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use cloud_db::sdwan::{
        RuntimeConfigurationApplyState as Apply, RuntimeConfigurationLookup,
        RuntimeConfigurationState, RuntimeConfigurationStatusWrite, RuntimePeerProjection,
        SdwanRepository,
    };
    let pool = cloud_db::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let output = PathBuf::from(std::env::var("CANDY_POLICY_FIXTURE_OUTPUT_DIR").unwrap());
    fs::create_dir_all(&output).unwrap();
    let core = real_core();
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let signer = RouteSigner::new("route-key-1", key.clone(), core.clone());
    let mut input = fixture();
    let mask = *Uuid::new_v4().as_bytes();
    let remap = |mut bytes: [u8; 16]| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte ^= mask[index];
        }
        bytes
    };
    input.tenant_id = TenantId(remap(input.tenant_id.0));
    input.segment_id = SegmentId(remap(input.segment_id.0));
    input.publication_id = Uuid::new_v4();
    input.audit_event_id = Uuid::new_v4();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    input.not_before = now - 30;
    input.expires_at = now + 3600;
    input.stale_until = now + 7200;
    for attachment in &mut input.attachments {
        attachment.attachment_id = AttachmentId(remap(attachment.attachment_id.0));
        attachment.site_id = attachment.site_id.map(|id| SiteId(remap(id.0)));
        let AttachmentPrincipalV1::Device {
            device_id,
            device_key_id,
        } = &mut attachment.principal
        else {
            panic!("device fixture")
        };
        *device_id = DeviceId(remap(device_id.0));
        *device_key_id = DeviceKeyId(remap(device_key_id.0));
    }
    let node_pool = Uuid::new_v4();
    for projection in &mut input.projections {
        projection.publication_id = Uuid::new_v4();
        projection.projection_id = PolicyId(remap(projection.projection_id.0));
        projection.attachment_id = AttachmentId(remap(projection.attachment_id.0));
        let own = input
            .attachments
            .iter()
            .find(|a| a.attachment_id == projection.attachment_id)
            .unwrap();
        let AttachmentPrincipalV1::Device { device_key_id, .. } = own.principal else {
            panic!()
        };
        projection.local_transport_node = Some(TransportNodeIdentityV1 {
            node_id: NodeId(own.attachment_id.0),
            node_key_id: NodeKeyId(device_key_id.0),
        });
        for path in &mut projection.peer_paths {
            path.candidate_id = PathCandidateId(remap(path.candidate_id.0));
            path.peer_site_id = SiteId(remap(path.peer_site_id.0));
            path.peer_attachment_id = AttachmentId(remap(path.peer_attachment_id.0));
            path.node_pool_id = NodePoolId(node_pool.into_bytes());
            path.authorization.policy_id = PolicyId(remap(path.authorization.policy_id.0));
            let remote = input
                .attachments
                .iter()
                .find(|a| a.attachment_id == path.peer_attachment_id)
                .unwrap();
            let AttachmentPrincipalV1::Device { device_key_id, .. } = remote.principal else {
                panic!()
            };
            path.transport_node = TransportNodeIdentityV1 {
                node_id: NodeId(remote.attachment_id.0),
                node_key_id: NodeKeyId(device_key_id.0),
            };
        }
        projection.peer_paths.sort_unstable_by_key(|path| {
            (
                path.peer_site_id.0,
                path.peer_attachment_id.0,
                path.priority,
                path.kind as u64,
                path.candidate_id.0,
            )
        });
    }
    let tenant = Uuid::from_bytes(input.tenant_id.0);
    let segment = Uuid::from_bytes(input.segment_id.0);
    let org = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(org)
        .bind(format!("signed-bridge-{org}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant)
        .bind(org)
        .bind(format!("signed-bridge-{tenant}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience) VALUES (?, ?, 'PRIVATE', ?, 'private')").bind(node_pool).bind(tenant).bind(format!("signed-bridge-{node_pool}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len) VALUES (?, ?, ?, ?, ?, 24)").bind(segment).bind(tenant).bind(format!("signed-bridge-{segment}")).bind(node_pool).bind([100u8,64,0,0].as_slice()).execute(&pool).await.unwrap();
    let mut lookups = Vec::new();
    for attachment in &input.attachments {
        let id = Uuid::from_bytes(attachment.attachment_id.0);
        let site = Uuid::from_bytes(attachment.site_id.unwrap().0);
        let AttachmentPrincipalV1::Device {
            device_id,
            device_key_id,
        } = attachment.principal
        else {
            panic!()
        };
        let device = Uuid::from_bytes(device_id.0);
        let device_key = Uuid::from_bytes(device_key_id.0);
        sqlx::query("INSERT INTO sites (id, tenant_id, name) VALUES (?, ?, ?)")
            .bind(site)
            .bind(tenant)
            .bind(format!("signed-bridge-{site}"))
            .execute(&pool)
            .await
            .unwrap();
        for prefix in &attachment.local_prefixes {
            sqlx::query("INSERT INTO site_prefixes (id, tenant_id, site_id, network, prefix_len, state) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
                .bind(Uuid::new_v4()).bind(tenant).bind(site).bind(prefix.network.as_slice())
                .bind(prefix.prefix_len).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, 'signed-bridge', 'ACTIVE')").bind(device).bind(tenant).bind(device.to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')").bind(device_key).bind(tenant).bind(device).bind(device_key.to_string()).bind([1u8;32].as_slice()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO nodes (id, tenant_id, device_id, device_key_id, node_pool_id, node_id, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')").bind(id).bind(tenant).bind(device).bind(device_key).bind(node_pool).bind(id.to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO node_endpoints (id, node_id, endpoint, transport, server_name, transport_preset, status, region) VALUES (?, ?, '203.0.113.1:18443', 'CANDY_QUIC_UDP', 'fixture.candy.invalid-net', 'CURRENT', 'ACTIVE', 'test')").bind(Uuid::new_v4()).bind(id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO segment_attachments (id, tenant_id, segment_id, site_id, principal_kind, device_id, device_key_id, overlay_router_ipv4, state, epoch_floor) VALUES (?, ?, ?, ?, 'DEVICE', ?, ?, ?, 'ACTIVE', ?)").bind(id).bind(tenant).bind(segment).bind(site).bind(device).bind(device_key).bind(attachment.overlay_router_ipv4.as_slice()).bind(attachment.epoch_floor).execute(&pool).await.unwrap();
        lookups.push(RuntimeConfigurationLookup {
            tenant_id: tenant,
            device_id: device,
            device_key_id: device_key,
        });
    }
    let repository = SdwanRepository::new(pool.clone()).with_policy_isolation(true);
    let mut built = build_route_publication(&input, &signer).unwrap();
    repository
        .publish(&built.database_write().unwrap())
        .await
        .unwrap();
    for state in [Apply::Prepared, Apply::Active] {
        for lookup in &lookups {
            let RuntimeConfigurationState::Current(config) = repository
                .current_runtime_configuration(lookup)
                .await
                .unwrap()
            else {
                panic!()
            };
            repository
                .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
                    lookup: lookup.clone(),
                    projection_publication_id: config.projection_publication_id,
                    projection_content_hash: config.projection_content_hash,
                    envelope_sha256: config.envelope_sha256(),
                    apply_state: state,
                    error_code: None,
                })
                .await
                .unwrap();
        }
    }
    for generation in 2..=3 {
        input.previous_hash = built.segment.content_hash;
        input.generation = generation;
        input.publication_id = Uuid::new_v4();
        input.audit_event_id = Uuid::new_v4();
        for projection in &mut input.projections {
            let previous = built
                .projections
                .iter()
                .find(|previous| previous.sealed.source.attachment_id == projection.attachment_id)
                .unwrap();
            projection.publication_id = Uuid::new_v4();
            projection.projection_generation = generation;
            projection.previous_hash = previous.sealed.content_hash;
            projection.coherent_manifest.generation = generation;
        }
        built = build_route_publication(&input, &signer).unwrap();
        let mut write = built.database_write().unwrap();
        write.policy_only = true;
        repository.publish(&write).await.unwrap();
        if generation == 2 {
            let RuntimeConfigurationState::Current(config) = repository
                .current_runtime_configuration(&lookups[0])
                .await
                .unwrap()
            else {
                panic!()
            };
            repository
                .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
                    lookup: lookups[0].clone(),
                    projection_publication_id: config.projection_publication_id,
                    projection_content_hash: config.projection_content_hash,
                    envelope_sha256: config.envelope_sha256(),
                    apply_state: Apply::Active,
                    error_code: None,
                })
                .await
                .unwrap();
        }
    }
    let RuntimeConfigurationState::Current(config) = repository
        .current_runtime_configuration(&lookups[2])
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        config
            .compatibility_generations
            .iter()
            .map(|group| group.segment_generation)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let peer_json = |peer: &RuntimePeerProjection| {
        serde_json::json!({ "projection_id": peer.projection_id,
        "projection_generation": peer.projection_generation, "projection_content_hash": hex(&peer.projection_content_hash),
        "site_projection": URL_SAFE_NO_PAD.encode(&peer.signed_projection_envelope) })
    };
    let payload = serde_json::json!({
        "schema_version":1, "activation_phase":"commit", "projection_publication_id":config.projection_publication_id,
        "projection_id":config.projection_id,"segment_id":config.segment_id,"attachment_id":config.attachment_id,
        "segment_generation":config.segment_generation,"projection_generation":config.projection_generation,
        "projection_content_hash":hex(&config.projection_content_hash), "route_signing_key_id":"route-key-1",
        "route_signing_public_key":hex(&key.verifying_key().to_bytes()), "segment_snapshot": URL_SAFE_NO_PAD.encode(&config.signed_segment_envelope),
        "site_projection":URL_SAFE_NO_PAD.encode(&config.signed_projection_envelope),
        "peer_projection_catalog":config.peer_projection_catalog.iter().map(peer_json).collect::<Vec<_>>(),
        "compatibility_generations": config.compatibility_generations.iter().map(|group| serde_json::json!({
            "segment_generation":group.segment_generation,"segment_content_hash":hex(&group.segment_content_hash),
            "segment_snapshot":URL_SAFE_NO_PAD.encode(&group.signed_segment_envelope),
            "peer_projection_catalog":group.peer_projection_catalog.iter().map(peer_json).collect::<Vec<_>>()
        })).collect::<Vec<_>>(), "grant_verification_keys":[]
    });
    for envelope in std::iter::once(&config.signed_segment_envelope)
        .chain(std::iter::once(&config.signed_projection_envelope))
        .chain(
            config
                .peer_projection_catalog
                .iter()
                .map(|peer| &peer.signed_projection_envelope),
        )
        .chain(config.compatibility_generations.iter().flat_map(|group| {
            std::iter::once(&group.signed_segment_envelope).chain(
                group
                    .peer_projection_catalog
                    .iter()
                    .map(|peer| &peer.signed_projection_envelope),
            )
        }))
    {
        core.validate(
            ObjectType::ROUTE_ENVELOPE_V1,
            envelope,
            Some(&key.verifying_key().to_bytes()),
        )
        .unwrap();
    }
    fs::write(
        output.join("runtime-configuration.json"),
        serde_json::to_vec_pretty(&payload).unwrap(),
    )
    .unwrap();
    fs::write(output.join("identity.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "tenant_id":tenant,"device_id":lookups[2].device_id,"device_key_id":lookups[2].device_key_id,
        "site_id":Uuid::from_bytes(input.attachments[2].site_id.unwrap().0),
    })).unwrap()).unwrap();
    println!("signed_database_policy_catalog_bridge output={} current_generation=3 retained_generations=1,2", output.display());
}
