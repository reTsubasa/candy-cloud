use candy_proto::{
    cloud_grant::{DeviceId, DeviceKeyId, NodePoolId, PolicyId, TenantId},
    dynamic_route_contract::{DynamicRouteSnapshotV1, DynamicRouteV1},
    fabric_assignment_contract::{FabricAttachmentAssignmentV1, HubFabricAssignmentV1},
    ip_tunnel::{AttachmentId, SegmentId, SiteId},
    mesh_contract::{MeshMembershipProjectionV1, MeshPeerRefV1},
    route_contract::{
        AllowedHubNodeV1, AttachmentPrincipalV1, AttachmentState, FailoverPolicyV1, Ipv4PrefixV1,
        NodeId, NodeKeyId, PacketResourcePolicyV1, SegmentAttachmentV1,
    },
    shared_hub_contract::{SharedHubAdmissionPolicyV1, SharedHubQuotaV1},
};
use carrier_crypto::route_contract::{
    verify_dynamic_route_snapshot, verify_fabric_assignment, verify_mesh_membership,
    verify_shared_hub_admission,
};
use cloud_worker::route_publication::{
    build_route_publication, BuiltExpansionPublication, DeviceProjectionInput,
    RoutePublicationError, RoutePublicationInput, RouteSigner,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct VectorDocument {
    segment_envelope_hex: String,
    projection_envelope_hex: String,
}

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4PrefixV1 {
    Ipv4PrefixV1::new(network, prefix_len).unwrap()
}

fn fixture() -> RoutePublicationInput {
    RoutePublicationInput {
        publication_id: Uuid::from_bytes([0x70; 16]),
        audit_event_id: Uuid::from_bytes([0x71; 16]),
        actor_id: "route-worker".into(),
        tenant_id: TenantId([1; 16]),
        segment_id: SegmentId([2; 16]),
        generation: 1,
        previous_hash: [0; 32],
        hub_node_pool_id: NodePoolId([3; 16]),
        segment_overlay_prefix: prefix([100, 64, 0, 0], 24),
        attachments: vec![
            SegmentAttachmentV1 {
                attachment_id: AttachmentId([0x10; 16]),
                site_id: Some(SiteId([0x20; 16])),
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
                attachment_id: AttachmentId([0x11; 16]),
                site_id: Some(SiteId([0x21; 16])),
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
                attachment_id: AttachmentId([0x12; 16]),
                site_id: None,
                principal: AttachmentPrincipalV1::Node {
                    node_id: NodeId([0x50; 16]),
                    node_key_id: NodeKeyId([0x51; 16]),
                },
                overlay_router_ipv4: [100, 64, 0, 12],
                local_prefixes: Vec::new(),
                state: AttachmentState::Active,
                epoch_floor: 3,
            },
        ],
        not_before: 1_800_000_000,
        expires_at: 1_800_003_600,
        stale_until: 1_800_007_200,
        projections: vec![
            DeviceProjectionInput {
                publication_id: Uuid::from_bytes([0x80; 16]),
                attachment_id: AttachmentId([0x10; 16]),
                projection_id: PolicyId([0x60; 16]),
                projection_generation: 1,
                previous_hash: [0; 32],
                allowed_hub_nodes: vec![AllowedHubNodeV1 {
                    node_id: NodeId([0x50; 16]),
                    node_key_id: NodeKeyId([0x51; 16]),
                    diagnostic_attachment_id: AttachmentId([0x12; 16]),
                }],
                max_inner_mtu: 1180,
                failover: FailoverPolicyV1 {
                    max_preconnected_hubs: 1,
                    critical_recovery_ms: 3_000,
                    standard_recovery_ms: 5_000,
                },
                resources: PacketResourcePolicyV1 {
                    max_route_prefixes: 256,
                    max_queue_packets: 1024,
                    max_queue_bytes: 4 * 1024 * 1024,
                    replay_window_packets: 1024,
                    max_packets_per_second: 100_000,
                    max_bytes_per_second: 100_000_000,
                    allowed_traffic_classes: 1,
                },
            },
            DeviceProjectionInput {
                publication_id: Uuid::from_bytes([0x81; 16]),
                attachment_id: AttachmentId([0x11; 16]),
                projection_id: PolicyId([0x61; 16]),
                projection_generation: 1,
                previous_hash: [0; 32],
                allowed_hub_nodes: vec![AllowedHubNodeV1 {
                    node_id: NodeId([0x50; 16]),
                    node_key_id: NodeKeyId([0x51; 16]),
                    diagnostic_attachment_id: AttachmentId([0x12; 16]),
                }],
                max_inner_mtu: 1180,
                failover: FailoverPolicyV1 {
                    max_preconnected_hubs: 1,
                    critical_recovery_ms: 3_000,
                    standard_recovery_ms: 5_000,
                },
                resources: PacketResourcePolicyV1 {
                    max_route_prefixes: 256,
                    max_queue_packets: 1024,
                    max_queue_bytes: 4 * 1024 * 1024,
                    replay_window_packets: 1024,
                    max_packets_per_second: 100_000,
                    max_bytes_per_second: 100_000_000,
                    allowed_traffic_classes: 1,
                },
            },
        ],
    }
}

#[test]
fn builds_one_coherent_publication_and_reproduces_core_vectors() {
    let vector: VectorDocument = serde_json::from_str(include_str!(
        "../../../../udp协议/interop/vectors/candy-sdwan-route-contract-v1.json"
    ))
    .unwrap();
    let built = build_route_publication(
        &fixture(),
        &RouteSigner::new("route-key-1", SigningKey::from_bytes(&[0x77; 32])),
    )
    .unwrap();

    assert_eq!(
        hex(&built.segment.envelope.encode().unwrap()),
        vector.segment_envelope_hex
    );
    assert_eq!(
        hex(&built.projections[0].sealed.envelope.encode().unwrap()),
        vector.projection_envelope_hex
    );
    assert_eq!(built.projections.len(), 2);
}

#[test]
fn rejects_incomplete_projection_and_node_key_mismatch_before_signing() {
    let signer = RouteSigner::new("route-key-1", SigningKey::from_bytes(&[0x77; 32]));
    let mut input = fixture();
    input.projections.pop();
    assert!(build_route_publication(&input, &signer).is_err());

    let mut input = fixture();
    input.projections[0].allowed_hub_nodes[0].node_key_id = NodeKeyId([0x52; 16]);
    assert!(build_route_publication(&input, &signer).is_err());
}

#[test]
fn signs_expansion_objects_against_the_exact_segment_publication() {
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let signer = RouteSigner::new("route-key-1", key.clone());
    let routes = build_route_publication(&fixture(), &signer).unwrap();
    let segment = &routes.segment.object;
    let quota = |entities| SharedHubQuotaV1 {
        max_entities: entities,
        max_queue_packets: 1024,
        max_queue_bytes: 1024 * 1024,
        packets_per_second: 10_000,
        bytes_per_second: 10_000_000,
        burst_packets: 1_000,
        burst_bytes: 1_000_000,
    };
    let shared = signer
        .sign_shared_hub_admission(SharedHubAdmissionPolicyV1 {
            node_id: NodeId([0x50; 16]),
            node_key_id: NodeKeyId([0x51; 16]),
            node_pool_id: segment.hub_node_pool_id,
            tenant_id: segment.tenant_id,
            segment_id: segment.segment_id,
            segment_generation: segment.segment_generation,
            segment_content_hash: segment.content_hash,
            policy_id: PolicyId([0x90; 16]),
            policy_generation: 1,
            not_before: segment.not_before,
            expires_at: segment.expires_at,
            stale_until: segment.stale_until,
            previous_hash: [0; 32],
            node: quota(64),
            tenant: quota(32),
            site: quota(16),
            tunnel: quota(1),
            content_hash: [0; 32],
        })
        .unwrap();
    assert_eq!(
        verify_shared_hub_admission(&shared.envelope, &key.verifying_key()).unwrap(),
        shared.object
    );

    let local = &routes.projections[0].sealed.object;
    let remote = &routes.projections[1].sealed.object;
    let mesh = signer
        .sign_mesh_membership(MeshMembershipProjectionV1 {
            tenant_id: local.tenant_id,
            segment_id: local.segment_id,
            segment_generation: local.segment_generation,
            segment_content_hash: local.segment_content_hash,
            local_site_id: local.site_id,
            local_attachment_id: local.attachment_id,
            peers: vec![MeshPeerRefV1 {
                site_id: remote.site_id,
                attachment_id: remote.attachment_id,
                epoch_floor: 2,
            }],
            projection_id: PolicyId([0x91; 16]),
            projection_generation: 1,
            not_before: local.not_before,
            expires_at: local.expires_at,
            stale_until: local.stale_until,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        })
        .unwrap();
    assert_eq!(
        verify_mesh_membership(&mesh.envelope, &key.verifying_key()).unwrap(),
        mesh.object
    );

    let dynamic = signer
        .sign_dynamic_route_snapshot(DynamicRouteSnapshotV1 {
            tenant_id: segment.tenant_id,
            segment_id: segment.segment_id,
            base_segment_generation: segment.segment_generation,
            base_segment_content_hash: segment.content_hash,
            routes: vec![DynamicRouteV1 {
                prefix: prefix([10, 2, 0, 0], 24),
                owner_site_id: remote.site_id,
                owner_attachment_id: remote.attachment_id,
                metric: 100,
            }],
            policy_id: PolicyId([0x92; 16]),
            generation: 1,
            not_before: segment.not_before,
            expires_at: segment.expires_at,
            stale_until: segment.stale_until,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        })
        .unwrap();
    assert_eq!(
        verify_dynamic_route_snapshot(&dynamic.envelope, &key.verifying_key()).unwrap(),
        dynamic.object
    );
    let fabric = signer
        .sign_fabric_assignment(HubFabricAssignmentV1 {
            tenant_id: segment.tenant_id,
            segment_id: segment.segment_id,
            segment_generation: segment.segment_generation,
            segment_content_hash: segment.content_hash,
            assignments: vec![
                FabricAttachmentAssignmentV1 {
                    site_id: local.site_id,
                    attachment_id: local.attachment_id,
                    hub_node_id: NodeId([0x50; 16]),
                    hub_node_key_id: NodeKeyId([0x51; 16]),
                    hub_attachment_id: AttachmentId([0x12; 16]),
                    attachment_epoch: 1,
                },
                FabricAttachmentAssignmentV1 {
                    site_id: remote.site_id,
                    attachment_id: remote.attachment_id,
                    hub_node_id: NodeId([0x50; 16]),
                    hub_node_key_id: NodeKeyId([0x51; 16]),
                    hub_attachment_id: AttachmentId([0x12; 16]),
                    attachment_epoch: 2,
                },
            ],
            policy_id: PolicyId([0x93; 16]),
            generation: 1,
            not_before: segment.not_before,
            expires_at: segment.expires_at,
            stale_until: segment.stale_until,
            previous_hash: [0; 32],
            content_hash: [0; 32],
        })
        .unwrap();
    assert_eq!(
        verify_fabric_assignment(&fabric.envelope, &key.verifying_key()).unwrap(),
        fabric.object
    );

    let expansions = vec![
        BuiltExpansionPublication::SharedHub {
            publication_id: Uuid::from_bytes([0xa0; 16]),
            sealed: Box::new(shared),
        },
        BuiltExpansionPublication::Mesh {
            publication_id: Uuid::from_bytes([0xa1; 16]),
            sealed: Box::new(mesh),
        },
        BuiltExpansionPublication::DynamicRoute {
            publication_id: Uuid::from_bytes([0xa2; 16]),
            sealed: Box::new(dynamic.clone()),
        },
        BuiltExpansionPublication::FabricAssignment {
            publication_id: Uuid::from_bytes([0xa3; 16]),
            sealed: Box::new(fabric),
        },
    ];
    let write = routes.database_write_with_expansions(&expansions).unwrap();
    assert_eq!(write.expansions.len(), 4);
    assert_eq!(
        write.expansions[0].kind,
        cloud_db::sdwan::ExpansionObjectKind::SharedHubAdmission
    );
    assert_eq!(write.expansions[0].site_id, None);
    assert_eq!(
        write.expansions[1].kind,
        cloud_db::sdwan::ExpansionObjectKind::MeshMembership
    );
    assert_eq!(write.expansions[1].site_id, Some(uuid(local.site_id.0)));
    assert_eq!(
        write.expansions[1].attachment_id,
        Some(uuid(local.attachment_id.0))
    );
    assert_eq!(
        write.expansions[2].kind,
        cloud_db::sdwan::ExpansionObjectKind::DynamicRouteSnapshot
    );
    assert_eq!(
        write.expansions[2].segment_content_hash,
        segment.content_hash
    );
    assert_eq!(
        write.expansions[3].kind,
        cloud_db::sdwan::ExpansionObjectKind::FabricAssignment
    );
    assert_eq!(write.expansions[3].site_id, None);

    let mut wrong_base = dynamic;
    wrong_base.object.base_segment_content_hash = [0xff; 32];
    assert!(matches!(
        routes.database_write_with_expansions(&[BuiltExpansionPublication::DynamicRoute {
            publication_id: Uuid::from_bytes([0xa4; 16]),
            sealed: Box::new(wrong_base),
        }]),
        Err(RoutePublicationError::ExpansionScopeMismatch)
    ));
}

fn uuid(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
