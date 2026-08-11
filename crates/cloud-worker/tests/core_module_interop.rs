use cloud_core_module::{CoreModule, ModuleRequirements, ObjectType, VerifiedModuleSpec};
use cloud_worker::{
    route_publication::RouteSigner,
    route_types::{
        AttachmentId, DynamicRouteSnapshotV1, DynamicRouteV1, FabricAttachmentAssignmentV1,
        HubFabricAssignmentV1, Ipv4PrefixV1, MeshMembershipProjectionV1, MeshPeerRefV1, NodeId,
        NodeKeyId, NodePoolId, PolicyId, SegmentId, SharedHubAdmissionPolicyV1, SharedHubQuotaV1,
        SiteId, TenantId,
    },
};
use ed25519_dalek::SigningKey;
use sha2::Digest;
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc};

const ROUTE_KEY_ID: &str = "route-key-1";

fn id(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn real_core() -> Arc<CoreModule> {
    let path = PathBuf::from(
        std::env::var("CANDY_CORE_INTEROP_MODULE")
            .expect("CANDY_CORE_INTEROP_MODULE must point to a released Core module"),
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
                    "shared-hub-admission-v1",
                    "mesh-membership-v1",
                    "dynamic-route-snapshot-v1",
                    "fabric-assignment-v1",
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

fn assert_valid(core: &CoreModule, key: &SigningKey, envelope: &[u8]) {
    core.validate(
        ObjectType::ROUTE_ENVELOPE_V1,
        envelope,
        Some(&key.verifying_key().to_bytes()),
    )
    .unwrap();
}

#[test]
#[ignore = "requires CANDY_CORE_INTEROP_MODULE"]
fn signs_all_sdwan_expansion_objects_through_core_module() {
    let core = real_core();
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let signer = RouteSigner::new(ROUTE_KEY_ID, signing_key.clone(), core.clone());
    let quota = |max_entities| SharedHubQuotaV1 {
        max_entities,
        max_queue_packets: 1024,
        max_queue_bytes: 4 * 1024 * 1024,
        packets_per_second: 100_000,
        bytes_per_second: 100_000_000,
        burst_packets: 1000,
        burst_bytes: 1_000_000,
    };
    let shared_hub = signer
        .sign_shared_hub_admission(SharedHubAdmissionPolicyV1 {
            node_id: NodeId(id(30)),
            node_key_id: NodeKeyId(id(31)),
            node_pool_id: NodePoolId(id(32)),
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            segment_generation: 1,
            segment_content_hash: [3; 32],
            policy_id: PolicyId(id(33)),
            policy_generation: 1,
            not_before: 100,
            expires_at: 200,
            stale_until: 250,
            previous_hash: [0; 32],
            node: quota(64),
            tenant: quota(32),
            site: quota(16),
            tunnel: quota(1),
        })
        .unwrap();
    assert_valid(&core, &signing_key, &shared_hub.envelope);

    let mesh = signer
        .sign_mesh_membership(MeshMembershipProjectionV1 {
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            segment_generation: 1,
            segment_content_hash: [3; 32],
            local_site_id: SiteId(id(4)),
            local_attachment_id: AttachmentId(id(5)),
            peers: vec![MeshPeerRefV1 {
                site_id: SiteId(id(6)),
                attachment_id: AttachmentId(id(7)),
                epoch_floor: 1,
            }],
            projection_id: PolicyId(id(34)),
            projection_generation: 1,
            not_before: 100,
            expires_at: 200,
            stale_until: 250,
            previous_hash: [0; 32],
        })
        .unwrap();
    assert_valid(&core, &signing_key, &mesh.envelope);

    let dynamic = signer
        .sign_dynamic_route_snapshot(DynamicRouteSnapshotV1 {
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            base_segment_generation: 1,
            base_segment_content_hash: [3; 32],
            routes: vec![DynamicRouteV1 {
                prefix: Ipv4PrefixV1::new([10, 20, 0, 0], 16).unwrap(),
                owner_site_id: SiteId(id(6)),
                owner_attachment_id: AttachmentId(id(7)),
                metric: 100,
            }],
            policy_id: PolicyId(id(35)),
            generation: 1,
            not_before: 100,
            expires_at: 200,
            stale_until: 250,
            previous_hash: [0; 32],
        })
        .unwrap();
    assert_valid(&core, &signing_key, &dynamic.envelope);

    let fabric = signer
        .sign_fabric_assignment(HubFabricAssignmentV1 {
            tenant_id: TenantId(id(1)),
            segment_id: SegmentId(id(2)),
            segment_generation: 1,
            segment_content_hash: [3; 32],
            assignments: vec![FabricAttachmentAssignmentV1 {
                site_id: SiteId(id(6)),
                attachment_id: AttachmentId(id(7)),
                hub_node_id: NodeId(id(30)),
                hub_node_key_id: NodeKeyId(id(31)),
                hub_attachment_id: AttachmentId(id(8)),
                attachment_epoch: 1,
            }],
            policy_id: PolicyId(id(36)),
            generation: 1,
            not_before: 100,
            expires_at: 200,
            stale_until: 250,
            previous_hash: [0; 32],
        })
        .unwrap();
    assert_valid(&core, &signing_key, &fabric.envelope);
}
