use candy_proto::{
    cloud_grant::{DeviceId, DeviceKeyId, PolicyId, PolicyRefV1, TenantId},
    ip_tunnel::{AttachmentId, SegmentId, SiteId},
    route_contract::{
        AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1, Ipv4PrefixV1,
        PacketResourcePolicyV1, PathCandidateId, PathSelectionPolicyV1, PeerEndpointV1,
        PeerPathCandidateV1, PeerPathKindV1, SegmentAttachmentV1,
    },
};
use carrier_crypto::route_contract::{verify_segment_snapshot, verify_site_projection};
use cloud_worker::route_publication::{
    build_route_publication, DeviceProjectionInput, RoutePublicationError, RoutePublicationInput,
    RouteSigner,
};
use ed25519_dalek::SigningKey;
use uuid::Uuid;

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
        endpoint: PeerEndpointV1::Ipv4 {
            address: [203, 0, 113, candidate],
            port: 18_443,
        },
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
        path_policy: PathSelectionPolicyV1::DirectPreferred,
        peer_paths: vec![path],
        coherent_manifest: CoherentPolicyManifestV1 {
            generation: 1,
            peer_paths_hash: [0; 32],
            dns_projection: None,
            egress_authorization: None,
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
    let local_attachment = AttachmentId([0x10; 16]);
    let remote_attachment = AttachmentId([0x11; 16]);
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
        ],
        not_before: 1_800_000_000,
        expires_at: 1_800_003_600,
        stale_until: 1_800_007_200,
        projections: vec![
            projection(
                0x80,
                local_attachment,
                local_site,
                remote_site,
                remote_attachment,
                DeviceId([0x30; 16]),
                DeviceKeyId([0x40; 16]),
                0x60,
                peer(remote_site, remote_attachment, 0x90, 0x61),
            ),
            projection(
                0x81,
                remote_attachment,
                remote_site,
                local_site,
                local_attachment,
                DeviceId([0x31; 16]),
                DeviceKeyId([0x41; 16]),
                0x62,
                peer(local_site, local_attachment, 0x91, 0x63),
            ),
        ],
    }
}

#[test]
fn builds_and_verifies_direct_first_v1_publication() {
    let key = SigningKey::from_bytes(&[0x77; 32]);
    let built =
        build_route_publication(&fixture(), &RouteSigner::new("route-key-1", key.clone())).unwrap();
    let snapshot = verify_segment_snapshot(&built.segment.envelope, &key.verifying_key()).unwrap();
    assert_eq!(snapshot, built.segment.object);
    assert_eq!(snapshot.attachments.len(), 2);
    for projection in &built.projections {
        let verified =
            verify_site_projection(&projection.sealed.envelope, &key.verifying_key()).unwrap();
        assert_eq!(verified, projection.sealed.object);
        assert_eq!(verified.peer_paths.len(), 1);
        assert_ne!(verified.coherent_manifest.peer_paths_hash, [0; 32]);
    }
}

#[test]
fn rejects_incomplete_or_cross_bound_peer_path_sets_before_signing() {
    let signer = RouteSigner::new("route-key-1", SigningKey::from_bytes(&[0x77; 32]));
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
fn database_write_binds_projection_to_exact_segment_hash() {
    let signer = RouteSigner::new("route-key-1", SigningKey::from_bytes(&[0x77; 32]));
    let built = build_route_publication(&fixture(), &signer).unwrap();
    let write = built.database_write().unwrap();
    assert_eq!(write.projections.len(), 2);
    assert_eq!(
        write.snapshot.content_hash,
        built.segment.object.content_hash
    );
    assert!(write
        .projections
        .iter()
        .all(|projection| projection.segment_content_hash == write.snapshot.content_hash));
}
