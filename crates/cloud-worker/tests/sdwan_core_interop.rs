use candy_proto::{
    cloud_grant::{
        AccessGrantPayloadV1, DeviceId, DeviceKeyId, NodePoolId, PolicyId, PolicyRefV1,
        ServiceClass, TenantId,
    },
    features::FeatureSet,
    ip_tunnel::{AttachmentId, OpenIpTunnel, SegmentId, SiteId, IP_PACKET_FORMAT_V1},
    route_contract::{
        AttachmentPrincipalV1, AttachmentState, CoherentPolicyManifestV1, Ipv4PrefixV1,
        PacketResourcePolicyV1, PathCandidateId, PathSelectionPolicyV1, PeerEndpointV1,
        PeerPathCandidateV1, PeerPathKindV1, SegmentAttachmentV1,
    },
};
use candy_tun::control::{
    authorize_ip_tunnel, AuthenticatedDevice, AuthorizationInput, ControlError, DirectPeerContext,
    RouteTrustStore, TunnelPeerContext, TunnelUse, VerifiedControl, VerifiedSegmentSnapshot,
    VerifiedSiteProjection,
};
use cloud_auth::{
    domain::{
        AuthorizationSnapshot, DeviceStatus, EntitlementSnapshot, GrantRequest,
        ServiceClass as CloudServiceClass, SnapshotDevice, SnapshotStatus,
    },
    grants::GrantSigner,
    issuance::{
        prepare_private_grant_with_id, GrantQuota, IssuerConfig, PrivateGrantMaterial,
        RoutePolicyBinding,
    },
};
use cloud_worker::route_publication::{
    build_route_publication, DeviceProjectionInput, RoutePublicationInput, RouteSigner,
};
use ed25519_dalek::SigningKey;
use uuid::Uuid;

const NOW: u64 = 150;
const ROUTE_KEY_ID: &str = "route-key-1";

fn id(byte: u8) -> [u8; 16] {
    [byte; 16]
}

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes(id(byte))
}

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4PrefixV1 {
    Ipv4PrefixV1::new(network, prefix_len).unwrap()
}

fn resources() -> PacketResourcePolicyV1 {
    PacketResourcePolicyV1 {
        max_route_prefixes: 64,
        max_queue_packets: 128,
        max_queue_bytes: 262_144,
        replay_window_packets: 1024,
        max_packets_per_second: 10_000,
        max_bytes_per_second: 1_000_000,
        allowed_traffic_classes: 0x03,
    }
}

fn direct_peer(site: SiteId, attachment: AttachmentId, candidate: u8) -> PeerPathCandidateV1 {
    PeerPathCandidateV1 {
        candidate_id: PathCandidateId(id(candidate)),
        peer_site_id: site,
        peer_attachment_id: attachment,
        kind: PeerPathKindV1::Direct,
        relay_node: None,
        endpoint: PeerEndpointV1::Ipv4 {
            address: [203, 0, 113, candidate],
            port: 18_443,
        },
        priority: 10,
        authorization: PolicyRefV1 {
            policy_id: PolicyId(id(candidate + 20)),
            generation: 1,
            content_hash: [candidate + 21; 32],
        },
    }
}

fn publication_input() -> RoutePublicationInput {
    let local_attachment = AttachmentId(id(4));
    let remote_attachment = AttachmentId(id(8));
    let local_site = SiteId(id(5));
    let remote_site = SiteId(id(9));
    let local_path = direct_peer(remote_site, remote_attachment, 30);
    let remote_path = direct_peer(local_site, local_attachment, 31);
    let projection = |publication_id, attachment_id, path, projection_id| DeviceProjectionInput {
        publication_id: uuid(publication_id),
        attachment_id,
        projection_id: PolicyId(id(projection_id)),
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
        max_inner_mtu: 1300,
        resources: resources(),
    };
    RoutePublicationInput {
        publication_id: uuid(40),
        audit_event_id: uuid(41),
        actor_id: "route-worker".into(),
        tenant_id: TenantId(id(1)),
        segment_id: SegmentId(id(2)),
        generation: 1,
        previous_hash: [0; 32],
        segment_overlay_prefix: prefix([100, 64, 0, 0], 24),
        attachments: vec![
            SegmentAttachmentV1 {
                attachment_id: local_attachment,
                site_id: Some(local_site),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId(id(6)),
                    device_key_id: DeviceKeyId(id(7)),
                },
                overlay_router_ipv4: [100, 64, 0, 1],
                local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
                state: AttachmentState::Active,
                epoch_floor: 7,
            },
            SegmentAttachmentV1 {
                attachment_id: remote_attachment,
                site_id: Some(remote_site),
                principal: AttachmentPrincipalV1::Device {
                    device_id: DeviceId(id(10)),
                    device_key_id: DeviceKeyId(id(11)),
                },
                overlay_router_ipv4: [100, 64, 0, 2],
                local_prefixes: vec![prefix([10, 2, 0, 0], 16)],
                state: AttachmentState::Active,
                epoch_floor: 3,
            },
        ],
        not_before: 100,
        expires_at: 200,
        stale_until: 250,
        projections: vec![
            projection(50, local_attachment, local_path, 15),
            projection(51, remote_attachment, remote_path, 16),
        ],
    }
}

struct InteropFixture {
    snapshot: VerifiedSegmentSnapshot,
    projection: VerifiedSiteProjection,
    grant: AccessGrantPayloadV1,
    device: AuthenticatedDevice,
    peer: DirectPeerContext,
    open: OpenIpTunnel,
}

fn fixture() -> InteropFixture {
    let route_key = SigningKey::from_bytes(&[42; 32]);
    let built = build_route_publication(
        &publication_input(),
        &RouteSigner::new(ROUTE_KEY_ID, route_key.clone()),
    )
    .unwrap();
    let trust =
        RouteTrustStore::new([(ROUTE_KEY_ID.as_bytes().to_vec(), route_key.verifying_key())])
            .unwrap();
    let snapshot = VerifiedSegmentSnapshot::verify(&built.segment.envelope, &trust).unwrap();
    let projection =
        VerifiedSiteProjection::verify(&built.projections[0].sealed.envelope, &trust).unwrap();
    VerifiedControl::new(snapshot.clone(), projection.clone()).unwrap();
    let request = GrantRequest {
        tenant_id: uuid(1),
        device_id: uuid(6),
        device_key_id: uuid(7),
        node_pool_id: uuid(3),
        service_class: CloudServiceClass::Private,
        service_permission: "private.tun.connect".into(),
    };
    let material = PrivateGrantMaterial {
        organization_id: uuid(20),
        subscription_id: uuid(21),
        device_key_id: uuid(7),
        device_public_key: [22; 32],
        assurance_level: 2,
        route_policy: Some(RoutePolicyBinding {
            tenant_id: uuid(1),
            segment_id: uuid(2),
            attachment_id: uuid(4),
            site_id: uuid(5),
            device_id: uuid(6),
            device_key_id: uuid(7),
            node_pool_id: uuid(3),
            projection_id: uuid(15),
            projection_generation: projection.generation(),
            projection_content_hash: projection.content_hash(),
            segment_generation: snapshot.generation(),
            segment_content_hash: snapshot.content_hash(),
        }),
        snapshot: AuthorizationSnapshot {
            tenant_id: uuid(1),
            authorization_generation: 1,
            device: SnapshotDevice {
                id: uuid(6),
                tenant_id: uuid(1),
                status: DeviceStatus::Active,
            },
            subscription_status: SnapshotStatus::Active,
            entitlement: EntitlementSnapshot {
                id: uuid(23),
                tenant_id: uuid(1),
                node_pool_id: uuid(3),
                service_class: CloudServiceClass::Private,
                service_permission: "private.tun.connect".into(),
                status: SnapshotStatus::Active,
                generation: 1,
            },
            policy_generation: 1,
            revocation_generation: 1,
        },
        quota: GrantQuota {
            allowed_features: FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
            max_outer_connections_per_node: 2,
            max_outer_connections_per_pool: 4,
            max_active_sessions_per_connection: 128,
            max_udp_flows_per_connection: 256,
            max_pending_opens: 32,
            max_speculative_streams: 8,
            max_datagram_record: 1400,
            upload_rate_bps: 10_000_000,
            download_rate_bps: 10_000_000,
        },
    };
    let issued = prepare_private_grant_with_id(
        &GrantSigner::new("grant-key-1", SigningKey::from_bytes(&[43; 32])),
        &IssuerConfig {
            issuer_id: uuid(24),
            environment_id: uuid(25),
        },
        uuid(26),
        "interop-grant-1",
        &request,
        &material,
        90,
    )
    .unwrap();
    let grant = AccessGrantPayloadV1::decode(&issued.issued.envelope().payload).unwrap();
    let site_projection = projection.policy_ref();
    let segment_content_hash = snapshot.content_hash();
    InteropFixture {
        snapshot,
        projection,
        grant,
        device: AuthenticatedDevice {
            tenant_id: TenantId(id(1)),
            device_id: DeviceId(id(6)),
            device_key_id: DeviceKeyId(id(7)),
            node_pool_id: NodePoolId(id(3)),
            service_class: ServiceClass::CustomerPrivate,
        },
        peer: DirectPeerContext {
            site_id: SiteId(id(9)),
            attachment_id: AttachmentId(id(8)),
        },
        open: OpenIpTunnel {
            tunnel_id: 30,
            attachment_id: AttachmentId(id(4)),
            attachment_epoch: 7,
            site_id: SiteId(id(5)),
            segment_id: SegmentId(id(2)),
            site_projection,
            segment_generation: 1,
            segment_content_hash,
            requested_inner_mtu: 1200,
            packet_format_version: IP_PACKET_FORMAT_V1,
        },
    }
}

fn authorize(value: &InteropFixture, now: u64) -> Result<(), ControlError> {
    authorize_ip_tunnel(AuthorizationInput {
        snapshot: &value.snapshot,
        projection: &value.projection,
        grant: &value.grant,
        device: &value.device,
        peer: TunnelPeerContext::Direct(&value.peer),
        open: &value.open,
        negotiated_features: FeatureSet::from_bits(
            FeatureSet::CLOUD_GRANT_V1 | FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
        ),
        now,
        tunnel_use: TunnelUse::New,
        local_cidr_overrides: &[],
    })
    .map(|_| ())
}

#[test]
fn direct_peer_route_and_tun_grant_authorize_in_core() {
    assert_eq!(authorize(&fixture(), NOW), Ok(()));
}

#[test]
fn core_rejects_cross_boundary_and_unsigned_cidr_inputs() {
    let mut value = fixture();
    value.device.device_key_id = DeviceKeyId(id(99));
    assert_eq!(authorize(&value, NOW), Err(ControlError::PrincipalMismatch));

    let mut value = fixture();
    value.peer.attachment_id = AttachmentId(id(99));
    assert_eq!(authorize(&value, NOW), Err(ControlError::PeerNotAllowed));

    let mut value = fixture();
    value.open.segment_content_hash[0] ^= 1;
    assert_eq!(
        authorize(&value, NOW),
        Err(ControlError::TunnelBindingMismatch)
    );

    let mut value = fixture();
    value.grant.route_policy.as_mut().unwrap().content_hash[0] ^= 1;
    assert_eq!(authorize(&value, NOW), Err(ControlError::PolicyMismatch));

    let mut value = fixture();
    value.open.segment_content_hash = value.snapshot.content_hash();
    let result = candy_tun::control::authorize_ip_tunnel(AuthorizationInput {
        snapshot: &value.snapshot,
        projection: &value.projection,
        grant: &value.grant,
        device: &value.device,
        peer: TunnelPeerContext::Direct(&value.peer),
        open: &value.open,
        negotiated_features: FeatureSet::from_bits(
            FeatureSet::CLOUD_GRANT_V1 | FeatureSet::DATAGRAM | FeatureSet::IP_PACKET_TUNNEL_V1,
        ),
        now: NOW,
        tunnel_use: TunnelUse::New,
        local_cidr_overrides: &[prefix([10, 9, 0, 0], 16)],
    })
    .map(|_| ());
    assert_eq!(result, Err(ControlError::UnsignedCidrOverride));
}
