use cloud_db::sdwan::{
    AttachmentPrincipalWrite, AttachmentState, Ipv4Prefix, SdwanError, SdwanTopologyWrite,
    SegmentAttachmentWrite, SitePrefixWrite,
};
use uuid::Uuid;

fn prefix(network: [u8; 4], prefix_len: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(network, prefix_len).unwrap()
}

fn topology() -> SdwanTopologyWrite {
    let tenant_id = Uuid::new_v4();
    let segment_id = Uuid::new_v4();
    let site_a = Uuid::new_v4();
    let site_b = Uuid::new_v4();
    SdwanTopologyWrite {
        tenant_id,
        segment_id,
        site_prefixes: vec![
            SitePrefixWrite {
                id: Uuid::new_v4(),
                tenant_id,
                site_id: site_a,
                prefix: prefix([10, 1, 0, 0], 16),
            },
            SitePrefixWrite {
                id: Uuid::new_v4(),
                tenant_id,
                site_id: site_b,
                prefix: prefix([10, 2, 0, 0], 16),
            },
        ],
        attachments: vec![
            SegmentAttachmentWrite {
                id: Uuid::new_v4(),
                tenant_id,
                segment_id,
                site_id: Some(site_a),
                principal: AttachmentPrincipalWrite::Device {
                    device_id: Uuid::new_v4(),
                    device_key_id: Uuid::new_v4(),
                },
                overlay_router_ipv4: [100, 64, 0, 1],
                local_prefixes: vec![prefix([10, 1, 0, 0], 16)],
                state: AttachmentState::Active,
                epoch_floor: 1,
            },
            SegmentAttachmentWrite {
                id: Uuid::new_v4(),
                tenant_id,
                segment_id,
                site_id: None,
                principal: AttachmentPrincipalWrite::Node {
                    node_id: Uuid::new_v4(),
                    node_key_id: Uuid::new_v4(),
                    node_pool_id: Uuid::new_v4(),
                },
                overlay_router_ipv4: [100, 64, 0, 2],
                local_prefixes: vec![],
                state: AttachmentState::Active,
                epoch_floor: 1,
            },
        ],
    }
}

#[test]
fn topology_validation_accepts_tenant_scoped_device_and_node_attachments() {
    assert!(topology().validate().is_ok());
}

#[test]
fn ipv4_prefix_rejects_default_and_noncanonical_networks() {
    assert_eq!(
        Ipv4Prefix::new([0, 0, 0, 0], 0).unwrap_err(),
        SdwanError::InvalidPrefix
    );
    assert_eq!(
        Ipv4Prefix::new([10, 1, 0, 1], 24).unwrap_err(),
        SdwanError::InvalidPrefix
    );
}

#[test]
fn topology_rejects_cross_tenant_overlap_and_duplicate_router_addresses() {
    let mut value = topology();
    value.site_prefixes[1].tenant_id = Uuid::new_v4();
    assert_eq!(value.validate().unwrap_err(), SdwanError::ScopeMismatch);

    let mut value = topology();
    value.site_prefixes[1].prefix = prefix([10, 1, 128, 0], 17);
    assert_eq!(value.validate().unwrap_err(), SdwanError::OverlappingPrefix);

    let mut value = topology();
    value.attachments[1].overlay_router_ipv4 = value.attachments[0].overlay_router_ipv4;
    assert_eq!(
        value.validate().unwrap_err(),
        SdwanError::DuplicateRouterAddress
    );
}

#[test]
fn topology_rejects_device_without_site_and_node_with_site_or_prefixes() {
    let mut value = topology();
    value.attachments[0].site_id = None;
    assert_eq!(value.validate().unwrap_err(), SdwanError::PrincipalMismatch);

    let mut value = topology();
    value.attachments[1].site_id = value.attachments[0].site_id;
    assert_eq!(value.validate().unwrap_err(), SdwanError::PrincipalMismatch);

    let mut value = topology();
    value.attachments[1].local_prefixes = vec![prefix([10, 9, 0, 0], 16)];
    assert_eq!(value.validate().unwrap_err(), SdwanError::PrincipalMismatch);
}

#[test]
fn topology_rejects_nil_principal_and_pool_ids_before_database_access() {
    let mut value = topology();
    value.attachments[1].principal = AttachmentPrincipalWrite::Node {
        node_id: Uuid::new_v4(),
        node_key_id: Uuid::new_v4(),
        node_pool_id: Uuid::nil(),
    };
    assert_eq!(value.validate().unwrap_err(), SdwanError::InvalidScope);
}
