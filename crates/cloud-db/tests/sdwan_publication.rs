use cloud_control::{
    AttachmentV1, ControlResourceV1, Ipv4PrefixV1, NodePlatformV1, NodeV1, PrefixSourceV1,
    PrefixV1, ResourceMetadataV1, ResourceSpecV1, ResourceState, SegmentV1, SiteKindV1, SiteV1,
    CONTROL_SCHEMA_V1,
};
use cloud_db::sdwan::{
    ExpansionObjectKind, ExpansionObjectPublicationWrite, PublicationOutcome,
    RuntimeConfigurationActivationPhase, RuntimeConfigurationApplyState, RuntimeConfigurationError,
    RuntimeConfigurationLookup, RuntimeConfigurationState, RuntimeConfigurationStatusWrite,
    RuntimeLifecycle, RuntimePathKind, RuntimePathTelemetryWrite,
    RuntimeProjectionPathCatalogWrite, RuntimeTelemetryWrite, SdwanError, SdwanRepository,
    SegmentPublicationWrite, SignedObjectWrite, SiteProjectionPublicationWrite,
};
use sqlx::Row;
use std::net::Ipv4Addr;
use uuid::Uuid;

fn signed(byte: u8) -> SignedObjectWrite {
    SignedObjectWrite {
        content_hash: [byte; 32],
        signed_envelope: vec![byte; 96],
    }
}

fn publication(tenant_id: Uuid, segment_id: Uuid) -> SegmentPublicationWrite {
    let snapshot = signed(7);
    let attachment_id = Uuid::new_v4();
    SegmentPublicationWrite {
        publication_id: Uuid::new_v4(),
        tenant_id,
        segment_id,
        expected_previous_generation: 0,
        expected_previous_hash: [0; 32],
        generation: 1,
        expires_at: 3_600,
        stale_until: 7_200,
        snapshot: snapshot.clone(),
        projections: vec![SiteProjectionPublicationWrite {
            publication_id: Uuid::new_v4(),
            projection_id: Uuid::new_v4(),
            tenant_id,
            segment_id,
            site_id: Uuid::new_v4(),
            attachment_id,
            device_id: Uuid::new_v4(),
            device_key_id: Uuid::new_v4(),
            segment_generation: 1,
            segment_content_hash: snapshot.content_hash,
            projection_generation: 1,
            previous_hash: [0; 32],
            object: signed(8),
            transport_nodes: vec![(Uuid::new_v4(), Uuid::new_v4())],
            runtime_paths: vec![RuntimeProjectionPathCatalogWrite {
                candidate_id: Uuid::new_v4(),
                peer_attachment_id: Uuid::new_v4(),
                path_kind: RuntimePathKind::Direct,
            }],
        }],
        expansions: Vec::new(),
        audit_event_id: Uuid::new_v4(),
        actor_id: "route-worker".into(),
    }
}

#[tokio::test]
async fn tunnel_host_catalog_contains_remote_route_owners_and_excludes_local_projection() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let segment_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("catalog-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("catalog-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience) VALUES (?, ?, 'PRIVATE', ?, 'private')")
        .bind(node_pool_id)
        .bind(tenant_id)
        .bind(format!("catalog-pool-{node_pool_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len) VALUES (?, ?, ?, ?, ?, 24)")
        .bind(segment_id)
        .bind(tenant_id)
        .bind(format!("catalog-segment-{segment_id}"))
        .bind(node_pool_id)
        .bind([100_u8, 64, 0, 0].as_slice())
        .execute(&pool)
        .await
        .unwrap();

    struct SiteFixture {
        site_id: Uuid,
        attachment_id: Uuid,
        device_id: Uuid,
        device_key_id: Uuid,
        node_id: Uuid,
    }
    let sites = (0..3)
        .map(|_| SiteFixture {
            site_id: Uuid::new_v4(),
            attachment_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_key_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
        })
        .collect::<Vec<_>>();
    for (index, site) in sites.iter().enumerate() {
        sqlx::query("INSERT INTO sites (id, tenant_id, name) VALUES (?, ?, ?)")
            .bind(site.site_id)
            .bind(tenant_id)
            .bind(format!("catalog-site-{}", site.site_id))
            .execute(&pool)
            .await
            .unwrap();
        if index != 0 {
            sqlx::query("INSERT INTO site_prefixes (id, tenant_id, site_id, network, prefix_len, state) VALUES (?, ?, ?, ?, 24, 'ACTIVE')")
                .bind(Uuid::new_v4())
                .bind(tenant_id)
                .bind(site.site_id)
                .bind([10_u8, u8::try_from(index).unwrap(), 0, 0].as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
            .bind(site.device_id)
            .bind(tenant_id)
            .bind(Uuid::new_v4().to_string())
            .bind(format!("catalog-device-{}", site.device_id))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
            .bind(site.device_key_id)
            .bind(tenant_id)
            .bind(site.device_id)
            .bind(format!("catalog-key-{}", site.device_key_id))
            .bind([u8::try_from(index + 1).unwrap(); 32].as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO nodes (id, tenant_id, device_id, device_key_id, node_pool_id, node_id, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')")
            .bind(site.node_id)
            .bind(tenant_id)
            .bind(site.device_id)
            .bind(site.device_key_id)
            .bind(node_pool_id)
            .bind(format!("catalog-node-{}", site.node_id))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO segment_attachments (id, tenant_id, segment_id, site_id, principal_kind, device_id, device_key_id, overlay_router_ipv4, state, epoch_floor) VALUES (?, ?, ?, ?, 'DEVICE', ?, ?, ?, 'ACTIVE', 1)")
            .bind(site.attachment_id)
            .bind(tenant_id)
            .bind(segment_id)
            .bind(site.site_id)
            .bind(site.device_id)
            .bind(site.device_key_id)
            .bind([100_u8, 64, 0, u8::try_from(index + 1).unwrap()].as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }

    let local = &sites[0];
    let mut write = publication(tenant_id, segment_id);
    write.expires_at = 4_102_441_200;
    write.stale_until = 4_102_444_800;
    write.projections = sites
        .iter()
        .enumerate()
        .map(|(index, site)| SiteProjectionPublicationWrite {
            publication_id: Uuid::new_v4(),
            projection_id: site.attachment_id,
            tenant_id,
            segment_id,
            site_id: site.site_id,
            attachment_id: site.attachment_id,
            device_id: site.device_id,
            device_key_id: site.device_key_id,
            segment_generation: write.generation,
            segment_content_hash: write.snapshot.content_hash,
            projection_generation: 1,
            previous_hash: [0; 32],
            object: signed(u8::try_from(index + 20).unwrap()),
            transport_nodes: vec![(local.node_id, local.device_key_id)],
            runtime_paths: sites
                .iter()
                .filter(|peer| peer.attachment_id != site.attachment_id)
                .map(|peer| RuntimeProjectionPathCatalogWrite {
                    candidate_id: Uuid::new_v4(),
                    peer_attachment_id: peer.attachment_id,
                    path_kind: RuntimePathKind::Direct,
                })
                .collect(),
        })
        .collect();
    let local_projection_envelope = write.projections[0].object.signed_envelope.clone();
    assert_eq!(
        SdwanRepository::new(pool.clone())
            .publish(&write)
            .await
            .unwrap(),
        PublicationOutcome::Published
    );

    let repository = SdwanRepository::new(pool.clone());
    let RuntimeConfigurationState::Current(configuration) = repository
        .current_runtime_configuration(&RuntimeConfigurationLookup {
            tenant_id,
            device_id: local.device_id,
            device_key_id: local.device_key_id,
        })
        .await
        .unwrap()
    else {
        panic!("expected tunnel-host Runtime configuration");
    };
    assert_eq!(
        configuration.signed_projection_envelope,
        local_projection_envelope
    );
    let catalog_ids = configuration
        .peer_projection_catalog
        .iter()
        .map(|projection| projection.projection_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        catalog_ids,
        std::collections::HashSet::from([sites[1].attachment_id, sites[2].attachment_id,])
    );
    assert!(!catalog_ids.contains(&local.attachment_id));

    let second_lookup = RuntimeConfigurationLookup {
        tenant_id,
        device_id: sites[1].device_id,
        device_key_id: sites[1].device_key_id,
    };
    let RuntimeConfigurationState::Current(_) = repository
        .current_runtime_configuration(&second_lookup)
        .await
        .unwrap()
    else {
        panic!("initial generation must bootstrap all members without a rollout deadlock");
    };
}

fn control_resource(
    tenant_id: Uuid,
    id: Uuid,
    state: ResourceState,
    resource: ResourceSpecV1,
) -> ControlResourceV1 {
    ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: 1,
            state,
        },
        resource,
    }
}

#[tokio::test]
async fn control_snapshot_materializes_empty_route_contract_idempotently() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let control_node_id = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let segment_id = Uuid::new_v4();
    let attachment_id = Uuid::new_v4();
    let prefix_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("materialize-org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("materialize-tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, 'materialize-device', 'ACTIVE')")
        .bind(device_id)
        .bind(tenant_id)
        .bind(Uuid::new_v4().to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(device_key_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(format!("materialize-key-{device_key_id}"))
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let mut resources = vec![
        control_resource(
            tenant_id,
            site_id,
            ResourceState::Active,
            ResourceSpecV1::Site(SiteV1 {
                name: "branch-a".into(),
                kind: SiteKindV1::Edge,
            }),
        ),
        control_resource(
            tenant_id,
            segment_id,
            ResourceState::Active,
            ResourceSpecV1::Segment(SegmentV1 {
                name: "production".into(),
                overlay_prefix: Ipv4PrefixV1 {
                    network: Ipv4Addr::new(100, 64, 0, 0),
                    prefix_len: 24,
                },
            }),
        ),
        control_resource(
            tenant_id,
            control_node_id,
            ResourceState::Active,
            ResourceSpecV1::Node(NodeV1 {
                device_id,
                device_key_id,
                site_id,
                display_name: "branch-router".into(),
                platform: NodePlatformV1::Linux,
                architecture: "x86_64".into(),
            }),
        ),
        control_resource(
            tenant_id,
            attachment_id,
            ResourceState::Active,
            ResourceSpecV1::Attachment(AttachmentV1 {
                segment_id,
                site_id,
                node_id: control_node_id,
                overlay_router_ipv4: Ipv4Addr::new(100, 64, 0, 2),
                epoch_floor: 1,
            }),
        ),
        control_resource(
            tenant_id,
            prefix_id,
            ResourceState::Active,
            ResourceSpecV1::Prefix(PrefixV1 {
                segment_id,
                site_id,
                prefix: Ipv4PrefixV1 {
                    network: Ipv4Addr::new(10, 10, 0, 0),
                    prefix_len: 24,
                },
                source: PrefixSourceV1::Configured,
            }),
        ),
    ];
    let repository = SdwanRepository::new(pool.clone());
    repository
        .ensure_control_topology(tenant_id, segment_id, &resources)
        .await
        .unwrap();
    repository
        .ensure_control_topology(tenant_id, segment_id, &resources)
        .await
        .unwrap();
    assert_eq!(
        repository
            .segment_head(tenant_id, segment_id)
            .await
            .unwrap(),
        (0, [0; 32])
    );
    let materialized_nodes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(materialized_nodes, 1);
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM segment_attachments WHERE tenant_id = ? AND segment_id = ? AND state = 'ACTIVE'")
        .bind(tenant_id)
        .bind(segment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(active, 1);
    let prefix_state: String =
        sqlx::query_scalar("SELECT state FROM site_prefixes WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(prefix_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(prefix_state, "ACTIVE");

    resources[3].metadata.state = ResourceState::Disabled;
    repository
        .ensure_control_topology(tenant_id, segment_id, &resources)
        .await
        .unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state FROM segment_attachments WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(attachment_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "DISABLED");

    resources[3].metadata.state = ResourceState::Deleted;
    repository
        .ensure_control_topology(tenant_id, segment_id, &resources)
        .await
        .unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state FROM segment_attachments WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(attachment_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "REVOKED");

    let replacement_attachment_id = Uuid::new_v4();
    resources.remove(3);
    resources.push(control_resource(
        tenant_id,
        replacement_attachment_id,
        ResourceState::Active,
        ResourceSpecV1::Attachment(AttachmentV1 {
            segment_id,
            site_id,
            node_id: control_node_id,
            overlay_router_ipv4: Ipv4Addr::new(100, 64, 0, 2),
            epoch_floor: 1,
        }),
    ));
    repository
        .ensure_control_topology(tenant_id, segment_id, &resources)
        .await
        .unwrap();
    let rows = sqlx::query(
        "SELECT id, state FROM segment_attachments WHERE tenant_id = ? AND segment_id = ? ORDER BY id",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    let states = rows
        .into_iter()
        .map(|row| (row.get::<Uuid, _>("id"), row.get::<String, _>("state")))
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        states.get(&attachment_id).map(String::as_str),
        Some("REVOKED")
    );
    assert_eq!(
        states.get(&replacement_attachment_id).map(String::as_str),
        Some("ACTIVE")
    );
}

#[test]
fn publication_validation_requires_signed_complete_adjacent_generation() {
    let tenant_id = Uuid::new_v4();
    let segment_id = Uuid::new_v4();
    assert!(publication(tenant_id, segment_id).validate().is_ok());

    let mut unsigned = publication(tenant_id, segment_id);
    unsigned.snapshot.signed_envelope.clear();
    assert_eq!(unsigned.validate().unwrap_err(), SdwanError::UnsignedObject);

    let mut gap = publication(tenant_id, segment_id);
    gap.generation = 2;
    gap.projections[0].segment_generation = 2;
    assert_eq!(gap.validate().unwrap_err(), SdwanError::GenerationGap);

    let mut partial = publication(tenant_id, segment_id);
    partial.projections.clear();
    assert_eq!(
        partial.validate().unwrap_err(),
        SdwanError::MissingProjection
    );

    let mut duplicate_candidate = publication(tenant_id, segment_id);
    let duplicate_path = duplicate_candidate.projections[0].runtime_paths[0].clone();
    duplicate_candidate.projections[0]
        .runtime_paths
        .push(duplicate_path);
    assert_eq!(
        duplicate_candidate.validate().unwrap_err(),
        SdwanError::InvalidScope
    );

    let mut expanded = publication(tenant_id, segment_id);
    expanded.expansions.push(ExpansionObjectPublicationWrite {
        publication_id: Uuid::new_v4(),
        kind: ExpansionObjectKind::MeshMembership,
        policy_id: Uuid::new_v4(),
        tenant_id,
        segment_id,
        generation: 1,
        segment_generation: expanded.generation,
        segment_content_hash: expanded.snapshot.content_hash,
        site_id: Some(expanded.projections[0].site_id),
        attachment_id: Some(expanded.projections[0].attachment_id),
        object: signed(9),
    });
    assert!(expanded.validate().is_ok());
    expanded.expansions[0].attachment_id = None;
    assert_eq!(expanded.validate().unwrap_err(), SdwanError::InvalidScope);
}

#[tokio::test]
async fn publication_is_atomic_idempotent_and_rejects_divergent_replay() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let pool = cloud_db::connect(&url).await.unwrap();
    cloud_db::migrate(&pool).await.unwrap();
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let segment_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    let site_id = Uuid::new_v4();
    let site_prefix_id = Uuid::new_v4();
    let attachment_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let peer_attachment_id = Uuid::new_v4();
    let peer_device_id = Uuid::new_v4();
    let peer_device_key_id = Uuid::new_v4();
    let service_node_id = Uuid::new_v4();
    let peer_service_node_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
        .bind(organization_id)
        .bind(format!("org-{organization_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
        .bind(tenant_id)
        .bind(organization_id)
        .bind(format!("tenant-{tenant_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_pools (id, tenant_id, service_class, name, audience) VALUES (?, ?, 'PRIVATE', ?, ?)")
        .bind(node_pool_id)
        .bind(tenant_id)
        .bind(format!("pool-{node_pool_id}"))
        .bind("private")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(segment_id)
        .bind(tenant_id)
        .bind(format!("segment-{segment_id}"))
        .bind(node_pool_id)
        .bind([100_u8, 64, 0, 0].as_slice())
        .bind(24_u8)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO sites (id, tenant_id, name) VALUES (?, ?, ?)")
        .bind(site_id)
        .bind(tenant_id)
        .bind(format!("site-{site_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO site_prefixes (id, tenant_id, site_id, network, prefix_len, state) VALUES (?, ?, ?, ?, 24, 'ACTIVE')")
        .bind(site_prefix_id)
        .bind(tenant_id)
        .bind(site_id)
        .bind([10_u8, 42, 0, 0].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
        .bind(device_id)
        .bind(tenant_id)
        .bind(Uuid::new_v4().to_string())
        .bind(format!("device-{device_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(device_key_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(format!("key-{device_key_id}"))
        .bind([1_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO devices (id, tenant_id, device_id, display_name, status) VALUES (?, ?, ?, ?, 'ACTIVE')")
        .bind(peer_device_id)
        .bind(tenant_id)
        .bind(Uuid::new_v4().to_string())
        .bind(format!("device-{peer_device_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_keys (id, tenant_id, device_id, key_id, public_key, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(peer_device_key_id)
        .bind(tenant_id)
        .bind(peer_device_id)
        .bind(format!("key-{peer_device_key_id}"))
        .bind([2_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO nodes (id, tenant_id, device_id, device_key_id, node_pool_id, node_id, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(service_node_id)
        .bind(tenant_id)
        .bind(device_id)
        .bind(device_key_id)
        .bind(node_pool_id)
        .bind(format!("publication-node-{service_node_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO nodes (id, tenant_id, device_id, device_key_id, node_pool_id, node_id, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')")
        .bind(peer_service_node_id)
        .bind(tenant_id)
        .bind(peer_device_id)
        .bind(peer_device_key_id)
        .bind(node_pool_id)
        .bind(format!("publication-node-{peer_service_node_id}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_endpoints (id, node_id, endpoint, transport, server_name, transport_preset, status, region) VALUES (?, ?, ?, 'CANDY_QUIC_UDP', ?, 'CURRENT', 'ACTIVE', 'test')")
        .bind(Uuid::new_v4())
        .bind(service_node_id)
        .bind("198.51.100.10:443")
        .bind("test-service")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO node_endpoints (id, node_id, endpoint, transport, server_name, transport_preset, status, region) VALUES (?, ?, ?, 'CANDY_QUIC_UDP', ?, 'CURRENT', 'ACTIVE', 'test')")
        .bind(Uuid::new_v4())
        .bind(peer_service_node_id)
        .bind("198.51.100.11:443")
        .bind("test-peer")
        .execute(&pool)
        .await
        .unwrap();
    let runtime_lookup = RuntimeConfigurationLookup {
        tenant_id,
        device_id,
        device_key_id,
    };
    let repository = SdwanRepository::new(pool.clone());
    assert!(matches!(
        repository
            .current_runtime_configuration(&runtime_lookup)
            .await
            .unwrap(),
        RuntimeConfigurationState::Unassigned
    ));
    sqlx::query("INSERT INTO segment_attachments (id, tenant_id, segment_id, site_id, principal_kind, device_id, device_key_id, overlay_router_ipv4, state, epoch_floor) VALUES (?, ?, ?, ?, 'DEVICE', ?, ?, ?, 'ACTIVE', 1)")
        .bind(attachment_id)
        .bind(tenant_id)
        .bind(segment_id)
        .bind(site_id)
        .bind(device_id)
        .bind(device_key_id)
        .bind([100_u8, 64, 0, 1].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO segment_attachments (id, tenant_id, segment_id, site_id, principal_kind, device_id, device_key_id, overlay_router_ipv4, state, epoch_floor) VALUES (?, ?, ?, ?, 'DEVICE', ?, ?, ?, 'ACTIVE', 1)")
        .bind(peer_attachment_id)
        .bind(tenant_id)
        .bind(segment_id)
        .bind(site_id)
        .bind(peer_device_id)
        .bind(peer_device_key_id)
        .bind([100_u8, 64, 0, 2].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .current_runtime_configuration(&runtime_lookup)
            .await,
        Err(RuntimeConfigurationError::MissingCurrentProjection)
    ));
    let mut write = publication(tenant_id, segment_id);
    // Keep generation 1 in its signed validity and bounded rollover windows
    // while generation 2 is published so an inbound transport node can
    // authenticate lagging peers.
    write.expires_at = 4_102_441_200;
    write.stale_until = 4_102_444_800;
    write.projections[0].site_id = site_id;
    write.projections[0].attachment_id = attachment_id;
    write.projections[0].device_id = device_id;
    write.projections[0].device_key_id = device_key_id;
    write.projections[0].transport_nodes = vec![(service_node_id, device_key_id)];
    write.projections[0].runtime_paths[0].peer_attachment_id = peer_attachment_id;
    let mut peer_projection = write.projections[0].clone();
    peer_projection.publication_id = Uuid::new_v4();
    peer_projection.projection_id = peer_attachment_id;
    peer_projection.site_id = site_id;
    peer_projection.attachment_id = peer_attachment_id;
    peer_projection.device_id = peer_device_id;
    peer_projection.device_key_id = peer_device_key_id;
    peer_projection.object = signed(10);
    peer_projection.transport_nodes = vec![
        (service_node_id, device_key_id),
        (peer_service_node_id, peer_device_key_id),
    ];
    peer_projection.runtime_paths[0].candidate_id = Uuid::new_v4();
    peer_projection.runtime_paths[0].peer_attachment_id = attachment_id;
    write.projections.push(peer_projection);
    write.expansions.push(ExpansionObjectPublicationWrite {
        publication_id: Uuid::new_v4(),
        kind: ExpansionObjectKind::MeshMembership,
        policy_id: Uuid::new_v4(),
        tenant_id,
        segment_id,
        generation: 1,
        segment_generation: write.generation,
        segment_content_hash: write.snapshot.content_hash,
        site_id: Some(site_id),
        attachment_id: Some(attachment_id),
        object: signed(9),
    });
    assert_eq!(
        repository.publish(&write).await.unwrap(),
        PublicationOutcome::Published
    );
    assert_eq!(
        repository.publish(&write).await.unwrap(),
        PublicationOutcome::Replayed
    );
    assert_eq!(
        repository
            .published_generation(tenant_id, segment_id, write.publication_id)
            .await
            .unwrap(),
        Some((1, [7_u8; 32]))
    );
    assert_eq!(
        repository
            .published_generation(tenant_id, segment_id, Uuid::new_v4())
            .await
            .unwrap(),
        None
    );
    let expansion_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM segment_expansion_publications WHERE segment_publication_id = ?",
    )
    .bind(write.publication_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(expansion_count, 1);

    assert_eq!(
        repository
            .current_head(tenant_id, segment_id)
            .await
            .unwrap(),
        (1, [7_u8; 32])
    );
    assert_eq!(
        repository
            .projection_head(tenant_id, segment_id, attachment_id)
            .await
            .unwrap(),
        Some((1, [8_u8; 32]))
    );
    let RuntimeConfigurationState::Current(first_runtime) = repository
        .current_runtime_configuration(&runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected current Runtime configuration");
    };
    assert_eq!(
        first_runtime.projection_publication_id,
        write.projections[0].publication_id
    );
    assert_eq!(
        first_runtime.signed_projection_envelope,
        write.projections[0].object.signed_envelope
    );
    assert_eq!(
        first_runtime.signed_segment_envelope,
        write.snapshot.signed_envelope
    );
    assert_eq!(
        first_runtime.activation_phase,
        RuntimeConfigurationActivationPhase::Prepare
    );
    let peer_runtime_lookup = RuntimeConfigurationLookup {
        tenant_id,
        device_id: peer_device_id,
        device_key_id: peer_device_key_id,
    };
    let RuntimeConfigurationState::Current(first_peer_runtime) = repository
        .current_runtime_configuration(&peer_runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected current Peer Runtime configuration");
    };
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: first_runtime.projection_publication_id,
            projection_content_hash: first_runtime.projection_content_hash,
            envelope_sha256: first_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Prepared,
            error_code: None,
        })
        .await
        .unwrap();
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: peer_runtime_lookup.clone(),
            projection_publication_id: first_peer_runtime.projection_publication_id,
            projection_content_hash: first_peer_runtime.projection_content_hash,
            envelope_sha256: first_peer_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Prepared,
            error_code: None,
        })
        .await
        .unwrap();
    for (lookup, prepared) in [
        (&runtime_lookup, &first_runtime),
        (&peer_runtime_lookup, &first_peer_runtime),
    ] {
        let RuntimeConfigurationState::Current(committing) = repository
            .current_runtime_configuration(lookup)
            .await
            .unwrap()
        else {
            panic!("expected committing Runtime configuration");
        };
        assert_eq!(
            committing.activation_phase,
            RuntimeConfigurationActivationPhase::Commit
        );
        repository
            .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
                lookup: (*lookup).clone(),
                projection_publication_id: prepared.projection_publication_id,
                projection_content_hash: prepared.projection_content_hash,
                envelope_sha256: prepared.envelope_sha256(),
                apply_state: RuntimeConfigurationApplyState::Active,
                error_code: None,
            })
            .await
            .unwrap();
    }
    let applied: String = sqlx::query_scalar(
        "SELECT apply_state FROM runtime_configuration_status WHERE tenant_id = ? AND device_id = ? AND device_key_id = ?",
    )
    .bind(tenant_id)
    .bind(device_id)
    .bind(device_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(applied, "ACTIVE");

    // A transient dataplane failure can happen after the rollout has already
    // completed. The Runtime must be able to report both the failure and its
    // recovery without the terminal rollout state rejecting the current
    // configuration status.
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: first_runtime.projection_publication_id,
            projection_content_hash: first_runtime.projection_content_hash,
            envelope_sha256: first_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Rejected,
            error_code: Some("transient_dataplane_failure".into()),
        })
        .await
        .unwrap();
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: first_runtime.projection_publication_id,
            projection_content_hash: first_runtime.projection_content_hash,
            envelope_sha256: first_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Active,
            error_code: None,
        })
        .await
        .unwrap();
    let recovered: (String, Option<String>) = sqlx::query_as(
        "SELECT apply_state, error_code FROM runtime_configuration_status WHERE tenant_id = ? AND device_id = ? AND device_key_id = ?",
    )
    .bind(tenant_id)
    .bind(device_id)
    .bind(device_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recovered, ("ACTIVE".into(), None));

    // Periodic reconciliation may acknowledge an unchanged, already-active
    // configuration. This is idempotent even after rollout completion.
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: first_runtime.projection_publication_id,
            projection_content_hash: first_runtime.projection_content_hash,
            envelope_sha256: first_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Active,
            error_code: None,
        })
        .await
        .unwrap();

    let mut second = write.clone();
    second.publication_id = Uuid::new_v4();
    second.audit_event_id = Uuid::new_v4();
    second.expected_previous_generation = 1;
    second.expected_previous_hash = [7_u8; 32];
    second.generation = 2;
    second.snapshot = signed(17);
    second.projections[0].publication_id = Uuid::new_v4();
    second.projections[0].segment_generation = 2;
    second.projections[0].segment_content_hash = second.snapshot.content_hash;
    second.projections[0].projection_generation = 2;
    second.projections[0].previous_hash = [8_u8; 32];
    second.projections[0].object = signed(18);
    second.projections[1].publication_id = Uuid::new_v4();
    second.projections[1].segment_generation = 2;
    second.projections[1].segment_content_hash = second.snapshot.content_hash;
    second.projections[1].projection_generation = 2;
    second.projections[1].previous_hash = [10_u8; 32];
    second.projections[1].object = signed(20);
    second.expansions[0].publication_id = Uuid::new_v4();
    second.expansions[0].generation = 2;
    second.expansions[0].segment_generation = 2;
    second.expansions[0].segment_content_hash = second.snapshot.content_hash;
    second.expansions[0].object = signed(19);
    assert_eq!(
        repository.publish(&second).await.unwrap(),
        PublicationOutcome::Published
    );
    assert_eq!(
        repository
            .current_head(tenant_id, segment_id)
            .await
            .unwrap(),
        (2, [17_u8; 32])
    );
    assert_eq!(
        repository
            .projection_head(tenant_id, segment_id, attachment_id)
            .await
            .unwrap(),
        Some((2, [18_u8; 32]))
    );
    let rollout: (u32, u32, String) = sqlx::query_as(
        "SELECT allowed_ordinal, member_count, state FROM runtime_configuration_rollouts WHERE tenant_id = ? AND segment_id = ? AND segment_generation = 2",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollout, (2, 2, "PREPARING".into()));
    let RuntimeConfigurationState::Current(second_runtime) = repository
        .current_runtime_configuration(&runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected generation 2 Runtime configuration");
    };
    assert_eq!(second_runtime.segment_generation, 2);
    assert_eq!(
        second_runtime.activation_phase,
        RuntimeConfigurationActivationPhase::Prepare
    );
    assert_eq!(second_runtime.compatibility_generations.len(), 1);
    let compatible = &second_runtime.compatibility_generations[0];
    assert_eq!(compatible.segment_generation, 1);
    assert_eq!(compatible.segment_content_hash, [7_u8; 32]);
    assert_eq!(
        compatible.signed_segment_envelope,
        write.snapshot.signed_envelope
    );
    assert_eq!(compatible.peer_projection_catalog.len(), 1);
    assert_eq!(
        compatible.peer_projection_catalog[0].projection_id,
        peer_attachment_id
    );
    assert_eq!(
        compatible.peer_projection_catalog[0].projection_generation,
        1
    );
    assert_eq!(
        compatible.peer_projection_catalog[0].projection_content_hash,
        [10_u8; 32]
    );
    let active_candidate = write.projections[0].runtime_paths[0].candidate_id;
    let telemetry = RuntimeTelemetryWrite {
        lookup: runtime_lookup.clone(),
        boot_id: Uuid::new_v4(),
        sequence: 1,
        lifecycle: RuntimeLifecycle::Active,
        configured_peers: 1,
        active_peers: 1,
        required_route_owners: 1,
        ready_route_owners: 1,
        fail_open_required: false,
        last_error_code: None,
        last_error_detail: None,
        rtt_ms: Some(40),
        jitter_ms: Some(2),
        packet_loss_ppm: Some(0),
        rx_bps: Some(1_000),
        tx_bps: Some(2_000),
        reconnects: Some(0),
        path_changes: Some(0),
        transport_mode: Some("stream_primary".into()),
        runtime_generation: Some(1),
        paths: vec![RuntimePathTelemetryWrite {
            peer_attachment_id,
            candidate_id: Some(active_candidate),
            path_kind: RuntimePathKind::Direct,
            transport: "quic_stream".into(),
            connection_epoch: 1,
            rtt_ms: Some(40),
            jitter_ms: Some(2),
            packet_loss_ppm: Some(0),
            rx_bps: Some(1_000),
            tx_bps: Some(2_000),
            reconnects: 0,
            path_changes: 0,
            transport_mode: Some("stream_primary".into()),
            route_generation: Some(1),
            congestion_state: Some("ready".into()),
            stream_count: Some(1),
            ready_streams: Some(1),
            queue_depth: Some(0),
            queue_limit: Some(256),
            last_ack_seq: Some(1),
            streams: Vec::new(),
        }],
        local_networks: None,
    };
    repository
        .record_runtime_telemetry(&telemetry)
        .await
        .unwrap();
    let mut forged = telemetry.clone();
    forged.sequence = 2;
    forged.paths[0].candidate_id = Some(Uuid::new_v4());
    assert!(matches!(
        repository.record_runtime_telemetry(&forged).await,
        Err(RuntimeConfigurationError::InvalidScope)
    ));
    sqlx::query("DELETE FROM runtime_projection_path_catalog WHERE projection_publication_id = ?")
        .bind(first_runtime.projection_publication_id)
        .execute(&pool)
        .await
        .unwrap();
    repository.record_runtime_telemetry(&forged).await.unwrap();
    let legacy_paths_json: String = sqlx::query_scalar(
        "SELECT CAST(paths_json AS CHAR) FROM runtime_telemetry_latest WHERE tenant_id = ? AND device_id = ? AND device_key_id = ?",
    )
    .bind(tenant_id)
    .bind(device_id)
    .bind(device_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(legacy_paths_json, "[]");
    let RuntimeConfigurationState::Current(peer_runtime_before_ack) = repository
        .current_runtime_configuration(&peer_runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected the peer to receive the prepared Runtime configuration");
    };
    assert_eq!(peer_runtime_before_ack.segment_generation, 2);
    assert_eq!(
        peer_runtime_before_ack.activation_phase,
        RuntimeConfigurationActivationPhase::Prepare
    );
    assert_eq!(
        peer_runtime_before_ack.projection_publication_id,
        second.projections[1].publication_id
    );
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: second_runtime.projection_publication_id,
            projection_content_hash: second_runtime.projection_content_hash,
            envelope_sha256: second_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Prepared,
            error_code: None,
        })
        .await
        .unwrap();
    let rollout_state: String = sqlx::query_scalar(
        "SELECT state FROM runtime_configuration_rollouts WHERE tenant_id = ? AND segment_id = ? AND segment_generation = 2",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollout_state, "PREPARING");
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: peer_runtime_lookup.clone(),
            projection_publication_id: peer_runtime_before_ack.projection_publication_id,
            projection_content_hash: peer_runtime_before_ack.projection_content_hash,
            envelope_sha256: peer_runtime_before_ack.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Prepared,
            error_code: None,
        })
        .await
        .unwrap();
    let rollout_state: String = sqlx::query_scalar(
        "SELECT state FROM runtime_configuration_rollouts WHERE tenant_id = ? AND segment_id = ? AND segment_generation = 2",
    )
    .bind(tenant_id)
    .bind(segment_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rollout_state, "COMMITTING");
    let RuntimeConfigurationState::Current(committing_runtime) = repository
        .current_runtime_configuration(&runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected committing Runtime configuration");
    };
    let RuntimeConfigurationState::Current(committing_peer_runtime) = repository
        .current_runtime_configuration(&peer_runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected committing Peer Runtime configuration");
    };
    assert_eq!(
        committing_runtime.activation_phase,
        RuntimeConfigurationActivationPhase::Commit
    );
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: runtime_lookup.clone(),
            projection_publication_id: committing_runtime.projection_publication_id,
            projection_content_hash: committing_runtime.projection_content_hash,
            envelope_sha256: committing_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Active,
            error_code: None,
        })
        .await
        .unwrap();
    repository
        .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
            lookup: peer_runtime_lookup.clone(),
            projection_publication_id: committing_peer_runtime.projection_publication_id,
            projection_content_hash: committing_peer_runtime.projection_content_hash,
            envelope_sha256: committing_peer_runtime.envelope_sha256(),
            apply_state: RuntimeConfigurationApplyState::Active,
            error_code: None,
        })
        .await
        .unwrap();
    forged.sequence = 3;
    assert!(matches!(
        repository.record_runtime_telemetry(&forged).await,
        Err(RuntimeConfigurationError::InvalidScope)
    ));
    let RuntimeConfigurationState::Current(peer_runtime) = repository
        .current_runtime_configuration(&peer_runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected peer generation 2 Runtime configuration");
    };
    assert!(peer_runtime.compatibility_generations.is_empty());
    sqlx::query("UPDATE segment_route_publications SET expires_at = 0 WHERE id = ?")
        .bind(write.publication_id)
        .execute(&pool)
        .await
        .unwrap();
    let RuntimeConfigurationState::Current(during_compatibility_window) = repository
        .current_runtime_configuration(&runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected current Runtime configuration during the stale compatibility window");
    };
    assert_eq!(
        during_compatibility_window.compatibility_generations.len(),
        1
    );
    sqlx::query("UPDATE segment_route_publications SET expires_at = ? WHERE id = ?")
        .bind(write.expires_at)
        .bind(write.publication_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .record_runtime_configuration_status(&RuntimeConfigurationStatusWrite {
                lookup: runtime_lookup.clone(),
                projection_publication_id: first_runtime.projection_publication_id,
                projection_content_hash: first_runtime.projection_content_hash,
                envelope_sha256: first_runtime.envelope_sha256(),
                apply_state: RuntimeConfigurationApplyState::Active,
                error_code: None,
            })
            .await,
        Err(RuntimeConfigurationError::StaleConfiguration)
    ));
    sqlx::query("UPDATE segment_route_publications SET stale_until = 0 WHERE id = ?")
        .bind(write.publication_id)
        .execute(&pool)
        .await
        .unwrap();
    let RuntimeConfigurationState::Current(after_stale_window) = repository
        .current_runtime_configuration(&runtime_lookup)
        .await
        .unwrap()
    else {
        panic!("expected current Runtime configuration after rollover expiry");
    };
    assert!(after_stale_window.compatibility_generations.is_empty());

    let mut gap = second.clone();
    gap.publication_id = Uuid::new_v4();
    gap.audit_event_id = Uuid::new_v4();
    gap.expected_previous_hash = [0x55_u8; 32];
    gap.generation = 3;
    gap.snapshot = signed(27);
    gap.projections[0].publication_id = Uuid::new_v4();
    gap.projections[0].segment_generation = 3;
    gap.projections[0].segment_content_hash = gap.snapshot.content_hash;
    gap.projections[0].projection_generation = 3;
    gap.projections[0].previous_hash = [18_u8; 32];
    gap.projections[0].object = signed(28);
    gap.expansions[0].publication_id = Uuid::new_v4();
    gap.expansions[0].generation = 3;
    gap.expansions[0].segment_generation = 3;
    gap.expansions[0].segment_content_hash = gap.snapshot.content_hash;
    gap.expansions[0].object = signed(29);
    assert!(matches!(
        repository.publish(&gap).await,
        Err(SdwanError::GenerationGap)
    ));
    assert_eq!(
        repository
            .current_head(tenant_id, segment_id)
            .await
            .unwrap(),
        (2, [17_u8; 32])
    );

    let mut projection_gap = second.clone();
    projection_gap.publication_id = Uuid::new_v4();
    projection_gap.audit_event_id = Uuid::new_v4();
    projection_gap.expected_previous_hash = [17_u8; 32];
    projection_gap.generation = 3;
    projection_gap.snapshot = signed(37);
    projection_gap.projections[0].publication_id = Uuid::new_v4();
    projection_gap.projections[0].segment_generation = 3;
    projection_gap.projections[0].segment_content_hash = projection_gap.snapshot.content_hash;
    projection_gap.projections[0].projection_generation = 3;
    projection_gap.projections[0].previous_hash = [0x44_u8; 32];
    projection_gap.projections[0].object = signed(38);
    projection_gap.expansions[0].publication_id = Uuid::new_v4();
    projection_gap.expansions[0].generation = 3;
    projection_gap.expansions[0].segment_generation = 3;
    projection_gap.expansions[0].segment_content_hash = projection_gap.snapshot.content_hash;
    projection_gap.expansions[0].object = signed(39);
    assert!(matches!(
        repository.publish(&projection_gap).await,
        Err(SdwanError::GenerationGap)
    ));

    let mut divergent = write.clone();
    divergent.expansions[0].object.signed_envelope.push(1);
    assert!(matches!(
        repository.publish(&divergent).await,
        Err(SdwanError::DivergentReplay)
    ));
    let mut divergent_catalog = write.clone();
    divergent_catalog.projections[0].runtime_paths[0].candidate_id = Uuid::new_v4();
    assert!(matches!(
        repository.publish(&divergent_catalog).await,
        Err(SdwanError::DivergentReplay)
    ));

    let second_segment_id = Uuid::new_v4();
    sqlx::query("INSERT INTO segments (id, tenant_id, name, hub_node_pool_id, overlay_network, overlay_prefix_len) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(second_segment_id)
        .bind(tenant_id)
        .bind(format!("segment-{second_segment_id}"))
        .bind(node_pool_id)
        .bind([100_u8, 65, 0, 0].as_slice())
        .bind(24_u8)
        .execute(&pool)
        .await
        .unwrap();
    let mut invalid = publication(tenant_id, second_segment_id);
    invalid.expansions.push(ExpansionObjectPublicationWrite {
        publication_id: Uuid::new_v4(),
        kind: ExpansionObjectKind::DynamicRouteSnapshot,
        policy_id: Uuid::new_v4(),
        tenant_id,
        segment_id: second_segment_id,
        generation: 1,
        segment_generation: invalid.generation,
        segment_content_hash: invalid.snapshot.content_hash,
        site_id: None,
        attachment_id: None,
        object: signed(10),
    });
    assert!(matches!(
        repository.publish(&invalid).await,
        Err(SdwanError::MissingProjection)
    ));
    let generation: u64 =
        sqlx::query_scalar("SELECT current_generation FROM segments WHERE id = ?")
            .bind(second_segment_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(generation, 0);
    let persisted: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM segment_route_publications WHERE id = ?")
            .bind(invalid.publication_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted, 0);
    let persisted_expansions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM segment_expansion_publications WHERE id = ?")
            .bind(invalid.expansions[0].publication_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(persisted_expansions, 0);
}
