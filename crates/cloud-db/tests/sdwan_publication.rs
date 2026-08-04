use cloud_db::sdwan::{
    ExpansionObjectKind, ExpansionObjectPublicationWrite, PublicationOutcome, SdwanError,
    SdwanRepository, SegmentPublicationWrite, SignedObjectWrite, SiteProjectionPublicationWrite,
};
use uuid::Uuid;

fn signed(byte: u8) -> SignedObjectWrite {
    SignedObjectWrite {
        content_hash: [byte; 32],
        signed_envelope: vec![byte; 96],
    }
}

fn publication(tenant_id: Uuid, segment_id: Uuid) -> SegmentPublicationWrite {
    let snapshot = signed(7);
    SegmentPublicationWrite {
        publication_id: Uuid::new_v4(),
        tenant_id,
        segment_id,
        expected_previous_generation: 0,
        expected_previous_hash: [0; 32],
        generation: 1,
        snapshot: snapshot.clone(),
        projections: vec![SiteProjectionPublicationWrite {
            publication_id: Uuid::new_v4(),
            projection_id: Uuid::new_v4(),
            tenant_id,
            segment_id,
            site_id: Uuid::new_v4(),
            attachment_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            device_key_id: Uuid::new_v4(),
            segment_generation: 1,
            segment_content_hash: snapshot.content_hash,
            projection_generation: 1,
            previous_hash: [0; 32],
            object: signed(8),
        }],
        expansions: Vec::new(),
        audit_event_id: Uuid::new_v4(),
        actor_id: "route-worker".into(),
    }
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
    let attachment_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
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

    let repository = SdwanRepository::new(pool.clone());
    let mut write = publication(tenant_id, segment_id);
    write.projections[0].site_id = site_id;
    write.projections[0].attachment_id = attachment_id;
    write.projections[0].device_id = device_id;
    write.projections[0].device_key_id = device_key_id;
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
    let expansion_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM segment_expansion_publications WHERE segment_publication_id = ?",
    )
    .bind(write.publication_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(expansion_count, 1);

    let mut divergent = write.clone();
    divergent.expansions[0].object.signed_envelope.push(1);
    assert!(matches!(
        repository.publish(&divergent).await,
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
