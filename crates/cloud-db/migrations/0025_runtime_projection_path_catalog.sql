CREATE TABLE runtime_projection_path_catalog (
    tenant_id BINARY(16) NOT NULL,
    projection_publication_id BINARY(16) NOT NULL,
    candidate_id BINARY(16) NOT NULL,
    source_attachment_id BINARY(16) NOT NULL,
    destination_attachment_id BINARY(16) NOT NULL,
    path_kind ENUM('DIRECT','RELAY') NOT NULL,
    PRIMARY KEY (projection_publication_id, candidate_id),
    KEY idx_runtime_projection_path_lookup (
        tenant_id,
        projection_publication_id,
        source_attachment_id,
        destination_attachment_id,
        path_kind
    ),
    CONSTRAINT fk_runtime_projection_path_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_runtime_projection_path_publication
        FOREIGN KEY (projection_publication_id) REFERENCES site_route_projection_publications(id),
    CONSTRAINT fk_runtime_projection_path_source
        FOREIGN KEY (source_attachment_id) REFERENCES segment_attachments(id),
    CONSTRAINT fk_runtime_projection_path_destination
        FOREIGN KEY (destination_attachment_id) REFERENCES segment_attachments(id)
) ENGINE=InnoDB;

-- Existing nodes may still be running a committed publication when this
-- migration lands. Materialize every candidate that can be reconstructed from
-- the retained publication attachment and the active control/transport state;
-- all new publications write the exact immutable catalog transactionally.
INSERT IGNORE INTO runtime_projection_path_catalog (
    tenant_id,
    projection_publication_id,
    candidate_id,
    source_attachment_id,
    destination_attachment_id,
    path_kind
)
SELECT
    projection.tenant_id,
    projection.id,
    UNHEX(LEFT(SHA2(CONCAT(
        _binary 'candy/path-endpoint-candidate-v1',
        0x00,
        resource.id,
        endpoint.id
    ), 256), 32)),
    projection.attachment_id,
    UUID_TO_BIN(JSON_UNQUOTE(JSON_EXTRACT(resource.document_json, '$.resource.spec.destination_attachment_id'))),
    JSON_UNQUOTE(JSON_EXTRACT(resource.document_json, '$.resource.spec.kind'))
FROM site_route_projection_publications projection
JOIN sdwan_control_resources resource
    ON resource.tenant_id = projection.tenant_id
    AND resource.segment_id = projection.segment_id
    AND resource.resource_kind = 'PATH_CANDIDATE'
    AND resource.state = 'ACTIVE'
    AND UUID_TO_BIN(JSON_UNQUOTE(JSON_EXTRACT(resource.document_json, '$.resource.spec.source_attachment_id')))
        = projection.attachment_id
JOIN nodes transport_node
    ON transport_node.tenant_id = projection.tenant_id
    AND transport_node.node_id = JSON_UNQUOTE(JSON_EXTRACT(resource.document_json, '$.resource.spec.transport_node_id'))
    AND transport_node.status = 'ACTIVE'
JOIN node_endpoints endpoint
    ON endpoint.node_id = transport_node.id
    AND endpoint.transport = 'CANDY_QUIC_UDP'
    AND endpoint.status = 'ACTIVE';

-- Replace the best-effort compatibility backfill with an exact catalog from a
-- freshly signed publication. The old committed projection remains valid
-- while the normal rolling activation advances each active Segment.
CREATE TEMPORARY TABLE runtime_path_catalog_refresh_segments (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (tenant_id, segment_id)
) ENGINE=InnoDB;

INSERT INTO runtime_path_catalog_refresh_segments (tenant_id, segment_id, desired_revision)
SELECT head.tenant_id, head.segment_id, head.desired_revision + 1
FROM segment_generation_heads head
JOIN segments segment
  ON segment.tenant_id = head.tenant_id
 AND segment.id = head.segment_id
 AND segment.state = 'ACTIVE';

UPDATE segment_generation_heads head
JOIN runtime_path_catalog_refresh_segments refresh
  ON refresh.tenant_id = head.tenant_id
 AND refresh.segment_id = head.segment_id
SET head.desired_revision = refresh.desired_revision;

INSERT INTO segment_generation_jobs (
    id,
    tenant_id,
    segment_id,
    desired_revision,
    idempotency_hash
)
SELECT
    UUID_TO_BIN(UUID()),
    refresh.tenant_id,
    refresh.segment_id,
    refresh.desired_revision,
    UNHEX(SHA2(CONCAT(
        'candy/runtime-path-catalog-v1/',
        HEX(refresh.tenant_id),
        '/',
        HEX(refresh.segment_id),
        '/',
        refresh.desired_revision
    ), 256))
FROM runtime_path_catalog_refresh_segments refresh;

DROP TEMPORARY TABLE runtime_path_catalog_refresh_segments;
