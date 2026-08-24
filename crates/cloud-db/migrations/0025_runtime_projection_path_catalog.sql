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

-- Historical signed projections cannot be reconstructed from mutable current
-- control state. They intentionally remain uncataloged: Runtime accepts their
-- aggregate telemetry but discards unverifiable per-path details until an
-- exact catalog is transactionally written by a fresh signed publication.
-- Force that publication while the old committed projection remains valid
-- throughout normal rolling activation.
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
