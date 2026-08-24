-- Migration 0025 temporarily reconstructed path catalogs from mutable control
-- state for historical projections. Those inferred rows cannot prove what a
-- node actually received. Remove them and republish every active Segment so
-- new projections receive an exact catalog in the publication transaction.
DELETE FROM runtime_projection_path_catalog;

CREATE TEMPORARY TABLE runtime_exact_path_catalog_refresh_segments (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (tenant_id, segment_id)
) ENGINE=InnoDB;

INSERT INTO runtime_exact_path_catalog_refresh_segments (tenant_id, segment_id, desired_revision)
SELECT head.tenant_id, head.segment_id, head.desired_revision + 1
FROM segment_generation_heads head
JOIN segments segment
  ON segment.tenant_id = head.tenant_id
 AND segment.id = head.segment_id
 AND segment.state = 'ACTIVE';

UPDATE segment_generation_heads head
JOIN runtime_exact_path_catalog_refresh_segments refresh
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
        'candy/runtime-exact-path-catalog-v1/',
        HEX(refresh.tenant_id),
        '/',
        HEX(refresh.segment_id),
        '/',
        refresh.desired_revision
    ), 256))
FROM runtime_exact_path_catalog_refresh_segments refresh;

DROP TEMPORARY TABLE runtime_exact_path_catalog_refresh_segments;
