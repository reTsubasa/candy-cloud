-- Route publication now includes every path between participating attachments.
-- Republish active Segments so runtimes stop receiving the incomplete peer
-- projection catalogs produced by older workers.
CREATE TEMPORARY TABLE complete_peer_catalog_refresh_segments (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (tenant_id, segment_id)
) ENGINE=InnoDB;

INSERT INTO complete_peer_catalog_refresh_segments (tenant_id, segment_id, desired_revision)
SELECT head.tenant_id, head.segment_id, head.desired_revision + 1
FROM segment_generation_heads head
JOIN segments segment
  ON segment.tenant_id = head.tenant_id
 AND segment.id = head.segment_id
 AND segment.state = 'ACTIVE';

UPDATE segment_generation_heads head
JOIN complete_peer_catalog_refresh_segments refresh
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
        'candy/complete-peer-catalog-v1/',
        HEX(refresh.tenant_id),
        '/',
        HEX(refresh.segment_id),
        '/',
        refresh.desired_revision
    ), 256))
FROM complete_peer_catalog_refresh_segments refresh;

DROP TEMPORARY TABLE complete_peer_catalog_refresh_segments;
