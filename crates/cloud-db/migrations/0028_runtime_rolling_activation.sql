ALTER TABLE segment_route_publication_members
    ADD COLUMN rollout_ordinal INT UNSIGNED NOT NULL DEFAULT 1 AFTER attachment_id,
    ADD KEY idx_segment_publication_rollout (tenant_id, segment_publication_id, rollout_ordinal);

CREATE TABLE runtime_configuration_rollouts (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    segment_generation BIGINT UNSIGNED NOT NULL,
    allowed_ordinal INT UNSIGNED NOT NULL,
    member_count INT UNSIGNED NOT NULL,
    state ENUM('ACTIVE','BLOCKED','COMPLETE') NOT NULL,
    started_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, segment_id, segment_generation),
    CONSTRAINT fk_runtime_rollout_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_runtime_rollout_segment FOREIGN KEY (segment_id) REFERENCES segments(id),
    CHECK (allowed_ordinal > 0),
    CHECK (member_count > 0),
    CHECK (allowed_ordinal <= member_count)
) ENGINE=InnoDB;

-- Existing publications were already delivered concurrently. Mark their
-- current generations complete so this migration does not replay them.
INSERT INTO runtime_configuration_rollouts (
    tenant_id,
    segment_id,
    segment_generation,
    allowed_ordinal,
    member_count,
    state
)
SELECT
    publication.tenant_id,
    publication.segment_id,
    publication.generation,
    COUNT(*),
    COUNT(*),
    'COMPLETE'
FROM segment_route_publications publication
JOIN segments segment
  ON segment.tenant_id = publication.tenant_id
 AND segment.id = publication.segment_id
 AND segment.current_generation = publication.generation
JOIN segment_route_publication_members member
  ON member.tenant_id = publication.tenant_id
 AND member.segment_publication_id = publication.id
GROUP BY publication.tenant_id, publication.segment_id, publication.generation;
