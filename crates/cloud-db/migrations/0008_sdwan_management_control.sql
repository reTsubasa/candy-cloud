CREATE TABLE sdwan_control_resources (
    tenant_id BINARY(16) NOT NULL,
    resource_kind ENUM(
        'NODE',
        'SITE',
        'SEGMENT',
        'ATTACHMENT',
        'PREFIX',
        'PEER',
        'RELAY',
        'PATH_CANDIDATE',
        'EGRESS',
        'SERVICE_POLICY',
        'DNS_INTENT'
    ) NOT NULL,
    id BINARY(16) NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    state ENUM('ACTIVE','DISABLED','DELETED') NOT NULL,
    segment_id BINARY(16) NULL,
    document_hash BINARY(32) NOT NULL,
    document_json JSON NOT NULL,
    created_by VARCHAR(120) NOT NULL,
    updated_by VARCHAR(120) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, resource_kind, id),
    KEY idx_control_resources_segment (tenant_id, segment_id, resource_kind, state),
    KEY idx_control_resources_list (tenant_id, resource_kind, state, id),
    CONSTRAINT fk_control_resources_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CHECK (revision > 0),
    CHECK (JSON_EXTRACT(document_json, '$.metadata.schema_version') = 1),
    CHECK (JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.metadata.tenant_id')) = LOWER(BIN_TO_UUID(tenant_id, 0))),
    CHECK (JSON_UNQUOTE(JSON_EXTRACT(document_json, '$.metadata.id')) = LOWER(BIN_TO_UUID(id, 0)))
) ENGINE=InnoDB;

CREATE TABLE sdwan_control_resource_references (
    tenant_id BINARY(16) NOT NULL,
    source_kind ENUM('NODE','SITE','SEGMENT','ATTACHMENT','PREFIX','PEER','RELAY','PATH_CANDIDATE','EGRESS','SERVICE_POLICY','DNS_INTENT') NOT NULL,
    source_id BINARY(16) NOT NULL,
    target_kind ENUM('NODE','SITE','SEGMENT','ATTACHMENT','PREFIX','PEER','RELAY','PATH_CANDIDATE','EGRESS','SERVICE_POLICY','DNS_INTENT') NOT NULL,
    target_id BINARY(16) NOT NULL,
    PRIMARY KEY (tenant_id, source_kind, source_id, target_kind, target_id),
    KEY idx_control_resource_references_target (tenant_id, target_kind, target_id),
    CONSTRAINT fk_control_references_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_control_references_source FOREIGN KEY (tenant_id, source_kind, source_id)
        REFERENCES sdwan_control_resources(tenant_id, resource_kind, id),
    CONSTRAINT fk_control_references_target FOREIGN KEY (tenant_id, target_kind, target_id)
        REFERENCES sdwan_control_resources(tenant_id, resource_kind, id),
    CHECK (NOT (source_kind = target_kind AND source_id = target_id))
) ENGINE=InnoDB;

CREATE TABLE management_idempotency_records (
    tenant_id BINARY(16) NOT NULL,
    actor_id VARCHAR(120) NOT NULL,
    idempotency_key VARCHAR(160) NOT NULL,
    request_method VARCHAR(12) NOT NULL,
    request_path VARCHAR(500) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    resource_kind ENUM(
        'NODE',
        'SITE',
        'SEGMENT',
        'ATTACHMENT',
        'PREFIX',
        'PEER',
        'RELAY',
        'PATH_CANDIDATE',
        'EGRESS',
        'SERVICE_POLICY',
        'DNS_INTENT'
    ) NOT NULL,
    resource_id BINARY(16) NOT NULL,
    resource_revision BIGINT UNSIGNED NOT NULL,
    response_document_json JSON NOT NULL,
    response_status SMALLINT UNSIGNED NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    replay_until TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (tenant_id, actor_id, idempotency_key),
    KEY idx_management_idempotency_replay_until (replay_until),
    CONSTRAINT fk_management_idempotency_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CHECK (resource_revision > 0),
    CHECK (JSON_EXTRACT(response_document_json, '$.metadata.schema_version') = 1),
    CHECK (response_status BETWEEN 200 AND 299)
) ENGINE=InnoDB;

CREATE TABLE segment_generation_heads (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, segment_id),
    CONSTRAINT fk_generation_heads_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE segment_generation_jobs (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL,
    idempotency_hash BINARY(32) NOT NULL,
    state ENUM('PENDING','LEASED','RETRY','PUBLISHED','PERMANENT_FAILURE') NOT NULL DEFAULT 'PENDING',
    attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
    lease_owner VARCHAR(120) NULL,
    lease_until TIMESTAMP(6) NULL,
    next_attempt_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    published_generation BIGINT UNSIGNED NULL,
    published_content_hash BINARY(32) NULL,
    last_error_code VARCHAR(80) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_generation_job_revision (tenant_id, segment_id, desired_revision),
    UNIQUE KEY uq_generation_job_idempotency (tenant_id, segment_id, idempotency_hash),
    KEY idx_generation_job_claim (state, next_attempt_at, lease_until, created_at),
    CONSTRAINT fk_generation_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CHECK (desired_revision > 0),
    CHECK (
        (state = 'LEASED' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR (state <> 'LEASED' AND lease_owner IS NULL AND lease_until IS NULL)
    ),
    CHECK (
        (state = 'PUBLISHED' AND published_generation IS NOT NULL AND published_content_hash IS NOT NULL AND last_error_code IS NULL)
        OR (state <> 'PUBLISHED' AND published_generation IS NULL AND published_content_hash IS NULL)
    ),
    CHECK ((state IN ('RETRY','PERMANENT_FAILURE') AND last_error_code IS NOT NULL) OR (state NOT IN ('RETRY','PERMANENT_FAILURE')))
) ENGINE=InnoDB;
