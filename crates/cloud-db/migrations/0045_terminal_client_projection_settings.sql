-- The signed terminal PolicyProjection carries several fields that are neither
-- policy resources nor node routing: DNS resolvers, search domains, underlay
-- exclusions, and the degraded-mode behaviour. Cloud needs an explicit,
-- versioned source of truth for them, otherwise the projection generator would
-- have to invent values at signing time and the Client would install a document
-- nobody reviewed.
--
-- The effective traffic mode is held per device. It is deliberately *not* a
-- caller-supplied field: the Client asks Cloud to change mode through its
-- control plane, and Cloud records the decision here before signing anything.

CREATE TABLE client_projection_settings (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    generation BIGINT UNSIGNED NOT NULL,
    request_id BINARY(16) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    content_hash BINARY(32) NOT NULL,
    settings_json JSON NOT NULL,
    status ENUM('ACTIVE','SUPERSEDED') NOT NULL DEFAULT 'ACTIVE',
    created_by BINARY(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_client_projection_settings_scope (id, organization_id, tenant_id),
    UNIQUE KEY uq_client_projection_settings_generation (tenant_id, generation),
    UNIQUE KEY uq_client_projection_settings_request (tenant_id, request_id),
    UNIQUE KEY uq_client_projection_settings_content (tenant_id, content_hash),
    KEY idx_client_projection_settings_current (tenant_id, status, generation),
    CONSTRAINT fk_client_projection_settings_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_client_projection_settings_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_client_projection_settings_creator FOREIGN KEY (created_by) REFERENCES human_users(id),
    CONSTRAINT client_projection_settings_generation_positive CHECK (generation >= 1),
    CONSTRAINT client_projection_settings_document_schema CHECK (JSON_EXTRACT(settings_json, '$.schema_version') = 1)
) ENGINE=InnoDB;

ALTER TABLE client_devices
    ADD COLUMN traffic_mode ENUM('POLICY','GLOBAL') NOT NULL DEFAULT 'POLICY' AFTER status;

-- Mode changes are recorded as requests rather than as a bare column update so
-- that a retried switch is idempotent and a reused idempotency key against a
-- different requested mode is a conflict instead of a silent flip. The row is
-- also the audit trail of who moved a device into global mode.
CREATE TABLE client_traffic_mode_requests (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    client_device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    request_id BINARY(16) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    previous_mode ENUM('POLICY','GLOBAL') NOT NULL,
    requested_mode ENUM('POLICY','GLOBAL') NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_client_traffic_mode_request (tenant_id, client_device_id, request_id),
    KEY idx_client_traffic_mode_request_device (tenant_id, client_device_id, created_at),
    CONSTRAINT fk_client_traffic_mode_request_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_client_traffic_mode_request_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_client_traffic_mode_request_user FOREIGN KEY (user_id) REFERENCES human_users(id),
    CONSTRAINT fk_client_traffic_mode_request_device FOREIGN KEY (client_device_id, organization_id, tenant_id, user_id) REFERENCES client_devices(id, organization_id, tenant_id, user_id)
) ENGINE=InnoDB;
