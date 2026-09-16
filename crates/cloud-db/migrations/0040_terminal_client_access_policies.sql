-- Terminal client authorization is separate from site ServicePolicy and
-- runtime configuration. The JSON document is the signed-projection input.

CREATE TABLE client_access_policies (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    generation BIGINT UNSIGNED NOT NULL,
    request_id BINARY(16) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    content_hash BINARY(32) NOT NULL,
    policy_json JSON NOT NULL,
    status ENUM('ACTIVE','SUPERSEDED','REVOKED') NOT NULL DEFAULT 'ACTIVE',
    created_by BINARY(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at TIMESTAMP(6) NULL,
    UNIQUE KEY uq_client_access_policy_scope (id, organization_id, tenant_id),
    UNIQUE KEY uq_client_access_policy_generation (tenant_id, generation),
    UNIQUE KEY uq_client_access_policy_request (tenant_id, request_id),
    UNIQUE KEY uq_client_access_policy_content (tenant_id, content_hash),
    KEY idx_client_access_policy_current (tenant_id, status, generation),
    CONSTRAINT fk_client_access_policy_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_client_access_policy_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_client_access_policy_creator FOREIGN KEY (created_by) REFERENCES human_users(id),
    CONSTRAINT client_access_policy_generation_positive CHECK (generation >= 1),
    CONSTRAINT client_access_policy_document_schema CHECK (JSON_EXTRACT(policy_json, '$.schema_version') = 1)
) ENGINE=InnoDB;

CREATE TABLE client_access_policy_bindings (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    client_device_id BINARY(16) NOT NULL,
    policy_id BINARY(16) NOT NULL,
    request_id BINARY(16) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    created_by BINARY(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_client_access_policy_binding_device (tenant_id, client_device_id),
    UNIQUE KEY uq_client_access_policy_binding_policy (policy_id, client_device_id),
    UNIQUE KEY uq_client_access_policy_binding_request (tenant_id, request_id),
    CONSTRAINT fk_client_access_policy_binding_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_client_access_policy_binding_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_client_access_policy_binding_user FOREIGN KEY (user_id) REFERENCES human_users(id),
    CONSTRAINT fk_client_access_policy_binding_device FOREIGN KEY (client_device_id, organization_id, tenant_id, user_id) REFERENCES client_devices(id, organization_id, tenant_id, user_id),
    CONSTRAINT fk_client_access_policy_binding_policy FOREIGN KEY (policy_id, organization_id, tenant_id) REFERENCES client_access_policies(id, organization_id, tenant_id),
    CONSTRAINT fk_client_access_policy_binding_creator FOREIGN KEY (created_by) REFERENCES human_users(id)
) ENGINE=InnoDB;
