ALTER TABLE client_access_policy_bindings
    ADD UNIQUE KEY uq_client_access_policy_binding_scope (id, organization_id, tenant_id);

CREATE TABLE client_access_policy_binding_requests (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    binding_id BINARY(16) NOT NULL,
    request_id BINARY(16) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    created_by BINARY(16) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_client_access_policy_binding_request_history (tenant_id, request_id),
    KEY idx_client_access_policy_binding_request_binding (tenant_id, binding_id),
    CONSTRAINT fk_client_access_policy_binding_request_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_client_access_policy_binding_request_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_client_access_policy_binding_request_binding FOREIGN KEY (binding_id, organization_id, tenant_id) REFERENCES client_access_policy_bindings(id, organization_id, tenant_id),
    CONSTRAINT fk_client_access_policy_binding_request_creator FOREIGN KEY (created_by) REFERENCES human_users(id)
) ENGINE=InnoDB;

INSERT INTO client_access_policy_binding_requests (
    id, organization_id, tenant_id, binding_id, request_id, request_hash, created_by
)
SELECT
    UUID_TO_BIN(UUID()), organization_id, tenant_id, id, request_id, request_hash, created_by
FROM client_access_policy_bindings;
