ALTER TABLE site_route_projection_publications
    ADD UNIQUE KEY uq_projection_runtime_identity (tenant_id, device_id, device_key_id, id);

CREATE TABLE runtime_configuration_status (
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    projection_publication_id BINARY(16) NOT NULL,
    envelope_sha256 BINARY(32) NOT NULL,
    apply_state ENUM('ACTIVE','REJECTED') NOT NULL,
    error_code VARCHAR(80) NULL,
    reported_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, device_id, device_key_id),
    KEY idx_runtime_configuration_projection (projection_publication_id),
    KEY idx_runtime_configuration_state (tenant_id, apply_state, updated_at),
    CONSTRAINT fk_runtime_configuration_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_runtime_configuration_projection_identity
        FOREIGN KEY (tenant_id, device_id, device_key_id, projection_publication_id)
        REFERENCES site_route_projection_publications(tenant_id, device_id, device_key_id, id),
    CHECK (
        (apply_state = 'ACTIVE' AND error_code IS NULL)
        OR (apply_state = 'REJECTED' AND error_code IS NOT NULL)
    )
) ENGINE=InnoDB;
