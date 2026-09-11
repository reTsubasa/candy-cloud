CREATE TABLE runtime_upgrade_inventory (
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    inventory JSON NOT NULL,
    reported_at TIMESTAMP(6) NOT NULL,
    PRIMARY KEY (tenant_id, device_id, device_key_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE runtime_upgrade_jobs (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    node_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    actor_id VARCHAR(120) NOT NULL,
    request_id BINARY(16) NOT NULL,
    target JSON NOT NULL,
    state ENUM('pending','running','succeeded','failed','expired') NOT NULL,
    error_code VARCHAR(80) NULL,
    active_node_id BINARY(16) GENERATED ALWAYS AS
        (CASE WHEN state IN ('pending','running') THEN node_id ELSE NULL END) STORED,
    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY upgrade_idempotency (tenant_id, node_id, actor_id, request_id),
    UNIQUE KEY one_active_upgrade (tenant_id, active_node_id),
    KEY upgrade_device (tenant_id, device_id, device_key_id, state),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;
