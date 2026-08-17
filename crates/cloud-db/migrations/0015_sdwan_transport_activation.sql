ALTER TABLE nodes
    ADD COLUMN device_id BINARY(16) NULL AFTER tenant_id,
    ADD COLUMN device_key_id BINARY(16) NULL AFTER device_id,
    ADD UNIQUE KEY uq_nodes_device_identity (tenant_id, device_id, device_key_id),
    ADD CONSTRAINT fk_nodes_device FOREIGN KEY (device_id) REFERENCES devices(id),
    ADD CONSTRAINT fk_nodes_device_key FOREIGN KEY (device_key_id) REFERENCES device_keys(id);

ALTER TABLE node_endpoints
    ADD COLUMN transport ENUM('CANDY_QUIC_UDP') NULL AFTER endpoint,
    ADD COLUMN server_name VARCHAR(253) NULL AFTER transport,
    ADD COLUMN server_cert_sha256 BINARY(32) NULL AFTER server_name,
    ADD COLUMN transport_preset ENUM('CURRENT','BBR_V1','AGGRESSIVE') NULL AFTER server_cert_sha256,
    ADD COLUMN status ENUM('ACTIVE','DISABLED') NOT NULL DEFAULT 'DISABLED' AFTER transport_preset,
    ADD UNIQUE KEY uq_node_endpoint (node_id, endpoint);

CREATE TABLE runtime_projection_transport_catalog (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    segment_generation BIGINT UNSIGNED NOT NULL,
    transport_node_id BINARY(16) NOT NULL,
    transport_node_key_id BINARY(16) NOT NULL,
    projection_publication_id BINARY(16) NOT NULL,
    projection_id BINARY(16) NOT NULL,
    PRIMARY KEY (transport_node_id, projection_publication_id),
    UNIQUE KEY uq_transport_projection_generation (tenant_id, segment_id, segment_generation, transport_node_id, projection_id),
    KEY idx_transport_catalog_runtime (tenant_id, transport_node_key_id, segment_id, segment_generation, projection_id),
    CONSTRAINT fk_transport_catalog_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_transport_catalog_segment FOREIGN KEY (segment_id) REFERENCES segments(id),
    CONSTRAINT fk_transport_catalog_node FOREIGN KEY (transport_node_id) REFERENCES nodes(id),
    CONSTRAINT fk_transport_catalog_node_key FOREIGN KEY (transport_node_key_id) REFERENCES device_keys(id),
    CONSTRAINT fk_transport_catalog_projection FOREIGN KEY (projection_publication_id) REFERENCES site_route_projection_publications(id)
) ENGINE=InnoDB;

CREATE TABLE runtime_transport_identity_requests (
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    request_id VARCHAR(120) NOT NULL,
    request_hash BINARY(32) NOT NULL,
    response_json JSON NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (tenant_id, device_id, request_id),
    CONSTRAINT fk_transport_request_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_transport_request_device FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB;
