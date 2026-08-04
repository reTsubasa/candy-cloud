CREATE TABLE segments (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    name VARCHAR(200) NOT NULL,
    hub_node_pool_id BINARY(16) NOT NULL,
    overlay_network BINARY(4) NOT NULL,
    overlay_prefix_len TINYINT UNSIGNED NOT NULL,
    state ENUM('ACTIVE','DISABLED','DELETED') NOT NULL DEFAULT 'ACTIVE',
    current_generation BIGINT UNSIGNED NOT NULL DEFAULT 0,
    current_content_hash BINARY(32) NOT NULL DEFAULT 0x0000000000000000000000000000000000000000000000000000000000000000,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_segments_tenant_name (tenant_id, name),
    KEY idx_segments_tenant_state (tenant_id, state),
    CONSTRAINT fk_segments_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_segments_hub_pool FOREIGN KEY (hub_node_pool_id) REFERENCES node_pools(id)
) ENGINE=InnoDB;

CREATE TABLE sites (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    name VARCHAR(200) NOT NULL,
    kind ENUM('EDGE','PRIVATE_CLOUD') NOT NULL DEFAULT 'EDGE',
    state ENUM('ACTIVE','DISABLED','DELETED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_sites_tenant_name (tenant_id, name),
    KEY idx_sites_tenant_state (tenant_id, state),
    CONSTRAINT fk_sites_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE site_prefixes (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    site_id BINARY(16) NOT NULL,
    network BINARY(4) NOT NULL,
    prefix_len TINYINT UNSIGNED NOT NULL,
    state ENUM('ACTIVE','DISABLED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_site_prefix (tenant_id, network, prefix_len),
    KEY idx_site_prefixes_tenant_site (tenant_id, site_id, state),
    CONSTRAINT fk_site_prefixes_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_site_prefixes_site FOREIGN KEY (site_id) REFERENCES sites(id)
) ENGINE=InnoDB;

CREATE TABLE segment_attachments (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    site_id BINARY(16) NULL,
    principal_kind ENUM('DEVICE','NODE') NOT NULL,
    device_id BINARY(16) NULL,
    device_key_id BINARY(16) NULL,
    node_id BINARY(16) NULL,
    node_key_id BINARY(16) NULL,
    node_pool_id BINARY(16) NULL,
    overlay_router_ipv4 BINARY(4) NOT NULL,
    state ENUM('ACTIVE','STANDBY','DISABLED','REVOKED') NOT NULL,
    epoch_floor BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_segment_router_address (tenant_id, segment_id, overlay_router_ipv4),
    KEY idx_segment_attachments_tenant_segment (tenant_id, segment_id, state),
    KEY idx_segment_attachments_tenant_site (tenant_id, site_id),
    KEY idx_segment_attachments_tenant_device (tenant_id, device_id, device_key_id),
    KEY idx_segment_attachments_tenant_node (tenant_id, node_id, node_key_id),
    CONSTRAINT fk_segment_attachments_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_segment_attachments_segment FOREIGN KEY (segment_id) REFERENCES segments(id),
    CONSTRAINT fk_segment_attachments_site FOREIGN KEY (site_id) REFERENCES sites(id),
    CONSTRAINT fk_segment_attachments_device FOREIGN KEY (device_id) REFERENCES devices(id),
    CONSTRAINT fk_segment_attachments_device_key FOREIGN KEY (device_key_id) REFERENCES device_keys(id),
    CONSTRAINT fk_segment_attachments_node_pool FOREIGN KEY (node_pool_id) REFERENCES node_pools(id)
) ENGINE=InnoDB;

CREATE TABLE segment_route_publications (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    expected_previous_generation BIGINT UNSIGNED NOT NULL,
    expected_previous_hash BINARY(32) NOT NULL,
    generation BIGINT UNSIGNED NOT NULL,
    content_hash BINARY(32) NOT NULL,
    signed_envelope MEDIUMBLOB NOT NULL,
    audit_event_id BINARY(16) NOT NULL,
    actor_id VARCHAR(120) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_segment_publication_generation (tenant_id, segment_id, generation),
    KEY idx_segment_publications_tenant_segment (tenant_id, segment_id, created_at),
    CONSTRAINT fk_segment_publications_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_segment_publications_segment FOREIGN KEY (segment_id) REFERENCES segments(id)
) ENGINE=InnoDB;

CREATE TABLE site_route_projection_publications (
    id BINARY(16) NOT NULL PRIMARY KEY,
    publication_id BINARY(16) NOT NULL,
    projection_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    site_id BINARY(16) NOT NULL,
    attachment_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    segment_generation BIGINT UNSIGNED NOT NULL,
    segment_content_hash BINARY(32) NOT NULL,
    projection_generation BIGINT UNSIGNED NOT NULL,
    previous_hash BINARY(32) NOT NULL,
    content_hash BINARY(32) NOT NULL,
    signed_envelope MEDIUMBLOB NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_projection_generation (tenant_id, projection_id, projection_generation),
    UNIQUE KEY uq_projection_publication_attachment (publication_id, attachment_id),
    KEY idx_projection_publications_tenant_segment (tenant_id, segment_id, segment_generation),
    KEY idx_projection_publications_tenant_device (tenant_id, device_id, device_key_id),
    CONSTRAINT fk_projection_publications_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_projection_publications_segment FOREIGN KEY (segment_id) REFERENCES segments(id),
    CONSTRAINT fk_projection_publications_site FOREIGN KEY (site_id) REFERENCES sites(id),
    CONSTRAINT fk_projection_publications_attachment FOREIGN KEY (attachment_id) REFERENCES segment_attachments(id),
    CONSTRAINT fk_projection_publications_device FOREIGN KEY (device_id) REFERENCES devices(id),
    CONSTRAINT fk_projection_publications_device_key FOREIGN KEY (device_key_id) REFERENCES device_keys(id)
) ENGINE=InnoDB;

CREATE TABLE segment_route_publication_members (
    tenant_id BINARY(16) NOT NULL,
    segment_publication_id BINARY(16) NOT NULL,
    projection_publication_id BINARY(16) NOT NULL,
    projection_id BINARY(16) NOT NULL,
    attachment_id BINARY(16) NOT NULL,
    PRIMARY KEY (segment_publication_id, projection_publication_id),
    UNIQUE KEY uq_publication_member_attachment (segment_publication_id, attachment_id),
    KEY idx_publication_members_tenant (tenant_id, segment_publication_id),
    CONSTRAINT fk_publication_members_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_publication_members_segment FOREIGN KEY (segment_publication_id) REFERENCES segment_route_publications(id),
    CONSTRAINT fk_publication_members_projection FOREIGN KEY (projection_publication_id) REFERENCES site_route_projection_publications(id)
) ENGINE=InnoDB;

ALTER TABLE segment_route_publications
    ADD CONSTRAINT fk_segment_publications_audit FOREIGN KEY (audit_event_id) REFERENCES audit_events(id);
