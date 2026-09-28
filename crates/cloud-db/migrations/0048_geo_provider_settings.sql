CREATE TABLE geo_provider_settings (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    provider VARCHAR(80) NOT NULL,
    source_url VARCHAR(2048) NOT NULL,
    countries_json JSON NOT NULL,
    refresh_interval_seconds INT UNSIGNED NOT NULL DEFAULT 86400,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version VARCHAR(64) NULL,
    digest CHAR(64) NULL,
    generation BIGINT UNSIGNED NOT NULL,
    updated_by BINARY(16) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_geo_provider_tenant (tenant_id),
    CONSTRAINT fk_geo_provider_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_geo_provider_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_geo_provider_actor FOREIGN KEY (updated_by) REFERENCES human_users(id)
) ENGINE=InnoDB;
