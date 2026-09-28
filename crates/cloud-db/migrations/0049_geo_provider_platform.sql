CREATE TABLE geo_provider_platform_settings (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
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
    CONSTRAINT fk_geo_provider_platform_actor FOREIGN KEY (updated_by) REFERENCES human_users(id)
) ENGINE=InnoDB;

INSERT INTO geo_provider_platform_settings
    (id, provider, source_url, countries_json, refresh_interval_seconds, enabled, version, digest, generation, updated_by)
SELECT 1, provider, source_url, countries_json, refresh_interval_seconds, enabled, version, digest, generation, updated_by
FROM geo_provider_settings
ORDER BY updated_at DESC
LIMIT 1;
