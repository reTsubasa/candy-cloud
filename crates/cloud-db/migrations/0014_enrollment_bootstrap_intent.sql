ALTER TABLE enrollment_activation_codes
    ADD COLUMN site_id BINARY(16) NULL AFTER tenant_id,
    ADD COLUMN requested_display_name VARCHAR(200) NULL AFTER site_id,
    ADD COLUMN requested_platform ENUM('OPEN_WRT','LINUX') NULL AFTER requested_display_name,
    ADD COLUMN requested_architecture VARCHAR(80) NULL AFTER requested_platform,
    ADD COLUMN bootstrap_instance_id VARCHAR(120) NULL AFTER requested_architecture,
    ADD COLUMN bootstrap_reserved_at TIMESTAMP(6) NULL AFTER bootstrap_instance_id,
    ADD COLUMN enrollment_credential_hash BINARY(32) NULL AFTER bootstrap_reserved_at,
    ADD KEY idx_enrollment_activation_site (tenant_id, site_id);
