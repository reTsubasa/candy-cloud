CREATE TABLE enrollment_activation_codes (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    code_hash BINARY(32) NOT NULL,
    hash_version VARCHAR(32) NOT NULL DEFAULT 'sha256-random-v1',
    status ENUM('ACTIVE','RESERVED','CONSUMED','REVOKED','EXPIRED') NOT NULL DEFAULT 'ACTIVE',
    expires_at TIMESTAMP(6) NOT NULL,
    reserved_at TIMESTAMP(6) NULL,
    consumed_at TIMESTAMP(6) NULL,
    created_by VARCHAR(120) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_enrollment_activation_code_hash (tenant_id, code_hash),
    KEY idx_enrollment_activation_tenant_status (tenant_id, status, expires_at),
    CONSTRAINT fk_enrollment_activation_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_enrollment_activation_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE enrollment_challenges (
    id BINARY(16) NOT NULL PRIMARY KEY,
    activation_code_id BINARY(16) NOT NULL,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    request_id VARCHAR(120) NOT NULL,
    request_fingerprint BINARY(32) NOT NULL,
    enrollment_instance_id VARCHAR(120) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    root_public_key BINARY(32) NOT NULL,
    operational_public_key BINARY(32) NOT NULL,
    metadata_hash BINARY(32) NOT NULL,
    attestation_hash BINARY(32) NOT NULL,
    server_nonce BINARY(32) NOT NULL,
    assurance_level BIGINT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('PENDING','CHALLENGED','PROVED','ISSUED','EXPIRED') NOT NULL DEFAULT 'PENDING',
    expires_at TIMESTAMP(6) NOT NULL,
    proved_at TIMESTAMP(6) NULL,
    issued_at TIMESTAMP(6) NULL,
    completion_request_id VARCHAR(120) NULL,
    device_id BINARY(16) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_enrollment_challenge_request (tenant_id, request_id),
    UNIQUE KEY uq_enrollment_challenge_activation (activation_code_id),
    KEY idx_enrollment_challenge_status_expiry (status, expires_at),
    CONSTRAINT fk_enrollment_challenge_activation FOREIGN KEY (activation_code_id) REFERENCES enrollment_activation_codes(id),
    CONSTRAINT fk_enrollment_challenge_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_enrollment_challenge_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_enrollment_challenge_device FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB;

CREATE TABLE device_certificates (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    device_key_id BINARY(16) NOT NULL,
    issuer_key_id VARCHAR(80) NOT NULL,
    serial_number VARBINARY(20) NOT NULL,
    certificate_der MEDIUMBLOB NOT NULL,
    certificate_chain_pem MEDIUMTEXT NOT NULL,
    san_uri VARCHAR(255) NOT NULL COMMENT 'URI:candy:device:<device_id>',
    environment VARCHAR(40) NOT NULL,
    assurance_level BIGINT UNSIGNED NOT NULL,
    not_before TIMESTAMP(6) NOT NULL,
    not_after TIMESTAMP(6) NOT NULL,
    status ENUM('ACTIVE','REVOKED','EXPIRED','SUPERSEDED') NOT NULL DEFAULT 'ACTIVE',
    revoked_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_device_certificate_serial (issuer_key_id, serial_number),
    KEY idx_device_certificate_device_status (device_id, status, not_after),
    KEY idx_device_certificate_tenant (tenant_id),
    CONSTRAINT fk_device_certificate_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_device_certificate_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_device_certificate_device FOREIGN KEY (device_id) REFERENCES devices(id),
    CONSTRAINT fk_device_certificate_key FOREIGN KEY (device_key_id) REFERENCES device_keys(id)
) ENGINE=InnoDB;

ALTER TABLE device_keys
    MODIFY status ENUM('PENDING','ACTIVE','RETIRED','RETIRING','REVOKED','COMPROMISED','EXPIRED') NOT NULL DEFAULT 'PENDING';

UPDATE device_keys SET status = 'RETIRING' WHERE status = 'RETIRED';

ALTER TABLE device_keys
    MODIFY status ENUM('PENDING','ACTIVE','RETIRING','REVOKED','COMPROMISED','EXPIRED') NOT NULL DEFAULT 'PENDING';
