CREATE TABLE organizations (
    id BINARY(16) NOT NULL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    status ENUM('ACTIVE','SUSPENDED','DELETED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;

CREATE TABLE tenants (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    name VARCHAR(200) NOT NULL,
    status ENUM('ACTIVE','SUSPENDED','DELETED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_tenants_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    KEY idx_tenants_org (organization_id)
) ENGINE=InnoDB;

CREATE TABLE devices (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    device_id CHAR(36) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    status ENUM('PENDING','ACTIVE','SUSPENDED','REVOKED') NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at TIMESTAMP(6) NULL,
    UNIQUE KEY uq_devices_device_id (device_id),
    KEY idx_devices_tenant (tenant_id),
    CONSTRAINT fk_devices_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE device_keys (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    key_id VARCHAR(80) NOT NULL,
    public_key VARBINARY(64) NOT NULL,
    assurance_level BIGINT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('ACTIVE','RETIRED','REVOKED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at TIMESTAMP(6) NULL,
    UNIQUE KEY uq_device_keys_key_id (key_id),
    KEY idx_device_keys_tenant (tenant_id),
    CONSTRAINT fk_device_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_device_keys_device FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB;

CREATE TABLE node_pools (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NULL,
    service_class ENUM('PRIVATE','CANDY_SHARED','CANDY_DEDICATED','PARTNER') NOT NULL,
    name VARCHAR(200) NOT NULL,
    audience VARCHAR(120) NOT NULL,
    status ENUM('ACTIVE','DISABLED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_node_pools_tenant (tenant_id),
    CONSTRAINT fk_node_pools_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE nodes (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NULL,
    node_pool_id BINARY(16) NOT NULL,
    node_id VARCHAR(120) NOT NULL,
    status ENUM('PENDING','ACTIVE','DRAINING','REVOKED') NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at TIMESTAMP(6) NULL,
    UNIQUE KEY uq_nodes_node_id (node_id),
    KEY idx_nodes_tenant (tenant_id),
    CONSTRAINT fk_nodes_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_nodes_pool FOREIGN KEY (node_pool_id) REFERENCES node_pools(id)
) ENGINE=InnoDB;

CREATE TABLE node_endpoints (
    id BINARY(16) NOT NULL PRIMARY KEY,
    node_id BINARY(16) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    region VARCHAR(80) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_node_endpoints_node FOREIGN KEY (node_id) REFERENCES nodes(id)
) ENGINE=InnoDB;

CREATE TABLE subscriptions (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    plan_code VARCHAR(100) NOT NULL,
    status ENUM('TRIAL','ACTIVE','GRACE','PAST_DUE','CANCELLED','EXPIRED') NOT NULL,
    starts_at TIMESTAMP(6) NOT NULL,
    ends_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_subscriptions_tenant (tenant_id),
    CONSTRAINT fk_subscriptions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE entitlements (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    subscription_id BINARY(16) NOT NULL,
    node_pool_id BINARY(16) NOT NULL,
    service_permission VARCHAR(120) NOT NULL,
    quota_json JSON NOT NULL,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('ACTIVE','SUSPENDED','REVOKED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_entitlements_tenant (tenant_id),
    UNIQUE KEY uq_entitlements_pool_permission (tenant_id, node_pool_id, service_permission),
    CONSTRAINT fk_entitlements_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_entitlements_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id),
    CONSTRAINT fk_entitlements_pool FOREIGN KEY (node_pool_id) REFERENCES node_pools(id)
) ENGINE=InnoDB;

CREATE TABLE policies (
    tenant_id BINARY(16) NOT NULL PRIMARY KEY,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    policy_json JSON NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_policies_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE authorization_generations (
    tenant_id BINARY(16) NOT NULL PRIMARY KEY,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_authorization_generations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE grant_issuance_records (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NOT NULL,
    request_id VARCHAR(120) NOT NULL,
    authorization_generation BIGINT UNSIGNED NOT NULL,
    request_fingerprint BINARY(32) NOT NULL,
    key_id VARCHAR(80) NOT NULL,
    grant_digest BINARY(32) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_grant_request (device_id, authorization_generation, request_id),
    KEY idx_grants_tenant (tenant_id),
    CONSTRAINT fk_grants_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_grants_device FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB;

CREATE TABLE revocation_generations (
    tenant_id BINARY(16) NOT NULL PRIMARY KEY,
    generation BIGINT UNSIGNED NOT NULL DEFAULT 1,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_revocations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE accounting_sessions (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    device_id BINARY(16) NULL,
    node_id BINARY(16) NULL,
    trust_level ENUM('CUSTOMER_REPORTED','TRUSTED_CANDY') NOT NULL,
    started_at TIMESTAMP(6) NOT NULL,
    ended_at TIMESTAMP(6) NULL,
    KEY idx_accounting_sessions_tenant (tenant_id),
    CONSTRAINT fk_accounting_sessions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE accounting_records (
    id BINARY(16) NOT NULL PRIMARY KEY,
    tenant_id BINARY(16) NOT NULL,
    session_id BINARY(16) NOT NULL,
    idempotency_key VARCHAR(160) NOT NULL,
    bytes_up BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes_down BIGINT UNSIGNED NOT NULL DEFAULT 0,
    recorded_at TIMESTAMP(6) NOT NULL,
    UNIQUE KEY uq_accounting_idempotency (tenant_id, idempotency_key),
    KEY idx_accounting_records_tenant (tenant_id),
    CONSTRAINT fk_accounting_records_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    CONSTRAINT fk_accounting_records_session FOREIGN KEY (session_id) REFERENCES accounting_sessions(id)
) ENGINE=InnoDB;

CREATE TABLE audit_events (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NULL,
    tenant_id BINARY(16) NULL,
    actor_type VARCHAR(40) NOT NULL,
    actor_id VARCHAR(120) NULL,
    action VARCHAR(120) NOT NULL,
    object_type VARCHAR(80) NOT NULL,
    object_id VARCHAR(120) NULL,
    metadata_json JSON NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_audit_tenant_time (tenant_id, created_at),
    CONSTRAINT fk_audit_org FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_audit_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE worker_leases (
    lease_name VARCHAR(120) NOT NULL PRIMARY KEY,
    owner_id VARCHAR(120) NOT NULL,
    lease_until TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
