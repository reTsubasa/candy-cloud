CREATE TABLE human_users (
    id BINARY(16) NOT NULL PRIMARY KEY,
    email_normalized VARCHAR(254) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified_at TIMESTAMP(6) NULL,
    status ENUM('PENDING_VERIFICATION','ACTIVE','SUSPENDED','DELETED') NOT NULL DEFAULT 'PENDING_VERIFICATION',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_human_users_email (email_normalized)
) ENGINE=InnoDB;

CREATE TABLE organization_memberships (
    organization_id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    role ENUM('ORGANIZATION_OWNER','TENANT_ADMIN','OPERATOR','BILLING_VIEWER','AUDITOR') NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (organization_id, user_id),
    KEY idx_organization_memberships_user (user_id),
    CONSTRAINT fk_organization_memberships_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_organization_memberships_user FOREIGN KEY (user_id) REFERENCES human_users(id)
) ENGINE=InnoDB;

CREATE TABLE human_sessions (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    session_family_id BINARY(16) NOT NULL,
    organization_id BINARY(16) NOT NULL,
    tenant_id BINARY(16) NOT NULL,
    device_label VARCHAR(200) NULL,
    user_agent_hash BINARY(32) NULL,
    ip_hash BINARY(32) NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    last_seen_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at TIMESTAMP(6) NULL,
    revoke_reason ENUM('USER','LOGOUT','ROTATION_REUSE','PASSWORD_RESET','ADMIN') NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_human_sessions_user (user_id, revoked_at, expires_at),
    KEY idx_human_sessions_family (session_family_id),
    CONSTRAINT fk_human_sessions_user FOREIGN KEY (user_id) REFERENCES human_users(id),
    CONSTRAINT fk_human_sessions_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_human_sessions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
) ENGINE=InnoDB;

CREATE TABLE human_refresh_tokens (
    id BINARY(16) NOT NULL PRIMARY KEY,
    session_id BINARY(16) NOT NULL,
    token_hash BINARY(32) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    used_at TIMESTAMP(6) NULL,
    revoked_at TIMESTAMP(6) NULL,
    replaced_by_id BINARY(16) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_human_refresh_tokens_hash (token_hash),
    KEY idx_human_refresh_tokens_session (session_id),
    CONSTRAINT fk_human_refresh_tokens_session FOREIGN KEY (session_id) REFERENCES human_sessions(id),
    CONSTRAINT fk_human_refresh_tokens_replaced_by FOREIGN KEY (replaced_by_id) REFERENCES human_refresh_tokens(id)
) ENGINE=InnoDB;

CREATE TABLE human_action_tokens (
    id BINARY(16) NOT NULL PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    purpose ENUM('VERIFY_EMAIL','RESET_PASSWORD') NOT NULL,
    token_hash BINARY(32) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    consumed_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_human_action_tokens_hash (token_hash),
    KEY idx_human_action_tokens_user_purpose (user_id, purpose, consumed_at),
    CONSTRAINT fk_human_action_tokens_user FOREIGN KEY (user_id) REFERENCES human_users(id)
) ENGINE=InnoDB;
