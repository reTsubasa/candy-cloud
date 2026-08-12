ALTER TABLE organization_memberships
    ADD COLUMN status ENUM('ACTIVE','SUSPENDED') NOT NULL DEFAULT 'ACTIVE' AFTER role,
    ADD COLUMN owner_guard TINYINT GENERATED ALWAYS AS (IF(role = 'ORGANIZATION_OWNER', 1, NULL)) STORED AFTER status,
    ADD COLUMN updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6) AFTER created_at,
    ADD KEY idx_organization_memberships_status (organization_id, status),
    ADD UNIQUE KEY uq_organization_single_owner (organization_id, owner_guard);

CREATE TABLE organization_invitations (
    id BINARY(16) NOT NULL PRIMARY KEY,
    organization_id BINARY(16) NOT NULL,
    email_normalized VARCHAR(254) NOT NULL,
    role ENUM('TENANT_ADMIN','OPERATOR','BILLING_VIEWER','AUDITOR') NOT NULL,
    token_hash BINARY(32) NOT NULL,
    invited_by_user_id BINARY(16) NOT NULL,
    expires_at TIMESTAMP(6) NOT NULL,
    accepted_at TIMESTAMP(6) NULL,
    revoked_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_organization_invitations_token (token_hash),
    KEY idx_organization_invitations_org_email (organization_id, email_normalized, accepted_at, revoked_at),
    CONSTRAINT fk_organization_invitations_organization FOREIGN KEY (organization_id) REFERENCES organizations(id),
    CONSTRAINT fk_organization_invitations_inviter FOREIGN KEY (invited_by_user_id) REFERENCES human_users(id)
) ENGINE=InnoDB;
