-- Platform Geo data is a deployment-wide capability.  Keep its authority
-- separate from organization ownership so an organization administrator
-- cannot change data consumed by every tenant.
ALTER TABLE organization_memberships
    MODIFY COLUMN role ENUM('PLATFORM_ADMIN','ORGANIZATION_OWNER','TENANT_ADMIN','OPERATOR','BILLING_VIEWER','AUDITOR') NOT NULL;

-- PLATFORM_ADMIN is intentionally not added to tenant invitation flows and is
-- never accepted by the member-management API. Bootstrap or revoke it only
-- through an authenticated deployment operation.
