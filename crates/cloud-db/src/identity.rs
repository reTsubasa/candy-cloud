use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::DbPool;

const MAX_EMAIL_LEN: usize = 254;
const MAX_NAME_LEN: usize = 200;
const MAX_DEVICE_LABEL_LEN: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum IdentityRepositoryError {
    #[error("invalid identity input")]
    InvalidInput,
    #[error("identity conflict")]
    Conflict,
    #[error("identity record not found")]
    NotFound,
    #[error("identity database failure")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRole {
    OrganizationOwner,
    TenantAdmin,
    Operator,
    BillingViewer,
    Auditor,
}

impl MembershipRole {
    pub const fn database_value(self) -> &'static str {
        match self {
            Self::OrganizationOwner => "ORGANIZATION_OWNER",
            Self::TenantAdmin => "TENANT_ADMIN",
            Self::Operator => "OPERATOR",
            Self::BillingViewer => "BILLING_VIEWER",
            Self::Auditor => "AUDITOR",
        }
    }

    pub fn parse(value: &str) -> Result<Self, IdentityRepositoryError> {
        match value {
            "ORGANIZATION_OWNER" => Ok(Self::OrganizationOwner),
            "TENANT_ADMIN" => Ok(Self::TenantAdmin),
            "OPERATOR" => Ok(Self::Operator),
            "BILLING_VIEWER" => Ok(Self::BillingViewer),
            "AUDITOR" => Ok(Self::Auditor),
            _ => Err(IdentityRepositoryError::InvalidInput),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HumanUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub verified: bool,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct RegistrationWrite {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoAccountBootstrap {
    Created,
    Updated,
}

#[derive(Debug, Clone)]
pub struct Membership {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub role: MembershipRole,
}

#[derive(Debug, Clone)]
pub struct OrganizationMember {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: MembershipRole,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct OrganizationInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: MembershipRole,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct InvitedRegistrationWrite {
    pub user_id: Uuid,
    pub display_name: String,
    pub password_hash: String,
}

pub struct ContextSessionReplacement<'a> {
    pub previous_session_id: Uuid,
    pub session: &'a SessionRecord,
    pub token_id: Uuid,
    pub token_hash: &'a [u8],
    pub token_expires_at: DateTime<Utc>,
    pub device_label: Option<&'a str>,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub family_id: Uuid,
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
    pub role: MembershipRole,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub id: Uuid,
    pub session_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTokenPurpose {
    VerifyEmail,
    ResetPassword,
}

impl ActionTokenPurpose {
    pub const fn database_value(self) -> &'static str {
        match self {
            Self::VerifyEmail => "VERIFY_EMAIL",
            Self::ResetPassword => "RESET_PASSWORD",
        }
    }
}

#[derive(Clone)]
pub struct IdentityRepository {
    pool: DbPool,
}

impl IdentityRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn readiness_check(&self) -> Result<(), IdentityRepositoryError> {
        sqlx::query("SELECT id FROM human_users LIMIT 0")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn register_user_and_workspace(
        &self,
        registration: &RegistrationWrite,
    ) -> Result<(), IdentityRepositoryError> {
        validate_email(&registration.email)?;
        if registration.user_id.is_nil()
            || registration.organization_id.is_nil()
            || registration.tenant_id.is_nil()
            || !bounded(&registration.display_name, MAX_NAME_LEN)
            || !bounded(&registration.organization_name, MAX_NAME_LEN)
            || registration.password_hash.is_empty()
            || registration.password_hash.len() > 255
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO human_users (id, email_normalized, display_name, password_hash) VALUES (?, ?, ?, ?)",
        )
        .bind(registration.user_id)
        .bind(&registration.email)
        .bind(&registration.display_name)
        .bind(&registration.password_hash)
        .execute(&mut *tx)
        .await;
        if let Err(error) = result {
            if error
                .as_database_error()
                .and_then(|db| db.code().map(|code| code == "1062"))
                == Some(true)
            {
                return Err(IdentityRepositoryError::Conflict);
            }
            return Err(error.into());
        }
        sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
            .bind(registration.organization_id)
            .bind(&registration.organization_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
            .bind(registration.tenant_id)
            .bind(registration.organization_id)
            .bind(&registration.organization_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES (?, ?, 'ORGANIZATION_OWNER')")
            .bind(registration.organization_id).bind(registration.user_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Creates or refreshes the explicitly enabled development demo owner.
    ///
    /// The caller is responsible for enforcing the development-only environment gate. Existing
    /// accounts are accepted only when they already own an organization, so a configured demo
    /// email cannot silently take over an unrelated user.
    pub async fn bootstrap_verified_demo_owner(
        &self,
        registration: &RegistrationWrite,
        now: DateTime<Utc>,
    ) -> Result<DemoAccountBootstrap, IdentityRepositoryError> {
        validate_email(&registration.email)?;
        if registration.user_id.is_nil()
            || registration.organization_id.is_nil()
            || registration.tenant_id.is_nil()
            || !bounded(&registration.display_name, MAX_NAME_LEN)
            || !bounded(&registration.organization_name, MAX_NAME_LEN)
            || registration.password_hash.is_empty()
            || registration.password_hash.len() > 255
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }

        let mut tx = self.pool.begin().await?;
        let existing = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM human_users WHERE email_normalized = ? FOR UPDATE",
        )
        .bind(&registration.email)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(user_id) = existing {
            let is_marked_demo = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM development_demo_accounts WHERE user_id = ? AND email_normalized = ?",
            )
            .bind(user_id)
            .bind(&registration.email)
            .fetch_one(&mut *tx)
            .await?
                > 0;
            if !is_marked_demo {
                tx.rollback().await?;
                return Err(IdentityRepositoryError::Conflict);
            }
            sqlx::query("UPDATE human_users SET display_name = ?, password_hash = ?, email_verified_at = COALESCE(email_verified_at, ?), status = 'ACTIVE' WHERE id = ?")
                .bind(&registration.display_name)
                .bind(&registration.password_hash)
                .bind(now)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE human_sessions SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = COALESCE(revoke_reason, 'PASSWORD_RESET') WHERE user_id = ?")
                .bind(now)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(DemoAccountBootstrap::Updated);
        }

        sqlx::query("INSERT INTO human_users (id, email_normalized, display_name, password_hash, email_verified_at, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
            .bind(registration.user_id)
            .bind(&registration.email)
            .bind(&registration.display_name)
            .bind(&registration.password_hash)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO organizations (id, name) VALUES (?, ?)")
            .bind(registration.organization_id)
            .bind(&registration.organization_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO tenants (id, organization_id, name) VALUES (?, ?, ?)")
            .bind(registration.tenant_id)
            .bind(registration.organization_id)
            .bind(&registration.organization_name)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role, status) VALUES (?, ?, 'ORGANIZATION_OWNER', 'ACTIVE')")
            .bind(registration.organization_id)
            .bind(registration.user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO development_demo_accounts (user_id, email_normalized) VALUES (?, ?)",
        )
        .bind(registration.user_id)
        .bind(&registration.email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DemoAccountBootstrap::Created)
    }

    pub async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<HumanUser>, IdentityRepositoryError> {
        validate_email(email)?;
        let row = sqlx::query("SELECT id, email_normalized, display_name, password_hash, email_verified_at, status FROM human_users WHERE email_normalized = ?")
            .bind(email).fetch_optional(&self.pool).await?;
        row.map(|row| {
            Ok(HumanUser {
                id: row.try_get("id")?,
                email: row.try_get("email_normalized")?,
                display_name: row.try_get("display_name")?,
                password_hash: row.try_get("password_hash")?,
                verified: row
                    .try_get::<Option<DateTime<Utc>>, _>("email_verified_at")?
                    .is_some(),
                active: row.try_get::<String, _>("status")? == "ACTIVE",
            })
        })
        .transpose()
    }

    pub async fn primary_membership(
        &self,
        user_id: Uuid,
    ) -> Result<Option<Membership>, IdentityRepositoryError> {
        if user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let row = sqlx::query("SELECT membership.organization_id, organization.name AS organization_name, tenant.id AS tenant_id, tenant.name AS tenant_name, membership.role FROM organization_memberships membership JOIN tenants tenant ON tenant.organization_id = membership.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = membership.organization_id AND organization.status = 'ACTIVE' WHERE membership.user_id = ? AND membership.status = 'ACTIVE' ORDER BY membership.created_at, tenant.created_at LIMIT 1")
            .bind(user_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            Ok(Membership {
                organization_id: row.try_get("organization_id")?,
                organization_name: row.try_get("organization_name")?,
                tenant_id: row.try_get("tenant_id")?,
                tenant_name: row.try_get("tenant_name")?,
                role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
            })
        })
        .transpose()
    }

    pub async fn membership_in_organization(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<Membership>, IdentityRepositoryError> {
        if user_id.is_nil() || organization_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let row = sqlx::query("SELECT membership.organization_id, organization.name AS organization_name, tenant.id AS tenant_id, tenant.name AS tenant_name, membership.role FROM organization_memberships membership JOIN tenants tenant ON tenant.organization_id = membership.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = membership.organization_id AND organization.status = 'ACTIVE' WHERE membership.user_id = ? AND membership.organization_id = ? AND membership.status = 'ACTIVE' ORDER BY tenant.created_at LIMIT 1")
            .bind(user_id).bind(organization_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            Ok(Membership {
                organization_id: row.try_get("organization_id")?,
                organization_name: row.try_get("organization_name")?,
                tenant_id: row.try_get("tenant_id")?,
                tenant_name: row.try_get("tenant_name")?,
                role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
            })
        })
        .transpose()
    }

    pub async fn memberships_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Membership>, IdentityRepositoryError> {
        if user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let rows = sqlx::query("SELECT membership.organization_id, organization.name AS organization_name, tenant.id AS tenant_id, tenant.name AS tenant_name, membership.role FROM organization_memberships membership JOIN tenants tenant ON tenant.organization_id = membership.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = membership.organization_id AND organization.status = 'ACTIVE' WHERE membership.user_id = ? AND membership.status = 'ACTIVE' ORDER BY membership.created_at, tenant.created_at")
            .bind(user_id).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(Membership {
                    organization_id: row.try_get("organization_id")?,
                    organization_name: row.try_get("organization_name")?,
                    tenant_id: row.try_get("tenant_id")?,
                    tenant_name: row.try_get("tenant_name")?,
                    role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
                })
            })
            .collect()
    }

    pub async fn find_user_by_session_id(
        &self,
        session_id: Uuid,
    ) -> Result<Option<HumanUser>, IdentityRepositoryError> {
        if session_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let row = sqlx::query("SELECT user.id, user.email_normalized, user.display_name, user.password_hash, user.email_verified_at, user.status FROM human_sessions session JOIN human_users user ON user.id = session.user_id WHERE session.id = ?")
            .bind(session_id).fetch_optional(&self.pool).await?;
        row.map(|row| {
            Ok(HumanUser {
                id: row.try_get("id")?,
                email: row.try_get("email_normalized")?,
                display_name: row.try_get("display_name")?,
                password_hash: row.try_get("password_hash")?,
                verified: row
                    .try_get::<Option<DateTime<Utc>>, _>("email_verified_at")?
                    .is_some(),
                active: row.try_get::<String, _>("status")? == "ACTIVE",
            })
        })
        .transpose()
    }

    pub async fn list_organization_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, IdentityRepositoryError> {
        if organization_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let rows = sqlx::query("SELECT user.id, user.email_normalized, user.display_name, membership.role, membership.status, membership.created_at FROM organization_memberships membership JOIN human_users user ON user.id = membership.user_id WHERE membership.organization_id = ? ORDER BY membership.created_at, user.email_normalized")
            .bind(organization_id).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(OrganizationMember {
                    user_id: row.try_get("id")?,
                    email: row.try_get("email_normalized")?,
                    display_name: row.try_get("display_name")?,
                    role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
                    active: row.try_get::<String, _>("status")? == "ACTIVE",
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn create_organization_invitation(
        &self,
        invitation: &OrganizationInvitation,
        token_hash: &[u8],
        invited_by: Uuid,
    ) -> Result<(), IdentityRepositoryError> {
        validate_email(&invitation.email)?;
        if invitation.id.is_nil()
            || invitation.organization_id.is_nil()
            || invited_by.is_nil()
            || token_hash.len() != 32
            || invitation.expires_at <= Utc::now()
            || invitation.role == MembershipRole::OrganizationOwner
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let already_member: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships membership JOIN human_users user ON user.id = membership.user_id WHERE membership.organization_id = ? AND user.email_normalized = ?)")
            .bind(invitation.organization_id).bind(&invitation.email).fetch_one(&mut *tx).await?;
        if already_member {
            return Err(IdentityRepositoryError::Conflict);
        }
        sqlx::query("UPDATE organization_invitations SET revoked_at = CURRENT_TIMESTAMP(6) WHERE organization_id = ? AND email_normalized = ? AND accepted_at IS NULL AND revoked_at IS NULL")
            .bind(invitation.organization_id).bind(&invitation.email).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO organization_invitations (id, organization_id, email_normalized, role, token_hash, invited_by_user_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(invitation.id).bind(invitation.organization_id).bind(&invitation.email)
            .bind(invitation.role.database_value()).bind(token_hash).bind(invited_by)
            .bind(invitation.expires_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn accept_organization_invitation(
        &self,
        user_id: Uuid,
        email: &str,
        token_hash: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Option<OrganizationInvitation>, IdentityRepositoryError> {
        validate_email(email)?;
        if user_id.is_nil() || token_hash.len() != 32 {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id, organization_id, email_normalized, role, expires_at FROM organization_invitations WHERE token_hash = ? AND email_normalized = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ? FOR UPDATE")
            .bind(token_hash).bind(email).bind(now).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let invitation = OrganizationInvitation {
            id: row.try_get("id")?,
            organization_id: row.try_get("organization_id")?,
            email: row.try_get("email_normalized")?,
            role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
            expires_at: row.try_get("expires_at")?,
        };
        let membership_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships WHERE organization_id = ? AND user_id = ?)")
            .bind(invitation.organization_id).bind(user_id).fetch_one(&mut *tx).await?;
        if membership_exists {
            return Err(IdentityRepositoryError::Conflict);
        }
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role, status) VALUES (?, ?, ?, 'ACTIVE')")
            .bind(invitation.organization_id).bind(user_id).bind(invitation.role.database_value()).execute(&mut *tx).await?;
        sqlx::query("UPDATE organization_invitations SET accepted_at = ? WHERE id = ?")
            .bind(now)
            .bind(invitation.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some(invitation))
    }

    pub async fn register_from_organization_invitation(
        &self,
        registration: &InvitedRegistrationWrite,
        token_hash: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Option<(HumanUser, Membership)>, IdentityRepositoryError> {
        if registration.user_id.is_nil()
            || !bounded(&registration.display_name, MAX_NAME_LEN)
            || registration.password_hash.is_empty()
            || registration.password_hash.len() > 255
            || token_hash.len() != 32
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT invitation.id, invitation.organization_id, invitation.email_normalized, invitation.role, invitation.expires_at, organization.name AS organization_name, tenant.id AS tenant_id, tenant.name AS tenant_name FROM organization_invitations invitation JOIN organizations organization ON organization.id = invitation.organization_id AND organization.status = 'ACTIVE' JOIN tenants tenant ON tenant.organization_id = organization.id AND tenant.status = 'ACTIVE' WHERE invitation.token_hash = ? AND invitation.accepted_at IS NULL AND invitation.revoked_at IS NULL AND invitation.expires_at > ? ORDER BY tenant.created_at LIMIT 1 FOR UPDATE")
            .bind(token_hash).bind(now).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let email: String = row.try_get("email_normalized")?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM human_users WHERE email_normalized = ?)",
        )
        .bind(&email)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            return Err(IdentityRepositoryError::Conflict);
        }
        sqlx::query("INSERT INTO human_users (id, email_normalized, display_name, password_hash, email_verified_at, status) VALUES (?, ?, ?, ?, ?, 'ACTIVE')")
            .bind(registration.user_id).bind(&email).bind(&registration.display_name)
            .bind(&registration.password_hash).bind(now).execute(&mut *tx).await?;
        let organization_id: Uuid = row.try_get("organization_id")?;
        let role = MembershipRole::parse(&row.try_get::<String, _>("role")?)?;
        sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role, status) VALUES (?, ?, ?, 'ACTIVE')")
            .bind(organization_id).bind(registration.user_id).bind(role.database_value()).execute(&mut *tx).await?;
        sqlx::query("UPDATE organization_invitations SET accepted_at = ? WHERE id = ?")
            .bind(now)
            .bind(row.try_get::<Uuid, _>("id")?)
            .execute(&mut *tx)
            .await?;
        let user = HumanUser {
            id: registration.user_id,
            email,
            display_name: registration.display_name.clone(),
            password_hash: registration.password_hash.clone(),
            verified: true,
            active: true,
        };
        let membership = Membership {
            organization_id,
            organization_name: row.try_get("organization_name")?,
            tenant_id: row.try_get("tenant_id")?,
            tenant_name: row.try_get("tenant_name")?,
            role,
        };
        tx.commit().await?;
        Ok(Some((user, membership)))
    }

    pub async fn revoke_organization_invitation(
        &self,
        invitation_id: Uuid,
        organization_id: Uuid,
    ) -> Result<(), IdentityRepositoryError> {
        if invitation_id.is_nil() || organization_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        sqlx::query("UPDATE organization_invitations SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP(6)) WHERE id = ? AND organization_id = ? AND accepted_at IS NULL")
            .bind(invitation_id).bind(organization_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn update_member_role_and_revoke_sessions(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        user_id: Uuid,
        role: MembershipRole,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if organization_id.is_nil()
            || actor_id.is_nil()
            || user_id.is_nil()
            || role == MembershipRole::OrganizationOwner
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE organization_memberships SET role = ? WHERE organization_id = ? AND user_id = ? AND role <> 'ORGANIZATION_OWNER'")
            .bind(role.database_value()).bind(organization_id).bind(user_id).execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            revoke_membership_sessions(&mut tx, organization_id, user_id, now).await?;
            append_identity_audit(
                &mut tx,
                organization_id,
                actor_id,
                "ORGANIZATION_MEMBER_ROLE_CHANGED",
                "ORGANIZATION_MEMBERSHIP",
                user_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn set_member_active_and_revoke_sessions(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        user_id: Uuid,
        active: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if organization_id.is_nil() || actor_id.is_nil() || user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE organization_memberships SET status = ? WHERE organization_id = ? AND user_id = ? AND role <> 'ORGANIZATION_OWNER'")
            .bind(if active { "ACTIVE" } else { "SUSPENDED" }).bind(organization_id).bind(user_id).execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            revoke_membership_sessions(&mut tx, organization_id, user_id, now).await?;
            append_identity_audit(
                &mut tx,
                organization_id,
                actor_id,
                if active {
                    "ORGANIZATION_MEMBER_REACTIVATED"
                } else {
                    "ORGANIZATION_MEMBER_SUSPENDED"
                },
                "ORGANIZATION_MEMBERSHIP",
                user_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn remove_member_and_revoke_sessions(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if organization_id.is_nil() || actor_id.is_nil() || user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("DELETE FROM organization_memberships WHERE organization_id = ? AND user_id = ? AND role <> 'ORGANIZATION_OWNER'")
            .bind(organization_id).bind(user_id).execute(&mut *tx).await?;
        if result.rows_affected() == 1 {
            revoke_membership_sessions(&mut tx, organization_id, user_id, now).await?;
            append_identity_audit(
                &mut tx,
                organization_id,
                actor_id,
                "ORGANIZATION_MEMBER_REMOVED",
                "ORGANIZATION_MEMBERSHIP",
                user_id,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn transfer_organization_ownership(
        &self,
        organization_id: Uuid,
        current_owner: Uuid,
        new_owner: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if organization_id.is_nil()
            || current_owner.is_nil()
            || new_owner.is_nil()
            || current_owner == new_owner
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let target = sqlx::query_scalar::<_, String>("SELECT role FROM organization_memberships WHERE organization_id = ? AND user_id = ? AND status = 'ACTIVE' FOR UPDATE")
            .bind(organization_id).bind(new_owner).fetch_optional(&mut *tx).await?;
        if target.is_none() {
            tx.commit().await?;
            return Ok(false);
        }
        let result = sqlx::query("UPDATE organization_memberships SET role = 'TENANT_ADMIN' WHERE organization_id = ? AND user_id = ? AND role = 'ORGANIZATION_OWNER'")
            .bind(organization_id).bind(current_owner).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("UPDATE organization_memberships SET role = 'ORGANIZATION_OWNER' WHERE organization_id = ? AND user_id = ?")
            .bind(organization_id).bind(new_owner).execute(&mut *tx).await?;
        revoke_membership_sessions(&mut tx, organization_id, current_owner, now).await?;
        revoke_membership_sessions(&mut tx, organization_id, new_owner, now).await?;
        append_identity_audit(
            &mut tx,
            organization_id,
            current_owner,
            "ORGANIZATION_OWNERSHIP_TRANSFERRED",
            "ORGANIZATION",
            organization_id,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn create_action_token(
        &self,
        id: Uuid,
        user_id: Uuid,
        purpose: ActionTokenPurpose,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> Result<(), IdentityRepositoryError> {
        if id.is_nil() || user_id.is_nil() || token_hash.len() != 32 || expires_at <= Utc::now() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        sqlx::query("UPDATE human_action_tokens SET consumed_at = CURRENT_TIMESTAMP(6) WHERE user_id = ? AND purpose = ? AND consumed_at IS NULL")
            .bind(user_id).bind(purpose.database_value()).execute(&self.pool).await?;
        sqlx::query("INSERT INTO human_action_tokens (id, user_id, purpose, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)")
            .bind(id).bind(user_id).bind(purpose.database_value()).bind(token_hash).bind(expires_at).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn consume_action_token(
        &self,
        purpose: ActionTokenPurpose,
        token_hash: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Option<Uuid>, IdentityRepositoryError> {
        if token_hash.len() != 32 {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let user_id = sqlx::query_scalar("SELECT user_id FROM human_action_tokens WHERE purpose = ? AND token_hash = ? AND consumed_at IS NULL AND expires_at > ? FOR UPDATE")
            .bind(purpose.database_value()).bind(token_hash).bind(now).fetch_optional(&mut *tx).await?;
        if user_id.is_some() {
            sqlx::query("UPDATE human_action_tokens SET consumed_at = ? WHERE purpose = ? AND token_hash = ? AND consumed_at IS NULL")
                .bind(now).bind(purpose.database_value()).bind(token_hash).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(user_id)
    }

    pub async fn mark_email_verified(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityRepositoryError> {
        sqlx::query("UPDATE human_users SET email_verified_at = COALESCE(email_verified_at, ?), status = 'ACTIVE' WHERE id = ?")
            .bind(now).bind(user_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn email_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Option<String>, IdentityRepositoryError> {
        if user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        Ok(
            sqlx::query_scalar("SELECT email_normalized FROM human_users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Removes a registration that could not dispatch its verification email. No session can
    /// exist at this point; the operation is tenant-scoped and runs in reverse FK order.
    pub async fn rollback_pending_registration(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<(), IdentityRepositoryError> {
        if user_id.is_nil() || organization_id.is_nil() || tenant_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM human_action_tokens WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM organization_memberships WHERE organization_id = ? AND user_id = ?",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM tenants WHERE id = ? AND organization_id = ?")
            .bind(tenant_id)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM organizations WHERE id = ?")
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM human_users WHERE id = ? AND status = 'PENDING_VERIFICATION'")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn update_password_and_revoke_sessions(
        &self,
        user_id: Uuid,
        password_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityRepositoryError> {
        if user_id.is_nil() || password_hash.is_empty() || password_hash.len() > 255 {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE human_users SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE human_sessions SET revoked_at = ?, revoke_reason = 'PASSWORD_RESET' WHERE user_id = ? AND revoked_at IS NULL")
            .bind(now).bind(user_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        session: &SessionRecord,
        token_id: Uuid,
        token_hash: &[u8],
        token_expires_at: DateTime<Utc>,
        device_label: Option<&str>,
    ) -> Result<(), IdentityRepositoryError> {
        if session.id.is_nil()
            || session.family_id.is_nil()
            || session.user_id.is_nil()
            || session.organization_id.is_nil()
            || session.tenant_id.is_nil()
            || token_id.is_nil()
            || token_hash.len() != 32
            || session.expires_at <= Utc::now()
            || token_expires_at > session.expires_at
            || device_label.is_some_and(|label| !bounded(label, MAX_DEVICE_LABEL_LEN))
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO human_sessions (id, user_id, session_family_id, organization_id, tenant_id, device_label, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(session.id).bind(session.user_id).bind(session.family_id).bind(session.organization_id).bind(session.tenant_id).bind(device_label).bind(session.expires_at).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO human_refresh_tokens (id, session_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
            .bind(token_id).bind(session.id).bind(token_hash).bind(token_expires_at).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn replace_context_session(
        &self,
        replacement: ContextSessionReplacement<'_>,
    ) -> Result<(), IdentityRepositoryError> {
        let ContextSessionReplacement {
            previous_session_id,
            session,
            token_id,
            token_hash,
            token_expires_at,
            device_label,
            now,
        } = replacement;
        if previous_session_id.is_nil()
            || session.id.is_nil()
            || session.family_id.is_nil()
            || session.user_id.is_nil()
            || session.organization_id.is_nil()
            || session.tenant_id.is_nil()
            || token_id.is_nil()
            || token_hash.len() != 32
            || session.expires_at <= now
            || token_expires_at > session.expires_at
            || device_label.is_some_and(|label| !bounded(label, MAX_DEVICE_LABEL_LEN))
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let previous: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM human_sessions WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?) FOR UPDATE")
            .bind(previous_session_id).bind(session.user_id).bind(now).fetch_one(&mut *tx).await?;
        if !previous {
            return Err(IdentityRepositoryError::Conflict);
        }
        sqlx::query("INSERT INTO human_sessions (id, user_id, session_family_id, organization_id, tenant_id, device_label, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(session.id).bind(session.user_id).bind(session.family_id).bind(session.organization_id).bind(session.tenant_id).bind(device_label).bind(session.expires_at).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO human_refresh_tokens (id, session_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
            .bind(token_id).bind(session.id).bind(token_hash).bind(token_expires_at).execute(&mut *tx).await?;
        sqlx::query("UPDATE human_sessions SET revoked_at = ?, revoke_reason = 'USER' WHERE id = ? AND revoked_at IS NULL")
            .bind(now).bind(previous_session_id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn rotate_refresh_token(
        &self,
        token_hash: &[u8],
        replacement_id: Uuid,
        replacement_hash: &[u8],
        replacement_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Option<SessionRecord>, IdentityRepositoryError> {
        if token_hash.len() != 32
            || replacement_hash.len() != 32
            || replacement_id.is_nil()
            || replacement_expires_at <= now
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let mut tx = self.pool.begin().await?;
        let token = sqlx::query("SELECT refresh.id, refresh.session_id, refresh.expires_at, refresh.used_at, refresh.revoked_at, session.user_id, session.session_family_id, session.organization_id, session.tenant_id, session.expires_at AS session_expires_at, session.revoked_at AS session_revoked_at, membership.role FROM human_refresh_tokens refresh JOIN human_sessions session ON session.id = refresh.session_id JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id AND membership.status = 'ACTIVE' WHERE refresh.token_hash = ? FOR UPDATE")
            .bind(token_hash).fetch_optional(&mut *tx).await?;
        let Some(token) = token else {
            tx.commit().await?;
            return Ok(None);
        };
        let session_id: Uuid = token.try_get("session_id")?;
        let family_id: Uuid = token.try_get("session_family_id")?;
        let invalid = token
            .try_get::<Option<DateTime<Utc>>, _>("used_at")?
            .is_some()
            || token
                .try_get::<Option<DateTime<Utc>>, _>("revoked_at")?
                .is_some()
            || token
                .try_get::<Option<DateTime<Utc>>, _>("session_revoked_at")?
                .is_some()
            || token.try_get::<DateTime<Utc>, _>("expires_at")? <= now
            || token.try_get::<DateTime<Utc>, _>("session_expires_at")? <= now;
        if invalid {
            sqlx::query("UPDATE human_sessions SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = 'ROTATION_REUSE' WHERE session_family_id = ? AND revoked_at IS NULL")
                .bind(now).bind(family_id).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let token_id: Uuid = token.try_get("id")?;
        let refresh_expires_at = replacement_expires_at.min(token.try_get("session_expires_at")?);
        sqlx::query("INSERT INTO human_refresh_tokens (id, session_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
            .bind(replacement_id).bind(session_id).bind(replacement_hash).bind(refresh_expires_at).execute(&mut *tx).await?;
        let rotation = sqlx::query("UPDATE human_refresh_tokens SET used_at = ?, replaced_by_id = ? WHERE id = ? AND used_at IS NULL")
            .bind(now).bind(replacement_id).bind(token_id).execute(&mut *tx).await?;
        if rotation.rows_affected() != 1 {
            return Err(IdentityRepositoryError::Conflict);
        }
        sqlx::query("UPDATE human_sessions SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        let record = SessionRecord {
            id: session_id,
            family_id,
            user_id: token.try_get("user_id")?,
            organization_id: token.try_get("organization_id")?,
            tenant_id: token.try_get("tenant_id")?,
            role: MembershipRole::parse(&token.try_get::<String, _>("role")?)?,
            expires_at: token.try_get("session_expires_at")?,
            revoked_at: None,
        };
        tx.commit().await?;
        Ok(Some(record))
    }

    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if user_id.is_nil() || session_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let result = sqlx::query("UPDATE human_sessions SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = 'USER' WHERE id = ? AND user_id = ?")
            .bind(now).bind(session_id).bind(user_id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn revoke_current_session(
        &self,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), IdentityRepositoryError> {
        sqlx::query("UPDATE human_sessions SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = 'LOGOUT' WHERE id = ?")
            .bind(now).bind(session_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn list_sessions(
        &self,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Vec<SessionRecord>, IdentityRepositoryError> {
        if user_id.is_nil() {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let rows = sqlx::query("SELECT session.id, session.session_family_id, session.user_id, session.organization_id, session.tenant_id, session.expires_at, session.revoked_at, membership.role FROM human_sessions session JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id AND membership.status = 'ACTIVE' WHERE session.user_id = ? AND session.expires_at > ? ORDER BY session.last_seen_at DESC")
            .bind(user_id).bind(now).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(SessionRecord {
                    id: row.try_get("id")?,
                    family_id: row.try_get("session_family_id")?,
                    user_id: row.try_get("user_id")?,
                    organization_id: row.try_get("organization_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    role: MembershipRole::parse(&row.try_get::<String, _>("role")?)?,
                    expires_at: row.try_get("expires_at")?,
                    revoked_at: row.try_get("revoked_at")?,
                })
            })
            .collect()
    }

    /// Confirms that a short-lived access token still maps to an active user, membership, and
    /// unrevoked session. This keeps Identity's own security endpoints immediately revocable.
    pub async fn session_is_active(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        organization_id: Uuid,
        tenant_id: Uuid,
        role: MembershipRole,
        now: DateTime<Utc>,
    ) -> Result<bool, IdentityRepositoryError> {
        if session_id.is_nil() || user_id.is_nil() || organization_id.is_nil() || tenant_id.is_nil()
        {
            return Err(IdentityRepositoryError::InvalidInput);
        }
        let found: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM human_sessions session JOIN human_users user ON user.id = session.user_id AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id AND membership.role = ? AND membership.status = 'ACTIVE' JOIN tenants tenant ON tenant.id = session.tenant_id AND tenant.organization_id = session.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = session.organization_id AND organization.status = 'ACTIVE' WHERE session.id = ? AND session.user_id = ? AND session.organization_id = ? AND session.tenant_id = ? AND session.revoked_at IS NULL AND session.expires_at > ?)",
        )
        .bind(role.database_value())
        .bind(session_id)
        .bind(user_id)
        .bind(organization_id)
        .bind(tenant_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(found)
    }
}

async fn revoke_membership_sessions(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    organization_id: Uuid,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE human_sessions SET revoked_at = COALESCE(revoked_at, ?), revoke_reason = 'ADMIN' WHERE organization_id = ? AND user_id = ? AND revoked_at IS NULL")
        .bind(now).bind(organization_id).bind(user_id).execute(&mut **tx).await?;
    Ok(())
}

async fn append_identity_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    organization_id: Uuid,
    actor_id: Uuid,
    action: &'static str,
    object_type: &'static str,
    object_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_events (id, organization_id, tenant_id, actor_type, actor_id, action, object_type, object_id, metadata_json) VALUES (?, ?, NULL, 'USER', ?, ?, ?, ?, JSON_OBJECT())")
        .bind(Uuid::now_v7()).bind(organization_id).bind(actor_id.to_string())
        .bind(action).bind(object_type).bind(object_id.to_string()).execute(&mut **tx).await?;
    Ok(())
}

fn validate_email(email: &str) -> Result<(), IdentityRepositoryError> {
    if !bounded(email, MAX_EMAIL_LEN)
        || email != email.trim()
        || email != email.to_ascii_lowercase()
        || email.contains(['\r', '\n'])
        || !email.contains('@')
    {
        Err(IdentityRepositoryError::InvalidInput)
    } else {
        Ok(())
    }
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_noncanonical_email_at_the_repository_boundary() {
        assert!(validate_email("User@Example.test").is_err());
        assert!(validate_email("user@example.test").is_ok());
    }
    #[test]
    fn membership_roles_are_strict() {
        assert_eq!(
            MembershipRole::parse("ORGANIZATION_OWNER").unwrap(),
            MembershipRole::OrganizationOwner
        );
        assert!(MembershipRole::parse("root").is_err());
    }
}
