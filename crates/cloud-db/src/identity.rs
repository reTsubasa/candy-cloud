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

#[derive(Debug, Clone)]
pub struct Membership {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub role: MembershipRole,
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
        let row = sqlx::query("SELECT membership.organization_id, organization.name AS organization_name, tenant.id AS tenant_id, tenant.name AS tenant_name, membership.role FROM organization_memberships membership JOIN tenants tenant ON tenant.organization_id = membership.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = membership.organization_id AND organization.status = 'ACTIVE' WHERE membership.user_id = ? ORDER BY membership.created_at, tenant.created_at LIMIT 1")
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
        let token = sqlx::query("SELECT refresh.id, refresh.session_id, refresh.expires_at, refresh.used_at, refresh.revoked_at, session.user_id, session.session_family_id, session.organization_id, session.tenant_id, session.expires_at AS session_expires_at, session.revoked_at AS session_revoked_at, membership.role FROM human_refresh_tokens refresh JOIN human_sessions session ON session.id = refresh.session_id JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id WHERE refresh.token_hash = ? FOR UPDATE")
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
        sqlx::query("UPDATE human_refresh_tokens SET used_at = ?, replaced_by_id = ? WHERE id = ? AND used_at IS NULL")
            .bind(now).bind(replacement_id).bind(token_id).execute(&mut *tx).await?;
        let refresh_expires_at = replacement_expires_at.min(token.try_get("session_expires_at")?);
        sqlx::query("INSERT INTO human_refresh_tokens (id, session_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
            .bind(replacement_id).bind(session_id).bind(replacement_hash).bind(refresh_expires_at).execute(&mut *tx).await?;
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
        let rows = sqlx::query("SELECT session.id, session.session_family_id, session.user_id, session.organization_id, session.tenant_id, session.expires_at, session.revoked_at, membership.role FROM human_sessions session JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id WHERE session.user_id = ? AND session.expires_at > ? ORDER BY session.last_seen_at DESC")
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
            "SELECT EXISTS(SELECT 1 FROM human_sessions session JOIN human_users user ON user.id = session.user_id AND user.status = 'ACTIVE' JOIN organization_memberships membership ON membership.organization_id = session.organization_id AND membership.user_id = session.user_id AND membership.role = ? JOIN tenants tenant ON tenant.id = session.tenant_id AND tenant.organization_id = session.organization_id AND tenant.status = 'ACTIVE' JOIN organizations organization ON organization.id = session.organization_id AND organization.status = 'ACTIVE' WHERE session.id = ? AND session.user_id = ? AND session.organization_id = ? AND session.tenant_id = ? AND session.revoked_at IS NULL AND session.expires_at > ?)",
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
