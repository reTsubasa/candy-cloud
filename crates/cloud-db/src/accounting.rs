use chrono::{DateTime, Utc};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

use crate::DbPool;

const MAX_IDEMPOTENCY_KEY_LEN: usize = 160;

#[derive(Debug, Error)]
pub enum AccountingError {
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("invalid accounting scope")]
    InvalidScope,
    #[error("accounting idempotency key conflicts with an existing record")]
    IdempotencyConflict,
    #[error("accounting session is not open")]
    SessionClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingTrustLevel {
    CustomerReported,
    TrustedCandy,
}

impl AccountingTrustLevel {
    fn database_value(self) -> &'static str {
        match self {
            Self::CustomerReported => "CUSTOMER_REPORTED",
            Self::TrustedCandy => "TRUSTED_CANDY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingSessionWrite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub device_id: Option<Uuid>,
    pub node_id: Option<Uuid>,
    pub trust_level: AccountingTrustLevel,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingRecordWrite {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub idempotency_key: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingRecordOutcome {
    Inserted,
    Replayed { id: Uuid },
}

#[derive(Clone)]
pub struct AccountingRepository {
    pool: DbPool,
}

impl AccountingRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn open_session(
        &self,
        session: &AccountingSessionWrite,
    ) -> Result<(), AccountingError> {
        validate_session(session)?;
        sqlx::query(
            "INSERT INTO accounting_sessions (id, tenant_id, device_id, node_id, trust_level, started_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id)
        .bind(session.tenant_id)
        .bind(session.device_id)
        .bind(session.node_id)
        .bind(session.trust_level.database_value())
        .bind(session.started_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn close_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        ended_at: DateTime<Utc>,
    ) -> Result<(), AccountingError> {
        if tenant_id.is_nil() || session_id.is_nil() {
            return Err(AccountingError::InvalidScope);
        }
        let result = sqlx::query(
            "UPDATE accounting_sessions SET ended_at = ? WHERE tenant_id = ? AND id = ? AND ended_at IS NULL AND started_at <= ?",
        )
        .bind(ended_at)
        .bind(tenant_id)
        .bind(session_id)
        .bind(ended_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(AccountingError::SessionClosed);
        }
        Ok(())
    }

    pub async fn record(
        &self,
        record: &AccountingRecordWrite,
    ) -> Result<AccountingRecordOutcome, AccountingError> {
        validate_record(record)?;
        let mut transaction = self.pool.begin().await?;
        let session_started_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT started_at FROM accounting_sessions WHERE tenant_id = ? AND id = ? AND ended_at IS NULL FOR SHARE",
        )
        .bind(record.tenant_id)
        .bind(record.session_id)
        .fetch_one(&mut *transaction)
        .await?;
        let Some(session_started_at) = session_started_at else {
            return Err(AccountingError::SessionClosed);
        };
        if record.recorded_at < session_started_at
            || record.recorded_at > Utc::now() + chrono::Duration::minutes(5)
        {
            return Err(AccountingError::InvalidScope);
        }
        let existing = sqlx::query(
            "SELECT id, session_id, bytes_up, bytes_down, recorded_at FROM accounting_records WHERE tenant_id = ? AND idempotency_key = ? FOR UPDATE",
        )
        .bind(record.tenant_id)
        .bind(&record.idempotency_key)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let id: Uuid = existing.try_get("id")?;
            let same = id == record.id
                && existing.try_get::<Uuid, _>("session_id")? == record.session_id
                && existing.try_get::<u64, _>("bytes_up")? == record.bytes_up
                && existing.try_get::<u64, _>("bytes_down")? == record.bytes_down
                && existing.try_get::<DateTime<Utc>, _>("recorded_at")? == record.recorded_at;
            transaction.commit().await?;
            return if same {
                Ok(AccountingRecordOutcome::Replayed { id })
            } else {
                Err(AccountingError::IdempotencyConflict)
            };
        }
        sqlx::query(
            "INSERT INTO accounting_records (id, tenant_id, session_id, idempotency_key, bytes_up, bytes_down, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.id)
        .bind(record.tenant_id)
        .bind(record.session_id)
        .bind(&record.idempotency_key)
        .bind(record.bytes_up)
        .bind(record.bytes_down)
        .bind(record.recorded_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(AccountingRecordOutcome::Inserted)
    }
}

fn validate_session(session: &AccountingSessionWrite) -> Result<(), AccountingError> {
    let valid_principal = match session.trust_level {
        AccountingTrustLevel::CustomerReported => {
            session.device_id.is_some() && session.node_id.is_none()
        }
        AccountingTrustLevel::TrustedCandy => {
            session.node_id.is_some() && session.device_id.is_none()
        }
    };
    if session.id.is_nil()
        || session.tenant_id.is_nil()
        || session.device_id.is_some_and(|id| id.is_nil())
        || session.node_id.is_some_and(|id| id.is_nil())
        || !valid_principal
    {
        Err(AccountingError::InvalidScope)
    } else {
        Ok(())
    }
}

fn validate_record(record: &AccountingRecordWrite) -> Result<(), AccountingError> {
    if record.id.is_nil()
        || record.tenant_id.is_nil()
        || record.session_id.is_nil()
        || record.idempotency_key.is_empty()
        || record.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_LEN
    {
        Err(AccountingError::InvalidScope)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounting_scope_is_bounded_before_database_access() {
        let record = AccountingRecordWrite {
            id: Uuid::nil(),
            tenant_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            idempotency_key: "event-1".into(),
            bytes_up: 1,
            bytes_down: 2,
            recorded_at: Utc::now(),
        };
        assert!(matches!(
            validate_record(&record),
            Err(AccountingError::InvalidScope)
        ));
    }
}
