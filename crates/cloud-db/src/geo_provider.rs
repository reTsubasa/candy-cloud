use crate::DbPool;
use serde::{Deserialize, Serialize};
use sqlx::{MySql, Row, Transaction};
use uuid::Uuid;

pub const OPENWRT_CIDR_PROVIDER: &str = "openwrt-cidr-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoProviderSettings {
    pub provider: String,
    pub source_url: String,
    pub countries: Vec<String>,
    pub refresh_interval_seconds: u32,
    pub enabled: bool,
    pub version: Option<String>,
    pub digest: Option<String>,
    pub generation: u64,
    pub updated_at: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GeoProviderError {
    #[error("invalid Geo provider settings")]
    Invalid,
    #[error("invalid scope")]
    Scope,
    #[error("generation conflict")]
    Conflict,
    #[error("storage unavailable")]
    Storage,
}

impl GeoProviderSettings {
    pub fn validate(&self) -> Result<(), GeoProviderError> {
        if self.provider != OPENWRT_CIDR_PROVIDER
            || self.source_url.len() > 2048
            || !self.source_url.starts_with("https://")
            || self.countries.is_empty()
            || self.countries.len() > 256
            || self.refresh_interval_seconds < 300
            || self.refresh_interval_seconds > 2_592_000
            || self.generation == 0
            || self
                .version
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 64)
        {
            return Err(GeoProviderError::Invalid);
        }
        if self
            .countries
            .iter()
            .any(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()))
            || self
                .countries
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.countries.len()
        {
            return Err(GeoProviderError::Invalid);
        }
        if self
            .digest
            .as_ref()
            .is_some_and(|d| d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(GeoProviderError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(countries: Vec<&str>) -> GeoProviderSettings {
        GeoProviderSettings {
            provider: OPENWRT_CIDR_PROVIDER.into(),
            source_url: "https://example.test/geo".into(),
            countries: countries.into_iter().map(str::to_owned).collect(),
            refresh_interval_seconds: 86_400,
            enabled: true,
            version: None,
            digest: None,
            generation: 1,
            updated_at: String::new(),
        }
    }

    #[test]
    fn provider_scope_requires_unique_uppercase_iso_codes() {
        assert!(settings(vec!["CN", "US"]).validate().is_ok());
        assert!(matches!(
            settings(vec!["cn"]).validate(),
            Err(GeoProviderError::Invalid)
        ));
        assert!(matches!(
            settings(vec!["CN", "CN"]).validate(),
            Err(GeoProviderError::Invalid)
        ));
    }
}

#[derive(Clone)]
pub struct GeoProviderRepository {
    pool: DbPool,
}
impl GeoProviderRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn get(&self) -> Result<Option<GeoProviderSettings>, GeoProviderError> {
        let row = sqlx::query("SELECT provider, source_url, countries_json, refresh_interval_seconds, enabled, version, digest, generation, updated_at FROM geo_provider_platform_settings WHERE id = 1")
            .fetch_optional(&self.pool).await.map_err(|_| GeoProviderError::Storage)?;
        row.map(|r| {
            let countries: String = r
                .try_get("countries_json")
                .map_err(|_| GeoProviderError::Storage)?;
            let updated_at: chrono::DateTime<chrono::Utc> = r
                .try_get("updated_at")
                .map_err(|_| GeoProviderError::Storage)?;
            Ok(GeoProviderSettings {
                provider: r
                    .try_get("provider")
                    .map_err(|_| GeoProviderError::Storage)?,
                source_url: r
                    .try_get("source_url")
                    .map_err(|_| GeoProviderError::Storage)?,
                countries: serde_json::from_str(&countries)
                    .map_err(|_| GeoProviderError::Storage)?,
                refresh_interval_seconds: r
                    .try_get("refresh_interval_seconds")
                    .map_err(|_| GeoProviderError::Storage)?,
                enabled: r
                    .try_get("enabled")
                    .map_err(|_| GeoProviderError::Storage)?,
                version: r
                    .try_get("version")
                    .map_err(|_| GeoProviderError::Storage)?,
                digest: r.try_get("digest").map_err(|_| GeoProviderError::Storage)?,
                generation: r
                    .try_get("generation")
                    .map_err(|_| GeoProviderError::Storage)?,
                updated_at: updated_at.to_rfc3339(),
            })
        })
        .transpose()
    }
    pub async fn put(
        &self,
        settings: &GeoProviderSettings,
        actor_id: Uuid,
    ) -> Result<(), GeoProviderError> {
        settings.validate()?;
        if actor_id.is_nil() {
            return Err(GeoProviderError::Scope);
        }
        let json =
            serde_json::to_string(&settings.countries).map_err(|_| GeoProviderError::Invalid)?;
        let mut tx: Transaction<'_, MySql> = self
            .pool
            .begin()
            .await
            .map_err(|_| GeoProviderError::Storage)?;
        let existing: Option<u64> = sqlx::query_scalar(
            "SELECT generation FROM geo_provider_platform_settings WHERE id = 1 FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| GeoProviderError::Storage)?;
        match existing {
            Some(generation) if settings.generation != generation.saturating_add(1) => {
                return Err(GeoProviderError::Conflict)
            }
            None if settings.generation != 1 => return Err(GeoProviderError::Conflict),
            _ => {}
        }
        sqlx::query("INSERT INTO geo_provider_platform_settings (id, provider, source_url, countries_json, refresh_interval_seconds, enabled, version, digest, generation, updated_by) VALUES (1, ?, ?, CAST(? AS JSON), ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE provider=VALUES(provider), source_url=VALUES(source_url), countries_json=VALUES(countries_json), refresh_interval_seconds=VALUES(refresh_interval_seconds), enabled=VALUES(enabled), version=VALUES(version), digest=VALUES(digest), generation=VALUES(generation), updated_by=VALUES(updated_by)")
            .bind(&settings.provider).bind(&settings.source_url).bind(json).bind(settings.refresh_interval_seconds).bind(settings.enabled).bind(&settings.version).bind(&settings.digest).bind(settings.generation).bind(actor_id).execute(&mut *tx).await.map_err(|_| GeoProviderError::Storage)?;
        tx.commit().await.map_err(|_| GeoProviderError::Storage)?;
        Ok(())
    }
}
