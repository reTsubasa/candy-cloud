use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

use crate::management::ManagementState;

pub async fn live() -> &'static str {
    "ok"
}

pub async fn ready(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    if !state.authentication_ready {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "management authentication unavailable",
        );
    }
    match &state.repository {
        Some(repository) if repository.readiness_check().await.is_ok() => (StatusCode::OK, "ready"),
        Some(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "database schema unavailable",
        ),
        None => (StatusCode::SERVICE_UNAVAILABLE, "database not configured"),
    }
}

pub async fn degraded() -> (StatusCode, &'static str) {
    (StatusCode::SERVICE_UNAVAILABLE, "degraded")
}

#[derive(Debug, Serialize)]
pub struct VersionInfo {
    schema_version: u8,
    cloud_version: &'static str,
    cloud_revision: String,
    core_version: String,
}

pub async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        schema_version: 1,
        cloud_version: env!("CARGO_PKG_VERSION"),
        cloud_revision: std::env::var("CANDY_CLOUD_REVISION")
            .unwrap_or_else(|_| "development".to_owned()),
        core_version: std::env::var("CANDY_CORE_VERSION")
            .unwrap_or_else(|_| "unavailable".to_owned()),
    })
}
