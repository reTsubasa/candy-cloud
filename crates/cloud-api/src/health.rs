use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

use crate::management::ManagementState;

pub async fn live() -> &'static str {
    "ok"
}

pub async fn ready(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    match dependency_status(&state).await {
        Ok(()) => (StatusCode::OK, "ready"),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, reason),
    }
}

pub async fn degraded(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    match dependency_status(&state).await {
        Ok(()) => (StatusCode::OK, "not degraded"),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, reason),
    }
}

async fn dependency_status(state: &ManagementState) -> Result<(), &'static str> {
    if !state.authentication_ready {
        return Err("management authentication unavailable");
    }
    match &state.repository {
        Some(repository) if repository.readiness_check().await.is_ok() => Ok(()),
        Some(_) => Err("database schema unavailable"),
        None => Err("database not configured"),
    }
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
