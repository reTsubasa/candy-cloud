use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse};

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
