use axum::{http::StatusCode, response::IntoResponse};

pub async fn live() -> &'static str { "ok" }

pub async fn ready() -> impl IntoResponse {
    match std::env::var("DATABASE_URL") {
        Ok(url) => match cloud_db::connect(&url).await {
            Ok(pool) if sqlx::query("SELECT 1").execute(&pool).await.is_ok() => (StatusCode::OK, "ready"),
            _ => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
        },
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database not configured"),
    }
}

pub async fn degraded() -> (StatusCode, &'static str) {
    (StatusCode::SERVICE_UNAVAILABLE, "degraded")
}
