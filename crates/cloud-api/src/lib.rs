pub mod domain;
pub mod health;

use axum::{routing::get, Router};

pub fn app() -> Router {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/health/degraded", get(health::degraded))
}
