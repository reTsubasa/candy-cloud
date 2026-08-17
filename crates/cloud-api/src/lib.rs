pub mod auth;
pub mod domain;
pub mod health;
pub mod management;

use std::sync::Arc;

use auth::ManagementAuthenticator;
use axum::{middleware, routing::get, Extension, Router};
use cloud_db::control::ControlRepository;
use management::{AuthenticatedPrincipal, ManagementState};

pub fn app() -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: None,
        enrollment: None,
        authentication_ready: false,
    }))
}

pub fn app_with_repository(repository: ControlRepository) -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: Some(repository),
        enrollment: None,
        authentication_ready: false,
    }))
}

pub fn app_with_authentication(
    repository: ControlRepository,
    authenticator: ManagementAuthenticator,
) -> Router {
    let state = Arc::new(ManagementState {
        repository: Some(repository),
        enrollment: None,
        authentication_ready: true,
    });
    health_routes()
        .merge(
            management_routes().route_layer(middleware::from_fn_with_state(
                Arc::new(authenticator),
                auth::require_management_principal,
            )),
        )
        .with_state(state)
}

pub fn app_with_authentication_and_enrollment(
    repository: ControlRepository,
    enrollment: cloud_db::enrollment::EnrollmentRepository,
    authenticator: ManagementAuthenticator,
) -> Router {
    let state = Arc::new(ManagementState {
        repository: Some(repository),
        enrollment: Some(enrollment),
        authentication_ready: true,
    });
    health_routes()
        .merge(
            management_routes().route_layer(middleware::from_fn_with_state(
                Arc::new(authenticator),
                auth::require_management_principal,
            )),
        )
        .with_state(state)
}

pub fn app_with_principal(
    repository: ControlRepository,
    principal: AuthenticatedPrincipal,
) -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: Some(repository),
        enrollment: None,
        authentication_ready: true,
    }))
    .layer(Extension(principal))
}

fn app_with_state(state: Arc<ManagementState>) -> Router {
    health_routes().merge(management_routes()).with_state(state)
}

fn health_routes() -> Router<Arc<ManagementState>> {
    Router::new()
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/health/degraded", get(health::degraded))
}

fn management_routes() -> Router<Arc<ManagementState>> {
    Router::new()
        .route(
            "/v1/tenants/{tenant_id}/enrollment/activations",
            get(management::list_activations).post(management::create_activation),
        )
        .route(
            "/v1/tenants/{tenant_id}/enrollment/activations/{activation_id}",
            axum::routing::delete(management::revoke_activation),
        )
        .route(
            "/v1/tenants/{tenant_id}/runtime-activation-readiness",
            get(management::runtime_activation_readiness),
        )
        .route(
            "/v1/tenants/{tenant_id}/{collection}",
            get(management::list).post(management::create),
        )
        .route(
            "/v1/tenants/{tenant_id}/{collection}/{id}",
            get(management::get)
                .put(management::replace)
                .delete(management::delete),
        )
}
