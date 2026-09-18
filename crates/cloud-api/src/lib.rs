pub mod auth;
pub mod client_api;
pub mod client_issuance;
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
        client_access: None,
        client_control: None,
        client_routing: None,
        client_grant: None,
        enrollment: None,
        authentication_ready: false,
    }))
}

pub fn app_with_repository(repository: ControlRepository) -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: Some(repository),
        client_access: None,
        client_control: None,
        client_routing: None,
        client_grant: None,
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
        client_access: None,
        client_control: None,
        client_routing: None,
        client_grant: None,
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
    app_with_authentication_and_enrollment_and_client_access(
        repository,
        enrollment,
        None,
        authenticator,
    )
}

pub fn app_with_authentication_and_enrollment_and_client_access(
    repository: ControlRepository,
    enrollment: cloud_db::enrollment::EnrollmentRepository,
    client_access: Option<cloud_db::client_access::ClientAccessPolicyRepository>,
    authenticator: ManagementAuthenticator,
) -> Router {
    app_with_authentication_and_terminal_client_plane(
        repository,
        enrollment,
        client_access,
        None,
        None,
        None,
        authenticator,
    )
}

/// Full terminal client plane. The client control, routing, and signing
/// capabilities are all optional so a deployment can run the management API
/// without terminal Grant issuance; when any of them is absent the terminal
/// routes answer `503` instead of failing open.
pub fn app_with_authentication_and_terminal_client_plane(
    repository: ControlRepository,
    enrollment: cloud_db::enrollment::EnrollmentRepository,
    client_access: Option<cloud_db::client_access::ClientAccessPolicyRepository>,
    client_control: Option<cloud_db::client_control::ClientControlRepository>,
    client_routing: Option<cloud_db::client_routing::ClientNodeRepository>,
    client_grant: Option<cloud_client_grant::ClientGrantSigner>,
    authenticator: ManagementAuthenticator,
) -> Router {
    let state = Arc::new(ManagementState {
        repository: Some(repository),
        client_access,
        client_control,
        client_routing,
        client_grant,
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
        client_access: None,
        client_control: None,
        client_routing: None,
        client_grant: None,
        enrollment: None,
        authentication_ready: true,
    }))
    .layer(Extension(principal))
}

/// Injects an already-authenticated principal into the *full* terminal client
/// plane, so route tests can exercise registration and Grant issuance without a
/// live identity service. Production code always reaches these handlers through
/// `require_management_principal`, which is what builds the principal from a
/// verified session; this constructor exists only so tests can prove the handler
/// logic (including which failures happen before storage is touched) in isolation.
pub fn app_with_terminal_client_plane_and_principal(
    repository: ControlRepository,
    client_access: Option<cloud_db::client_access::ClientAccessPolicyRepository>,
    client_control: Option<cloud_db::client_control::ClientControlRepository>,
    client_routing: Option<cloud_db::client_routing::ClientNodeRepository>,
    client_grant: Option<cloud_client_grant::ClientGrantSigner>,
    principal: AuthenticatedPrincipal,
) -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: Some(repository),
        client_access,
        client_control,
        client_routing,
        client_grant,
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
        .route("/version", get(health::version))
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .route("/health/degraded", get(health::degraded))
}

fn management_routes() -> Router<Arc<ManagementState>> {
    Router::new()
        // Terminal client routes are session-scoped and carry no tenant in the
        // path. They must be registered before the `/v1/tenants/{tenant_id}/...`
        // catch-alls, otherwise `client` would be parsed as a tenant id.
        .route(
            "/v1/client/devices",
            axum::routing::post(client_api::register_client_device),
        )
        .route(
            "/v1/client/devices/{device_id}/grant",
            axum::routing::post(client_api::issue_client_grant),
        )
        .route(
            "/v1/tenants/{tenant_id}/nodes/{node_id}/upgrades",
            get(management::node_upgrades).post(management::create_node_upgrade),
        )
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
            "/v1/tenants/{tenant_id}/runtime-configuration-status",
            get(management::runtime_configuration_statuses),
        )
        .route(
            "/v1/tenants/{tenant_id}/runtime-telemetry",
            get(management::runtime_telemetry),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-access-policies",
            axum::routing::post(management::create_client_access_policy),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-access-policy-bindings",
            axum::routing::post(management::bind_client_access_policy),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-users/{user_id}/client-devices/{client_device_id}/access-policy",
            get(management::get_client_access_policy),
        )
        .route(
            "/v1/tenants/{tenant_id}/audit-events",
            get(management::audit_events),
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
        .route(
            "/v1/tenants/{tenant_id}/{collection}/{id}/references",
            get(management::references),
        )
}
