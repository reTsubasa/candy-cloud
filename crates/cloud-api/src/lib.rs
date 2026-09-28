pub mod auth;
pub mod client_api;
pub mod client_issuance;
pub mod client_projection;
pub mod client_projection_api;
pub mod domain;
pub mod health;
pub mod management;

use std::sync::Arc;

use auth::ManagementAuthenticator;
use axum::{
    middleware,
    routing::{any, get},
    Extension, Router,
};
use cloud_db::control::ControlRepository;
use management::{AuthenticatedPrincipal, ManagementState};

pub fn app() -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: None,
        client_access: None,
        client_control: None,
        client_routing: None,
        client_grant: None,
        client_projection: None,
        client_settings: None,
        client_projection_signer: None,
        geo_provider: None,
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
        client_projection: None,
        client_settings: None,
        client_projection_signer: None,
        geo_provider: None,
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
        client_projection: None,
        client_settings: None,
        client_projection_signer: None,
        geo_provider: None,
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
        TerminalClientPlane {
            access: client_access,
            ..TerminalClientPlane::default()
        },
        authenticator,
    )
}

/// Everything the terminal client plane needs beyond the control-plane
/// repository, grouped so adding a capability does not keep widening the
/// constructor signatures. Every field is optional: an absent capability makes
/// its routes answer `503` instead of failing open.
#[derive(Clone, Default)]
pub struct TerminalClientPlane {
    pub access: Option<cloud_db::client_access::ClientAccessPolicyRepository>,
    pub control: Option<cloud_db::client_control::ClientControlRepository>,
    pub routing: Option<cloud_db::client_routing::ClientNodeRepository>,
    pub grant: Option<cloud_client_grant::ClientGrantSigner>,
    pub projection: Option<cloud_db::client_projection::ClientProjectionRepository>,
    pub settings: Option<cloud_db::client_settings::ClientProjectionSettingsRepository>,
    pub projection_signer: Option<cloud_client_projection::PolicyProjectionSigner>,
    pub geo_provider: Option<cloud_db::geo_provider::GeoProviderRepository>,
}

/// Full terminal client plane. The client control, routing, and signing
/// capabilities are all optional so a deployment can run the management API
/// without terminal Grant issuance; when any of them is absent the terminal
/// routes answer `503` instead of failing open.
pub fn app_with_authentication_and_terminal_client_plane(
    repository: ControlRepository,
    enrollment: cloud_db::enrollment::EnrollmentRepository,
    plane: TerminalClientPlane,
    authenticator: ManagementAuthenticator,
) -> Router {
    let state = Arc::new(ManagementState {
        repository: Some(repository),
        client_access: plane.access,
        client_control: plane.control,
        client_routing: plane.routing,
        client_grant: plane.grant,
        client_projection: plane.projection,
        client_settings: plane.settings,
        client_projection_signer: plane.projection_signer,
        geo_provider: plane.geo_provider,
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
        client_projection: None,
        client_settings: None,
        client_projection_signer: None,
        geo_provider: None,
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
    plane: TerminalClientPlane,
    principal: AuthenticatedPrincipal,
) -> Router {
    app_with_state(Arc::new(ManagementState {
        repository: Some(repository),
        client_access: plane.access,
        client_control: plane.control,
        client_routing: plane.routing,
        client_grant: plane.grant,
        client_projection: plane.projection,
        client_settings: plane.settings,
        client_projection_signer: plane.projection_signer,
        geo_provider: plane.geo_provider,
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
            "/v1/client/devices/{device_id}/projection",
            axum::routing::post(client_projection_api::fetch_client_projection),
        )
        .route(
            "/v1/client/devices/{device_id}/projection/receipt",
            axum::routing::put(client_projection_api::record_client_receipt),
        )
        .route(
            "/v1/client/devices/{device_id}/heartbeat",
            axum::routing::post(client_projection_api::client_heartbeat),
        )
        .route(
            "/v1/client/devices/{device_id}/traffic-mode",
            axum::routing::post(client_projection_api::set_client_traffic_mode),
        )
        .route(
            "/v1/client/devices/{device_id}/revoke",
            axum::routing::post(client_projection_api::revoke_client_device),
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
            "/v1/platform/geo-provider",
            get(management::get_platform_geo_provider)
                .put(management::put_platform_geo_provider),
        )
        .route(
            "/v1/tenants/{tenant_id}/geo-provider",
            any(management::tenant_geo_provider_removed),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-access-policies",
            axum::routing::post(management::create_client_access_policy),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-access-policy-bindings",
            axum::routing::post(management::bind_client_access_policy),
        )
        // Device lifecycle and key rotation are management decisions about a
        // device, so they live under the tenant and take `WriteConfiguration`
        // like every other management mutation. They must stay above the
        // `{collection}` catch-all, which would otherwise read `client-devices`
        // as a resource collection name.
        .route(
            "/v1/tenants/{tenant_id}/client-devices/{device_id}/status",
            axum::routing::put(management::set_client_device_status),
        )
        .route(
            "/v1/tenants/{tenant_id}/client-devices/{device_id}/key-rotation",
            axum::routing::post(management::rotate_client_device_key),
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
