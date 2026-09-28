use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use cloud_api::domain::{Role, TenantContext};
use cloud_api::management::AuthenticatedPrincipal;
use cloud_api::{
    app, app_with_principal, app_with_terminal_client_plane_and_principal, TerminalClientPlane,
};
use cloud_db::DbPool;

fn lazy_repository() -> cloud_db::control::ControlRepository {
    let pool: DbPool = sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap();
    cloud_db::control::ControlRepository::new(pool)
}

fn lazy_geo_provider() -> cloud_db::geo_provider::GeoProviderRepository {
    let pool: DbPool = sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap();
    cloud_db::geo_provider::GeoProviderRepository::new(pool)
}

fn app_with_geo_provider(principal: AuthenticatedPrincipal) -> axum::Router {
    app_with_terminal_client_plane_and_principal(
        lazy_repository(),
        TerminalClientPlane {
            geo_provider: Some(lazy_geo_provider()),
            ..TerminalClientPlane::default()
        },
        principal,
    )
}

fn client_policy(tenant_id: Uuid) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "policy_id": Uuid::new_v4(),
        "tenant_id": tenant_id,
        "generation": 1,
        "mode_capabilities": ["policy"],
        "global_egress_enabled": false,
        "allowed_resources": [{
            "name": "internal-git",
            "domains": ["git.example.test"],
            "cidrs": ["10.20.0.0/16"],
            "ports": [443]
        }]
    }))
    .unwrap()
}

#[tokio::test]
async fn management_routes_fail_closed_without_authenticated_principal() {
    let tenant = Uuid::new_v4();
    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{tenant}/sites"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("AUTHENTICATION_REQUIRED"));
}

#[tokio::test]
async fn management_routes_reject_cross_tenant_before_touching_storage() {
    let organization = Uuid::new_v4();
    let principal_tenant = Uuid::new_v4();
    let requested_tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: "operator-1".into(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: principal_tenant,
            role: Role::TenantAdmin,
        },
    };
    let response = app_with_principal(lazy_repository(), principal.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{requested_tenant}/sites"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app_with_principal(lazy_repository(), principal.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{requested_tenant}/runtime-telemetry"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{requested_tenant}/runtime-configuration-status"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn platform_geo_route_is_platform_scoped_and_tenant_independent() {
    let organization = Uuid::new_v4();
    let platform = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: Uuid::new_v4(),
            role: Role::PlatformAdmin,
        },
    };

    // The platform principal reaches the single platform repository. The lazy
    // test pool then deliberately fails with the storage-specific 503.
    let response = app_with_geo_provider(platform.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/platform/geo-provider")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    // Geo is a deployment capability, not a tenant resource. The old tenant
    // shaped endpoint is intentionally absent instead of being an alias.
    let response = app_with_geo_provider(platform)
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{}/geo-provider", Uuid::new_v4()))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app_with_geo_provider(AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: Uuid::new_v4(),
            role: Role::PlatformAdmin,
        },
    })
    .oneshot(
        Request::builder()
            .uri(format!("/v1/tenants/{}/geo-provider", Uuid::new_v4()))
            .method("PUT")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenant_owner_cannot_read_platform_geo_provider() {
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            role: Role::OrganizationOwner,
        },
    };
    let response = app_with_geo_provider(principal)
        .oneshot(
            Request::builder()
                .uri("/v1/platform/geo-provider")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn platform_admin_cannot_fall_through_to_tenant_resources() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: tenant,
            role: Role::PlatformAdmin,
        },
    };
    let response = app_with_geo_provider(principal)
        .oneshot(
            Request::builder()
                .uri(format!("/v1/tenants/{tenant}/sites"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn tenant_principal(organization: Uuid, tenant: Uuid) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: tenant,
            role: Role::TenantAdmin,
        },
    }
}

fn status_uri(tenant: Uuid, device: Uuid) -> String {
    format!("/v1/tenants/{tenant}/client-devices/{device}/status")
}

fn rotation_uri(tenant: Uuid, device: Uuid) -> String {
    format!("/v1/tenants/{tenant}/client-devices/{device}/key-rotation")
}

async fn send_body(app: axum::Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn json_body(value: serde_json::Value) -> Body {
    Body::from(serde_json::to_vec(&value).unwrap())
}

#[tokio::test]
async fn malformed_pagination_is_rejected_before_storage_access() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: "operator-1".into(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: tenant,
            role: Role::TenantAdmin,
        },
    };
    for (header, value, expected_code) in [
        ("x-page-size", "many", "INVALID_PAGE_SIZE"),
        ("x-page-after", "not-a-uuid", "INVALID_PAGE_CURSOR"),
    ] {
        let response = app_with_principal(lazy_repository(), principal.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/tenants/{tenant}/sites"))
                    .header(header, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains(expected_code));
    }
}

#[tokio::test]
async fn terminal_policy_route_requires_authentication() {
    let tenant = Uuid::new_v4();
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/tenants/{tenant}/client-access-policies"))
                .header("Idempotency-Key", Uuid::new_v4().to_string())
                .header("content-type", "application/json")
                .body(Body::from(client_policy(tenant)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn terminal_policy_route_rejects_cross_tenant_before_storage_access() {
    let organization = Uuid::new_v4();
    let principal_tenant = Uuid::new_v4();
    let requested_tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: principal_tenant,
            role: Role::TenantAdmin,
        },
    };
    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/tenants/{requested_tenant}/client-access-policies"
                ))
                .header("Idempotency-Key", Uuid::new_v4().to_string())
                .header("content-type", "application/json")
                .body(Body::from(client_policy(requested_tenant)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn terminal_policy_route_rejects_body_tenant_switch() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: tenant,
            role: Role::TenantAdmin,
        },
    };
    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/tenants/{tenant}/client-access-policies"))
                .header("Idempotency-Key", Uuid::new_v4().to_string())
                .header("content-type", "application/json")
                .body(Body::from(client_policy(other_tenant)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn terminal_policy_route_requires_uuid_idempotency_key() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: tenant,
            role: Role::TenantAdmin,
        },
    };
    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/tenants/{tenant}/client-access-policies"))
                .header("content-type", "application/json")
                .body(Body::from(client_policy(tenant)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("MISSING_IDEMPOTENCY_KEY"));
}

#[tokio::test]
async fn terminal_policy_binding_route_rejects_cross_tenant_before_storage_access() {
    let organization = Uuid::new_v4();
    let principal_tenant = Uuid::new_v4();
    let requested_tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: principal_tenant,
            role: Role::TenantAdmin,
        },
    };
    let body = serde_json::to_vec(&serde_json::json!({
        "policy_id": Uuid::new_v4(),
        "user_id": Uuid::new_v4(),
        "client_device_id": Uuid::new_v4()
    }))
    .unwrap();
    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/tenants/{requested_tenant}/client-access-policy-bindings"
                ))
                .header("Idempotency-Key", Uuid::new_v4().to_string())
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn terminal_policy_read_route_rejects_cross_tenant_before_storage_access() {
    let organization = Uuid::new_v4();
    let principal_tenant = Uuid::new_v4();
    let requested_tenant = Uuid::new_v4();
    let principal = AuthenticatedPrincipal {
        actor_id: Uuid::new_v4().to_string(),
        context: TenantContext {
            organization_id: organization,
            tenant_id: principal_tenant,
            role: Role::TenantAdmin,
        },
    };
    let response = app_with_principal(lazy_repository(), principal)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/tenants/{requested_tenant}/client-users/{}/client-devices/{}/access-policy",
                    Uuid::new_v4(),
                    Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// A device lifecycle request must lose to the session check, not to body
// validation: an unauthenticated caller must never learn which `status` values
// Cloud accepts. The body here is deliberately nonsense so that a handler which
// parsed it first would answer `400` instead of `401`.
#[tokio::test]
async fn device_status_route_requires_authentication_before_body_validation() {
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let response = app()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(status_uri(tenant, device))
                .header("content-type", "application/json")
                .body(Body::from("{ this is not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("AUTHENTICATION_REQUIRED"),
        "{}",
        String::from_utf8_lossy(&body)
    );
}

// Key rotation has the same ordering contract as the status route: session
// first, so an unauthenticated caller cannot probe the `public_key` parser.
#[tokio::test]
async fn device_key_rotation_route_requires_authentication_before_body_validation() {
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(rotation_uri(tenant, device))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn device_lifecycle_routes_reject_cross_tenant_before_body_validation() {
    let organization = Uuid::new_v4();
    let principal_tenant = Uuid::new_v4();
    let requested_tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let app = app_with_principal(
        lazy_repository(),
        tenant_principal(organization, principal_tenant),
    );

    let (status, body) = send_body(
        app.clone(),
        Request::builder()
            .method("PUT")
            .uri(status_uri(requested_tenant, device))
            .header("content-type", "application/json")
            .body(json_body(
                serde_json::json!({ "status": "not-a-real-state" }),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, body) = send_body(
        app,
        Request::builder()
            .method("POST")
            .uri(rotation_uri(requested_tenant, device))
            .header("content-type", "application/json")
            .body(json_body(serde_json::json!({
                "device_key_id": Uuid::new_v4(),
                "public_key": "not-base64url!"
            })))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

// `revoked` is intentionally not an accepted status value. Revocation has its
// own route and is terminal, so a lifecycle call asking for it is refused
// rather than quietly satisfied.
#[tokio::test]
async fn device_status_route_rejects_unknown_or_terminal_values() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let principal = tenant_principal(organization, tenant);
    for value in ["not-a-real-state", "revoked", "Active", ""] {
        let (status, body) = send_body(
            app_with_principal(lazy_repository(), principal.clone()),
            Request::builder()
                .method("PUT")
                .uri(status_uri(tenant, device))
                .header("content-type", "application/json")
                .body(json_body(serde_json::json!({ "status": value })))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{value}: {body}");
        assert!(body.contains("INVALID_DEVICE_STATUS"), "{value}: {body}");
    }
}

#[tokio::test]
async fn device_status_route_rejects_a_malformed_body_before_storage() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let principal = tenant_principal(organization, tenant);
    for body in [
        "{}",
        "{",
        "{\"status\": 3}",
        "{\"status\":\"active\",\"extra\":1}",
    ] {
        let (status, response) = send_body(
            app_with_principal(lazy_repository(), principal.clone()),
            Request::builder()
                .method("PUT")
                .uri(status_uri(tenant, device))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        assert!(response.contains("INVALID_REQUEST"), "{body}: {response}");
    }
}

// With validation passed and the session authorized, the only thing left is
// storage -- which the test harness intentionally leaves unconfigured. A `503`
// here is the proof that the request got past every ordering gate, including the
// absence of any required `Idempotency-Key`: these two routes are idempotent by
// device state, not by an operator-supplied key, so they must not demand one.
#[tokio::test]
async fn device_lifecycle_routes_reach_storage_without_an_idempotency_key() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let app = app_with_principal(lazy_repository(), tenant_principal(organization, tenant));

    let (status, body) = send_body(
        app.clone(),
        Request::builder()
            .method("PUT")
            .uri(status_uri(tenant, device))
            .header("content-type", "application/json")
            .body(json_body(serde_json::json!({ "status": "suspended" })))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("AUTHENTICATION_UNAVAILABLE"), "{body}");
    assert!(!body.contains("MISSING_IDEMPOTENCY_KEY"), "{body}");

    let (status, body) = send_body(
        app,
        Request::builder()
            .method("POST")
            .uri(rotation_uri(tenant, device))
            .header("content-type", "application/json")
            .body(json_body(serde_json::json!({
                "device_key_id": Uuid::new_v4(),
                "public_key": URL_SAFE_NO_PAD.encode([9_u8; 32])
            })))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("AUTHENTICATION_UNAVAILABLE"), "{body}");
    assert!(!body.contains("MISSING_IDEMPOTENCY_KEY"), "{body}");
}

// The rotation parser accepts the storage schema's 32..=64 byte window and
// nothing else: a truncated key, an over-long key, an all-zero key, plain text,
// and padded base64 are all `400 INVALID_PUBLIC_KEY` rather than a storage write.
#[tokio::test]
async fn device_key_rotation_route_rejects_invalid_public_keys() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let principal = tenant_principal(organization, tenant);
    let rejected = [
        String::new(),
        "not-base64url!".to_string(),
        URL_SAFE_NO_PAD.encode([3_u8; 31]),
        URL_SAFE_NO_PAD.encode([3_u8; 65]),
        URL_SAFE_NO_PAD.encode([0_u8; 32]),
        format!("{}=", URL_SAFE_NO_PAD.encode([3_u8; 32])),
    ];
    for key in rejected {
        let (status, body) = send_body(
            app_with_principal(lazy_repository(), principal.clone()),
            Request::builder()
                .method("POST")
                .uri(rotation_uri(tenant, device))
                .header("content-type", "application/json")
                .body(json_body(serde_json::json!({
                    "device_key_id": Uuid::new_v4(),
                    "public_key": key
                })))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}: {body}");
        assert!(body.contains("INVALID_PUBLIC_KEY"), "{key}: {body}");
    }
}

#[tokio::test]
async fn device_key_rotation_route_rejects_a_malformed_body_before_storage() {
    let organization = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let device = Uuid::new_v4();
    let principal = tenant_principal(organization, tenant);
    let encoded = URL_SAFE_NO_PAD.encode([3_u8; 32]);
    for body in [
        "{}".to_string(),
        format!(r#"{{"device_key_id":"not-a-uuid","public_key":"{encoded}"}}"#),
        format!(
            r#"{{"device_key_id":"{}","public_key":"{encoded}","extra":1}}"#,
            Uuid::new_v4()
        ),
    ] {
        let (status, response) = send_body(
            app_with_principal(lazy_repository(), principal.clone()),
            Request::builder()
                .method("POST")
                .uri(rotation_uri(tenant, device))
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
        assert!(response.contains("INVALID_REQUEST"), "{body}: {response}");
    }
}
