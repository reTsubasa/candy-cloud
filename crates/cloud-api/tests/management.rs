use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use cloud_api::domain::{Role, TenantContext};
use cloud_api::management::AuthenticatedPrincipal;
use cloud_api::{app, app_with_principal};
use cloud_db::DbPool;

fn lazy_repository() -> cloud_db::control::ControlRepository {
    let pool: DbPool = sqlx::MySqlPool::connect_lazy("mysql://invalid/invalid").unwrap();
    cloud_db::control::ControlRepository::new(pool)
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
