use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use cloud_auth::{
    domain::{DeviceEnrollment, GrantRequest, ServiceClass},
    enrollment::{
        EnrollmentChallengeCommand, EnrollmentChallengeReceipt, EnrollmentCompleteCommand,
        EnrollmentCompleteReceipt, EnrollmentCoordinatorError,
    },
    routes::{
        authenticated_app, enrollment_app, AuthenticatedDevice, AuthenticatedTenant,
        EnrollmentHttpService, EnrollmentReceipt, GrantIssuanceReceipt, GrantIssueCommand,
        GrantServiceError, ServiceFuture, TenantAuthService,
    },
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Default)]
struct RecordingService {
    enrollments: Mutex<Vec<DeviceEnrollment>>,
    grants: Mutex<Vec<GrantIssueCommand>>,
}

impl TenantAuthService for RecordingService {
    fn enroll(
        &self,
        _actor: AuthenticatedTenant,
        enrollment: DeviceEnrollment,
    ) -> ServiceFuture<'_, Result<EnrollmentReceipt, GrantServiceError>> {
        Box::pin(async move {
            let device_id = enrollment.device.id;
            self.enrollments.lock().unwrap().push(enrollment);
            Ok(EnrollmentReceipt { device_id })
        })
    }

    fn issue_grant(
        &self,
        command: GrantIssueCommand,
    ) -> ServiceFuture<'_, Result<GrantIssuanceReceipt, GrantServiceError>> {
        Box::pin(async move {
            self.grants.lock().unwrap().push(command);
            Ok(GrantIssuanceReceipt {
                grant_id: Uuid::new_v4(),
                expires_at_unix: 1_800_000_000,
                replayed: false,
                access_grant: vec![1, 2, 3],
            })
        })
    }
}

fn device_actor(
    organization_id: Uuid,
    tenant_id: Uuid,
    device_id: Uuid,
    device_key_id: Uuid,
) -> AuthenticatedDevice {
    AuthenticatedDevice::new(organization_id, tenant_id, device_id, device_key_id, 2).unwrap()
}

#[derive(Default)]
struct RecordingEnrollmentService {
    challenges: Mutex<Vec<EnrollmentChallengeCommand>>,
    completions: Mutex<Vec<EnrollmentCompleteCommand>>,
}

impl EnrollmentHttpService for RecordingEnrollmentService {
    fn challenge(
        &self,
        command: EnrollmentChallengeCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentChallengeReceipt, EnrollmentCoordinatorError>> {
        Box::pin(async move {
            self.challenges.lock().unwrap().push(command);
            Ok(EnrollmentChallengeReceipt {
                challenge_id: Uuid::from_bytes([1; 16]),
                organization_id: Uuid::from_bytes([2; 16]),
                server_nonce: [3; 32],
                expires_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
                replayed: false,
            })
        })
    }

    fn complete(
        &self,
        command: EnrollmentCompleteCommand,
    ) -> ServiceFuture<'_, Result<EnrollmentCompleteReceipt, EnrollmentCoordinatorError>> {
        Box::pin(async move {
            self.completions.lock().unwrap().push(command);
            Ok(EnrollmentCompleteReceipt {
                device_id: Uuid::from_bytes([4; 16]),
                device_key_id: Uuid::from_bytes([5; 16]),
                certificate_der: vec![1, 2, 3],
                certificate_chain_pem: "test-chain".into(),
                not_after: chrono::DateTime::from_timestamp(1_800_604_800, 0).unwrap(),
                replayed: false,
            })
        })
    }
}

#[tokio::test]
async fn public_enrollment_routes_decode_fixed_binary_fields_and_reject_client_scope() {
    let service = Arc::new(RecordingEnrollmentService::default());
    let app = enrollment_app(service.clone());
    let encoded_32 =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7; 32]);
    let body = format!(
        r#"{{"activation_credential":"{encoded_32}","request_id":"challenge-1","enrollment_instance_id":"installer-1","display_name":"branch-router","root_public_key":"{encoded_32}","operational_public_key":"{encoded_32}","metadata_hash":"{encoded_32}","attestation_hash":"{encoded_32}"}}"#
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enrollment/challenges")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let command = service.challenges.lock().unwrap().pop().unwrap();
    assert_eq!(command.activation_credential, [7; 32]);
    assert_eq!(command.root_public_key, [7; 32]);
    assert_eq!(command.operational_public_key, [7; 32]);

    let scoped = body.replacen('{', &format!(r#"{{"tenant_id":"{}","#, Uuid::new_v4()), 1);
    let rejected = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enrollment/challenges")
                .header("content-type", "application/json")
                .body(Body::from(scoped))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn public_enrollment_complete_decodes_proof_and_encodes_certificate() {
    let service = Arc::new(RecordingEnrollmentService::default());
    let app = enrollment_app(service.clone());
    let challenge_id = Uuid::new_v4();
    let proof = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [9; 64]);
    let body = format!(
        r#"{{"challenge_id":"{challenge_id}","request_id":"complete-1","operational_proof":"{proof}"}}"#
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enrollment/complete")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let command = service.completions.lock().unwrap().pop().unwrap();
    assert_eq!(command.challenge_id, challenge_id);
    assert_eq!(command.operational_proof, [9; 64]);
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(response_body
        .windows(b"AQID".len())
        .any(|item| item == b"AQID"));
}

#[tokio::test]
async fn legacy_enrollment_request_route_is_not_mounted() {
    let service = Arc::new(RecordingService::default());
    let app = authenticated_app(service.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enrollment/requests")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(service.enrollments.lock().unwrap().is_empty());
}

#[tokio::test]
async fn authenticated_grant_route_uses_actor_tenant_and_device_scope() {
    let organization_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let node_pool_id = Uuid::new_v4();
    let service = Arc::new(RecordingService::default());
    let app = authenticated_app(service.clone());
    let body = format!(
        r#"{{"request_id":"refresh-01","node_pool_id":"{node_pool_id}","service_class":"candy_shared","service_permission":"shared.accelerator.connect"}}"#
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/access-grants")
                .header("content-type", "application/json")
                .extension(device_actor(
                    organization_id,
                    tenant_id,
                    device_id,
                    device_key_id,
                ))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let command = service.grants.lock().unwrap().pop().expect("service call");
    assert_eq!(command.request.tenant_id, tenant_id);
    assert_eq!(command.request.device_id, device_id);
    assert_eq!(command.request.device_key_id, device_key_id);
    assert_eq!(command.request.node_pool_id, node_pool_id);
    assert_eq!(command.request.service_class, ServiceClass::CandyShared);
    assert_eq!(command.actor.organization_id(), organization_id);
    assert_eq!(command.actor.assurance_level(), 2);
    assert_eq!(
        command.request.service_permission,
        "shared.accelerator.connect"
    );
    let response_body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(response_body
        .windows(b"AQID".len())
        .any(|item| item == b"AQID"));
}

#[tokio::test]
async fn grant_route_rejects_body_supplied_device_identity() {
    let tenant_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let device_key_id = Uuid::new_v4();
    let service = Arc::new(RecordingService::default());
    let app = authenticated_app(service.clone());
    let body = format!(
        r#"{{"request_id":"refresh-02","device_id":"{device_id}","device_key_id":"{device_key_id}","node_pool_id":"{}","service_class":"private","service_permission":"private.connect"}}"#,
        Uuid::new_v4()
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/access-grants")
                .header("content-type", "application/json")
                .extension(device_actor(
                    Uuid::new_v4(),
                    tenant_id,
                    device_id,
                    device_key_id,
                ))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(service.grants.lock().unwrap().is_empty());
}

#[test]
fn grant_request_type_remains_domain_owned() {
    let request = GrantRequest {
        tenant_id: Uuid::new_v4(),
        device_id: Uuid::new_v4(),
        device_key_id: Uuid::new_v4(),
        node_pool_id: Uuid::new_v4(),
        service_class: ServiceClass::Private,
        service_permission: "private.connect".into(),
    };
    assert_eq!(request.service_class, ServiceClass::Private);
}
