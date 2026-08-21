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
        authenticated_app, enrollment_app, runtime_configuration_app, AuthenticatedDevice,
        AuthenticatedTenant, EnrollmentHttpService, EnrollmentReceipt, GrantIssuanceReceipt,
        GrantIssueCommand, GrantServiceError, RuntimeConfigurationApplyState,
        RuntimeConfigurationDelivery, RuntimeConfigurationService,
        RuntimeConfigurationServiceError, RuntimeConfigurationStatusCommand,
        RuntimeProfileDelivery, RuntimeTelemetryCommand, RuntimeTransportEndpointDelivery,
        RuntimeTransportIdentityCommand, RuntimeTransportIdentityDelivery, ServiceFuture,
        TenantAuthService,
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
                refresh_after_unix: 1_799_978_400,
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

struct RecordingRuntimeConfigurationService {
    delivery: Mutex<Option<RuntimeConfigurationDelivery>>,
    statuses: Mutex<Vec<RuntimeConfigurationStatusCommand>>,
    telemetry: Mutex<Vec<RuntimeTelemetryCommand>>,
    transport_publications: Mutex<Vec<RuntimeTransportIdentityCommand>>,
    transport_withdrawals: Mutex<Vec<AuthenticatedDevice>>,
    status_result: Mutex<Result<(), RuntimeConfigurationServiceError>>,
}

impl RecordingRuntimeConfigurationService {
    fn with_delivery(delivery: Option<RuntimeConfigurationDelivery>) -> Self {
        Self {
            delivery: Mutex::new(delivery),
            statuses: Mutex::new(Vec::new()),
            telemetry: Mutex::new(Vec::new()),
            transport_publications: Mutex::new(Vec::new()),
            transport_withdrawals: Mutex::new(Vec::new()),
            status_result: Mutex::new(Ok(())),
        }
    }
}

impl RuntimeConfigurationService for RecordingRuntimeConfigurationService {
    fn current(
        &self,
        _actor: AuthenticatedDevice,
    ) -> ServiceFuture<
        '_,
        Result<Option<RuntimeConfigurationDelivery>, RuntimeConfigurationServiceError>,
    > {
        Box::pin(async move { Ok(self.delivery.lock().unwrap().clone()) })
    }

    fn profile(
        &self,
        actor: AuthenticatedDevice,
    ) -> ServiceFuture<'_, Result<RuntimeProfileDelivery, RuntimeConfigurationServiceError>> {
        Box::pin(async move {
            Ok(RuntimeProfileDelivery {
                organization_id: actor.organization_id(),
                organization_name: "Candy Demo".into(),
                tenant_id: actor.tenant_id(),
                tenant_name: "Default".into(),
                device_id: actor.device_id(),
                device_key_id: actor.device_key_id(),
                device_name: "OpenWrt".into(),
                site_id: None,
                site_name: None,
                segment_id: None,
                segment_name: None,
                attachment_id: None,
            })
        })
    }

    fn record_status(
        &self,
        command: RuntimeConfigurationStatusCommand,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>> {
        Box::pin(async move {
            self.statuses.lock().unwrap().push(command);
            *self.status_result.lock().unwrap()
        })
    }

    fn record_telemetry(
        &self,
        command: RuntimeTelemetryCommand,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>> {
        Box::pin(async move {
            self.telemetry.lock().unwrap().push(command);
            Ok(())
        })
    }

    fn publish_transport_identity(
        &self,
        command: RuntimeTransportIdentityCommand,
    ) -> ServiceFuture<'_, Result<RuntimeTransportIdentityDelivery, RuntimeConfigurationServiceError>>
    {
        Box::pin(async move {
            let node_id = command.actor.device_id();
            let endpoints = command
                .endpoints
                .iter()
                .map(|endpoint| RuntimeTransportEndpointDelivery {
                    endpoint: endpoint.endpoint.to_string(),
                    server_name: format!("device-{node_id}.sdwan.candy.internal"),
                })
                .collect();
            self.transport_publications.lock().unwrap().push(command);
            Ok(RuntimeTransportIdentityDelivery {
                node_id,
                endpoints,
                replayed: false,
            })
        })
    }

    fn withdraw_transport_identity(
        &self,
        actor: AuthenticatedDevice,
    ) -> ServiceFuture<'_, Result<(), RuntimeConfigurationServiceError>> {
        Box::pin(async move {
            self.transport_withdrawals.lock().unwrap().push(actor);
            Ok(())
        })
    }
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
                certificate_der: vec![251, 255],
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
        .windows(b"+/8=".len())
        .any(|item| item == b"+/8="));
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

fn runtime_delivery() -> RuntimeConfigurationDelivery {
    RuntimeConfigurationDelivery {
        projection_publication_id: Uuid::from_bytes([1; 16]),
        projection_id: Uuid::from_bytes([2; 16]),
        segment_id: Uuid::from_bytes([3; 16]),
        attachment_id: Uuid::from_bytes([4; 16]),
        segment_generation: 5,
        projection_generation: 6,
        projection_content_hash: [7; 32],
        envelope_sha256: [8; 32],
        signed_segment_envelope: vec![0, 1, 2, 0xff],
        signed_projection_envelope: vec![3, 4, 5, 0xfe],
        route_signing_key_id: "route-signing-1".into(),
        route_signing_public_key: [9; 32],
        peer_projection_catalog: vec![cloud_auth::routes::RuntimePeerProjectionDelivery {
            projection_id: Uuid::from_bytes([10; 16]),
            projection_generation: 4,
            projection_content_hash: [11; 32],
            signed_projection_envelope: vec![6, 7, 8],
        }],
        compatibility_generations: vec![
            cloud_auth::routes::RuntimeCompatibilityGenerationDelivery {
                segment_generation: 3,
                segment_content_hash: [15; 32],
                signed_segment_envelope: vec![9, 10, 11],
                peer_projection_catalog: vec![cloud_auth::routes::RuntimePeerProjectionDelivery {
                    projection_id: Uuid::from_bytes([16; 16]),
                    projection_generation: 2,
                    projection_content_hash: [17; 32],
                    signed_projection_envelope: vec![12, 13, 14],
                }],
            },
        ],
        grant_verification_keys: vec![cloud_auth::routes::RuntimeGrantVerificationKeyDelivery {
            key_id: "grant-key-1".into(),
            ed25519_public_key: [12; 32],
            issuer_id: Uuid::from_bytes([13; 16]),
            environment_id: Uuid::from_bytes([14; 16]),
        }],
    }
}

#[tokio::test]
async fn runtime_transport_identity_accepts_dual_stack_and_explicit_withdrawal() {
    let service = Arc::new(RecordingRuntimeConfigurationService::with_delivery(None));
    let app = runtime_configuration_app(service.clone());
    let actor = device_actor(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let body = serde_json::json!({
        "schema_version": 1,
        "request_id": "transport-20260817-01",
        "endpoints": [
            {
                "endpoint": "203.0.113.9:4433",
                "server_cert_sha256": "11".repeat(32),
                "transport_preset": "current"
            },
            {
                "endpoint": "[2001:db8::9]:4433",
                "server_cert_sha256": "22".repeat(32),
                "transport_preset": "bbr_v1"
            }
        ]
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/transport-identity")
                .header("content-type", "application/json")
                .extension(actor.clone())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    {
        let publications = service.transport_publications.lock().unwrap();
        assert_eq!(publications.len(), 1);
        assert_eq!(publications[0].actor, actor);
        assert_eq!(
            publications[0].endpoints[0].endpoint.to_string(),
            "203.0.113.9:4433"
        );
        assert_eq!(
            publications[0].endpoints[1].endpoint.to_string(),
            "[2001:db8::9]:4433"
        );
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/runtime/transport-identity")
                .extension(actor.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        service.transport_withdrawals.lock().unwrap().as_slice(),
        &[actor]
    );
}

#[tokio::test]
async fn runtime_transport_identity_rejects_duplicate_endpoints_before_storage() {
    let service = Arc::new(RecordingRuntimeConfigurationService::with_delivery(None));
    let app = runtime_configuration_app(service.clone());
    let body = serde_json::json!({
        "schema_version": 1,
        "request_id": "transport-duplicate",
        "endpoints": [
            {
                "endpoint": "203.0.113.10:4433",
                "server_cert_sha256": "11".repeat(32),
                "transport_preset": "current"
            },
            {
                "endpoint": "203.0.113.10:4433",
                "server_cert_sha256": "22".repeat(32),
                "transport_preset": "aggressive"
            }
        ]
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/transport-identity")
                .header("content-type", "application/json")
                .extension(device_actor(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(service.transport_publications.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_configuration_returns_coherent_signed_bundle_and_honors_etag() {
    let delivery = runtime_delivery();
    let service = Arc::new(RecordingRuntimeConfigurationService::with_delivery(Some(
        delivery.clone(),
    )));
    let app = runtime_configuration_app(service);
    let actor = device_actor(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/configuration")
                .extension(actor.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/vnd.candy.runtime-configuration.v1+json"
    );
    let etag = response.headers()["etag"].clone();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["segment_snapshot"], "AAEC_w");
    assert_eq!(body["site_projection"], "AwQF_g");
    assert_eq!(body["route_signing_key_id"], "route-signing-1");
    assert_eq!(body["route_signing_public_key"], "09".repeat(32));
    assert_eq!(
        body["peer_projection_catalog"][0]["projection_id"],
        Uuid::from_bytes([10; 16]).to_string()
    );
    assert_eq!(
        body["peer_projection_catalog"][0]["site_projection"],
        "BgcI"
    );
    assert_eq!(
        body["compatibility_generations"][0]["segment_generation"],
        3
    );
    assert_eq!(
        body["compatibility_generations"][0]["segment_content_hash"],
        "0f".repeat(32)
    );
    assert_eq!(
        body["compatibility_generations"][0]["segment_snapshot"],
        "CQoL"
    );
    assert_eq!(
        body["compatibility_generations"][0]["peer_projection_catalog"][0]["projection_id"],
        Uuid::from_bytes([16; 16]).to_string()
    );
    assert_eq!(
        body["compatibility_generations"][0]["peer_projection_catalog"][0]["projection_generation"],
        2
    );
    assert_eq!(
        body["compatibility_generations"][0]["peer_projection_catalog"][0]["site_projection"],
        "DA0O"
    );
    assert_eq!(body["grant_verification_keys"][0]["key_id"], "grant-key-1");

    let unchanged = app
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/configuration")
                .header("if-none-match", etag)
                .extension(actor.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
    assert!(unchanged
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty());
}

#[tokio::test]
async fn runtime_configuration_distinguishes_unassigned_and_records_bounded_status() {
    let service = Arc::new(RecordingRuntimeConfigurationService::with_delivery(None));
    let actor = device_actor(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let app = runtime_configuration_app(service.clone());

    let unassigned = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/configuration")
                .extension(actor.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unassigned.status(), StatusCode::NO_CONTENT);
    assert_eq!(unassigned.headers()["retry-after"], "30");

    let status = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/configuration/status")
                .header("content-type", "application/json")
                .header("if-match", format!("\"sha256-{}\"", "08".repeat(32)))
                .extension(actor)
                .body(Body::from(format!(
                    r#"{{"projection_publication_id":"{}","projection_content_hash":"{}","state":"rejected","error_code":"signature_verification_failed"}}"#,
                    Uuid::from_bytes([1; 16]),
                    "07".repeat(32)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::NO_CONTENT);
    let command = service.statuses.lock().unwrap().pop().unwrap();
    assert_eq!(
        command.apply_state,
        RuntimeConfigurationApplyState::Rejected
    );
    assert_eq!(command.envelope_sha256, [8; 32]);
    assert_eq!(command.projection_content_hash, [7; 32]);
}

#[tokio::test]
async fn runtime_telemetry_uses_authenticated_identity_and_rejects_impossible_counters() {
    let service = Arc::new(RecordingRuntimeConfigurationService::with_delivery(None));
    let actor = device_actor(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let app = runtime_configuration_app(service.clone());
    let body = serde_json::json!({
        "schema_version": 1,
        "boot_id": Uuid::new_v4(),
        "sequence": 1200,
        "lifecycle": "active",
        "configured_peers": 2,
        "active_peers": 2,
        "required_route_owners": 2,
        "ready_route_owners": 2,
        "fail_open_required": false,
        "last_error_code": null,
        "rtt_ms": null,
        "jitter_ms": null,
        "packet_loss_ppm": null,
        "rx_bps": null,
        "tx_bps": null,
        "reconnects": null,
        "path_changes": null,
        "local_networks": [{
            "network_id": "30bfd718e3f4b79faf151e52915f15928bf9c63b57a7963b807c8c1f7f502ae5",
            "interface_name": "br-lan.10",
            "cidr": "192.168.10.0/24",
            "address": "192.168.10.1",
            "kind": "direct_ipv4"
        }]
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/telemetry")
                .header("content-type", "application/json")
                .extension(actor.clone())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let command = service.telemetry.lock().unwrap().pop().unwrap();
    assert_eq!(command.actor, actor);
    assert_eq!(command.active_peers, 2);
    let local_networks = command.local_networks.expect("local network telemetry");
    assert_eq!(local_networks.len(), 1);
    assert_eq!(
        local_networks[0].network_id,
        "30bfd718e3f4b79faf151e52915f15928bf9c63b57a7963b807c8c1f7f502ae5"
    );

    let legacy = serde_json::json!({
        "schema_version": 1,
        "boot_id": Uuid::new_v4(),
        "sequence": 1,
        "lifecycle": "stopped",
        "configured_peers": 0,
        "active_peers": 0,
        "required_route_owners": 0,
        "ready_route_owners": 0,
        "fail_open_required": false,
        "last_error_code": null,
        "rtt_ms": null,
        "jitter_ms": null,
        "packet_loss_ppm": null,
        "rx_bps": null,
        "tx_bps": null,
        "reconnects": null,
        "path_changes": null
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/telemetry")
                .header("content-type", "application/json")
                .extension(actor.clone())
                .body(Body::from(legacy.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(service
        .telemetry
        .lock()
        .unwrap()
        .pop()
        .unwrap()
        .local_networks
        .is_none());

    let mut invalid = body.clone();
    invalid["active_peers"] = serde_json::json!(3);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/telemetry")
                .header("content-type", "application/json")
                .extension(actor.clone())
                .body(Body::from(invalid.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(service.telemetry.lock().unwrap().is_empty());

    let mut invalid_network = body;
    invalid_network["local_networks"][0]["cidr"] = serde_json::json!("192.168.10.0/129");
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/runtime/telemetry")
                .header("content-type", "application/json")
                .extension(actor)
                .body(Body::from(invalid_network.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(service.telemetry.lock().unwrap().is_empty());
}
