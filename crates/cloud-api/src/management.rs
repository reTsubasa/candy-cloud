use std::sync::Arc;

use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use cloud_control::{
    ControlResourceV1, ResourceKind, ResourceMetadataV1, ResourceSpecV1, ResourceState,
    CONTROL_SCHEMA_V1,
};
use cloud_db::control::{
    ControlRepository, ControlStoreError, MutationContext, MutationOutcome, ResourceMutation,
    ResourcePageRequest,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::domain::{authorize, Action, TenantContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub actor_id: String,
    pub context: TenantContext,
}

#[derive(Clone)]
pub struct ManagementState {
    pub repository: Option<ControlRepository>,
    pub enrollment: Option<cloud_db::enrollment::EnrollmentRepository>,
    pub authentication_ready: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    schema_version: u16,
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub(crate) fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTHENTICATION_REQUIRED",
            message: "management authentication is required",
        }
    }

    pub(crate) fn authentication_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "AUTHENTICATION_UNAVAILABLE",
            message: "identity session validation is unavailable",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "TENANT_ACCESS_DENIED",
            message: "tenant access is denied",
        }
    }

    fn from_store(error: ControlStoreError) -> Self {
        match error {
            ControlStoreError::InvalidResource(_) | ControlStoreError::InvalidRequest => Self {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_REQUEST",
                message: "request does not satisfy the V1 contract",
            },
            ControlStoreError::NotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "RESOURCE_NOT_FOUND",
                message: "resource was not found",
            },
            ControlStoreError::RevisionConflict => Self {
                status: StatusCode::PRECONDITION_FAILED,
                code: "REVISION_CONFLICT",
                message: "resource revision does not match If-Match",
            },
            ControlStoreError::ReferenceConflict => Self {
                status: StatusCode::CONFLICT,
                code: "RESOURCE_REFERENCE_CONFLICT",
                message: "resource reference is missing, inconsistent, or still in use",
            },
            ControlStoreError::IdempotencyConflict => Self {
                status: StatusCode::CONFLICT,
                code: "IDEMPOTENCY_CONFLICT",
                message: "idempotency key was reused with a different request",
            },
            ControlStoreError::IdempotencyReplayExpired => Self {
                status: StatusCode::CONFLICT,
                code: "IDEMPOTENCY_REPLAY_EXPIRED",
                message: "idempotency replay window expired; use a new key",
            },
            ControlStoreError::LeaseLost | ControlStoreError::InvalidTransition => Self {
                status: StatusCode::CONFLICT,
                code: "STATE_CONFLICT",
                message: "resource state changed concurrently",
            },
            ControlStoreError::Database(_) => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "CONTROL_PLANE_UNAVAILABLE",
                message: "control plane storage is unavailable",
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                schema_version: CONTROL_SCHEMA_V1,
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRequest {
    pub resource: ResourceSpecV1,
}

#[derive(Debug, Serialize)]
pub struct ResourceListResponse {
    pub schema_version: u16,
    pub items: Vec<ControlResourceV1>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct MutationResponse {
    pub schema_version: u16,
    pub replayed: bool,
    pub resource: ControlResourceV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationCreateRequest {
    pub expires_in_seconds: Option<u64>,
    pub site_id: Option<Uuid>,
    pub display_name: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ActivationCreateResponse {
    pub id: Uuid,
    pub credential: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ActivationResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub site_id: Option<Uuid>,
    pub requested_display_name: Option<String>,
    pub requested_platform: Option<String>,
    pub requested_architecture: Option<String>,
    pub status: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
    pub reserved_at: Option<chrono::DateTime<Utc>>,
    pub consumed_at: Option<chrono::DateTime<Utc>>,
    pub display_name: Option<String>,
    pub device_id: Option<Uuid>,
    pub device_key_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct RuntimeActivationReadinessQuery {
    pub segment_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct RuntimeActivationReadinessResponse {
    pub schema_version: u16,
    pub segment_id: Uuid,
    pub ready: bool,
    pub candidate_count: usize,
    pub ready_candidate_count: usize,
    pub missing_transport_count: usize,
    pub reason_codes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeConfigurationStatusResponse {
    pub schema_version: u16,
    pub items: Vec<RuntimeConfigurationStatusItem>,
}

#[derive(Debug, Serialize)]
pub struct RuntimeConfigurationStatusItem {
    pub device_id: Uuid,
    pub device_key_id: Uuid,
    pub projection_publication_id: Uuid,
    pub state: String,
    pub error_code: Option<String>,
    pub reported_at: chrono::DateTime<Utc>,
    pub current: bool,
}

pub async fn runtime_configuration_statuses(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<RuntimeConfigurationStatusResponse>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let items = repository
        .runtime_configuration_statuses(tenant_id)
        .await
        .map_err(ApiError::from_store)?
        .into_iter()
        .map(|record| RuntimeConfigurationStatusItem {
            device_id: record.device_id,
            device_key_id: record.device_key_id,
            projection_publication_id: record.projection_publication_id,
            state: record.apply_state.to_ascii_lowercase(),
            error_code: record.error_code,
            reported_at: record.reported_at,
            current: record.current,
        })
        .collect();
    Ok(Json(RuntimeConfigurationStatusResponse {
        schema_version: CONTROL_SCHEMA_V1,
        items,
    }))
}

pub async fn runtime_activation_readiness(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path(tenant_id): Path<Uuid>,
    Query(query): Query<RuntimeActivationReadinessQuery>,
) -> Result<Json<RuntimeActivationReadinessResponse>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let result = repository
        .runtime_activation_readiness(tenant_id, query.segment_id)
        .await
        .map_err(ApiError::from_store)?;
    let missing_transport_count = result.missing_candidate_ids.len();
    Ok(Json(RuntimeActivationReadinessResponse {
        schema_version: CONTROL_SCHEMA_V1,
        segment_id: result.segment_id,
        ready: result.candidate_count > 0
            && missing_transport_count == 0
            && result.reason_codes.is_empty(),
        candidate_count: result.candidate_count,
        ready_candidate_count: result.ready_candidate_count,
        missing_transport_count,
        reason_codes: result.reason_codes,
    }))
}

pub async fn list_activations(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<ActivationResponse>>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ManageDevices)?;
    let repository = state.enrollment.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "ENROLLMENT_UNAVAILABLE",
        message: "device enrollment is not configured",
    })?;
    let records = repository
        .list_activation_codes(tenant_id, Utc::now())
        .await
        .map_err(|error| {
            tracing::error!(event = "enrollment_activation_list_failed", error = %error);
            ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "ENROLLMENT_UNAVAILABLE",
                message: "device enrollment is temporarily unavailable",
            }
        })?;
    Ok(Json(
        records
            .into_iter()
            .map(|record| ActivationResponse {
                id: record.id,
                tenant_id: record.tenant_id,
                site_id: record.site_id,
                requested_display_name: record.requested_display_name,
                requested_platform: record.requested_platform,
                requested_architecture: record.requested_architecture,
                status: record.status,
                expires_at: record.expires_at,
                created_at: record.created_at,
                reserved_at: record.reserved_at,
                consumed_at: record.consumed_at,
                display_name: record.display_name,
                device_id: record.device_id,
                device_key_id: record.device_key_id,
            })
            .collect(),
    ))
}

pub async fn create_activation(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path(tenant_id): Path<Uuid>,
    Json(body): Json<ActivationCreateRequest>,
) -> Result<(StatusCode, Json<ActivationCreateResponse>), ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ManageDevices)?;
    let seconds = body.expires_in_seconds.unwrap_or(600);
    if !(300..=3_600).contains(&seconds) {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_EXPIRATION",
            message: "expires_in_seconds must be between 300 and 3600",
        });
    }
    let intent_fields = [
        body.site_id.is_some(),
        body.display_name.is_some(),
        body.platform.is_some(),
        body.architecture.is_some(),
    ];
    if intent_fields.iter().any(|value| *value) && !intent_fields.iter().all(|value| *value) {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_BOOTSTRAP_INTENT",
            message: "site_id, display_name, platform and architecture must be provided together",
        });
    }
    if body
        .display_name
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.len() > 200)
        || body
            .platform
            .as_ref()
            .is_some_and(|value| !matches!(value.as_str(), "OPEN_WRT" | "LINUX"))
        || body
            .platform
            .as_deref()
            .zip(body.architecture.as_deref())
            .is_some_and(|(platform, architecture)| {
                !matches!(
                    (platform, architecture),
                    ("OPEN_WRT", "x86_64" | "armv7") | ("LINUX", "x86_64" | "aarch64")
                )
            })
    {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_BOOTSTRAP_INTENT",
            message: "node bootstrap configuration is invalid",
        });
    }
    let repository = state.enrollment.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "ENROLLMENT_UNAVAILABLE",
        message: "device enrollment is not configured",
    })?;
    let mut credential = [0u8; 32];
    OsRng.fill_bytes(&mut credential);
    let expires_at = Utc::now()
        + Duration::seconds(i64::try_from(seconds).map_err(|_| ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_EXPIRATION",
            message: "expiration is outside the allowed range",
        })?);
    let id = Uuid::now_v7();
    let outcome = repository
        .insert_activation_code(&cloud_db::enrollment::ActivationCodeWrite {
            id,
            organization_id: principal.context.organization_id,
            tenant_id,
            site_id: body.site_id,
            requested_display_name: body.display_name.map(|value| value.trim().to_owned()),
            requested_platform: body.platform,
            requested_architecture: body.architecture,
            code_hash: cloud_db::enrollment::hash_activation_credential(&credential),
            expires_at,
            created_by: principal.actor_id,
        })
        .await
        .map_err(|error| {
            tracing::error!(event = "enrollment_activation_create_failed", error = %error);
            ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "ENROLLMENT_UNAVAILABLE",
                message: "device enrollment is temporarily unavailable",
            }
        })?;
    if !matches!(
        outcome,
        cloud_db::enrollment::ActivationCodeOutcome::Inserted
    ) {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            code: "ACTIVATION_CONFLICT",
            message: "node join code could not be created; retry the request",
        });
    }
    Ok((
        StatusCode::CREATED,
        Json(ActivationCreateResponse {
            id,
            credential: URL_SAFE_NO_PAD.encode(credential),
            expires_at,
        }),
    ))
}

pub async fn revoke_activation(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, activation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ManageDevices)?;
    let repository = state.enrollment.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "ENROLLMENT_UNAVAILABLE",
        message: "device enrollment is not configured",
    })?;
    let changed = repository
        .revoke_activation_code(tenant_id, activation_id, &principal.actor_id)
        .await
        .map_err(|error| {
            tracing::error!(event = "enrollment_activation_revoke_failed", error = %error);
            ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "ENROLLMENT_UNAVAILABLE",
                message: "device enrollment is temporarily unavailable",
            }
        })?;
    if changed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError {
            status: StatusCode::NOT_FOUND,
            code: "ACTIVATION_NOT_FOUND",
            message: "node join code was not found or is already finalized",
        })
    }
}

pub async fn list(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection)): Path<(Uuid, String)>,
    headers: HeaderMap,
) -> Result<Json<ResourceListResponse>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let limit = match headers.get("x-page-size") {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.parse().ok())
            .ok_or(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_PAGE_SIZE",
                message: "X-Page-Size must be an integer between 1 and 200",
            })?,
        None => 50,
    };
    let after_id = match headers.get("x-page-after") {
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(|value| Uuid::parse_str(value).ok())
                .filter(|value| !value.is_nil())
                .ok_or(ApiError {
                    status: StatusCode::BAD_REQUEST,
                    code: "INVALID_PAGE_CURSOR",
                    message: "X-Page-After must be a non-zero UUID",
                })?,
        ),
        None => None,
    };
    let page = ResourcePageRequest::new(limit, after_id).map_err(ApiError::from_store)?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let result = repository
        .list(tenant_id, kind, page)
        .await
        .map_err(ApiError::from_store)?;
    Ok(Json(ResourceListResponse {
        schema_version: CONTROL_SCHEMA_V1,
        items: result.items,
        next_cursor: result.next_cursor,
    }))
}

pub async fn get(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
) -> Result<Json<ControlResourceV1>, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::ReadConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    Ok(Json(
        repository
            .get(tenant_id, kind, id)
            .await
            .map_err(ApiError::from_store)?,
    ))
}

pub async fn create(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection)): Path<(Uuid, String)>,
    headers: HeaderMap,
    Json(body): Json<ResourceRequest>,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    if body.resource.kind() != kind {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "RESOURCE_KIND_MISMATCH",
            message: "resource body does not match collection",
        });
    }
    let key = required_header(&headers, "idempotency-key")?;
    let id = idempotent_resource_id(tenant_id, &principal.actor_id, &key);
    let resource = ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: 1,
            state: ResourceState::Active,
        },
        resource: body.resource,
    };
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "POST",
        &format!("/v1/tenants/{tenant_id}/{collection}"),
        key,
        &resource,
    )?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: None,
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::CREATED))
}

pub async fn replace(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<ResourceRequest>,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    if body.resource.kind() != kind {
        return Err(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "RESOURCE_KIND_MISMATCH",
            message: "resource body does not match collection",
        });
    }
    let expected = if_match(&headers)?;
    let key = required_header(&headers, "idempotency-key")?;
    let resource = ControlResourceV1 {
        metadata: ResourceMetadataV1 {
            schema_version: CONTROL_SCHEMA_V1,
            id,
            tenant_id,
            revision: expected.checked_add(1).ok_or(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_REVISION",
                message: "revision is too large",
            })?,
            state: ResourceState::Active,
        },
        resource: body.resource,
    };
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "PUT",
        &format!("/v1/tenants/{tenant_id}/{collection}/{id}"),
        key,
        &resource,
    )?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: Some(expected),
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::OK))
}

pub async fn delete(
    State(state): State<Arc<ManagementState>>,
    principal: Option<Extension<AuthenticatedPrincipal>>,
    Path((tenant_id, collection, id)): Path<(Uuid, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let principal = principal.ok_or(ApiError::unauthorized())?.0;
    authorize_tenant(&principal, tenant_id, Action::WriteConfiguration)?;
    let kind = ResourceKind::parse_api_collection(&collection).ok_or(ApiError {
        status: StatusCode::NOT_FOUND,
        code: "UNKNOWN_RESOURCE",
        message: "resource collection is not supported",
    })?;
    let expected = if_match(&headers)?;
    let key = required_header(&headers, "idempotency-key")?;
    let repository = state.repository.as_ref().ok_or(ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "CONTROL_PLANE_UNAVAILABLE",
        message: "control plane storage is not configured",
    })?;
    let current = repository
        .get(tenant_id, kind, id)
        .await
        .map_err(ApiError::from_store)?;
    if current.metadata.revision != expected {
        return Err(ApiError::from_store(ControlStoreError::RevisionConflict));
    }
    let mut resource = current;
    resource.metadata.revision = expected.checked_add(1).ok_or(ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_REVISION",
        message: "revision is too large",
    })?;
    resource.metadata.state = ResourceState::Deleted;
    let context = mutation_context(
        &principal.actor_id,
        &headers,
        "DELETE",
        &format!("/v1/tenants/{tenant_id}/{collection}/{id}"),
        key,
        &resource,
    )?;
    let outcome = repository
        .mutate(
            &ResourceMutation {
                context,
                resource,
                expected_revision: Some(expected),
            },
            Utc::now(),
        )
        .await
        .map_err(ApiError::from_store)?;
    Ok(mutation_response(outcome, StatusCode::OK))
}

fn authorize_tenant(
    principal: &AuthenticatedPrincipal,
    tenant_id: Uuid,
    action: Action,
) -> Result<(), ApiError> {
    if principal.context.tenant_id != tenant_id
        || authorize(
            &principal.context,
            principal.context.organization_id,
            tenant_id,
            action,
        )
        .is_err()
    {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 160)
        .map(str::to_owned)
        .ok_or(ApiError {
            status: StatusCode::BAD_REQUEST,
            code: "MISSING_IDEMPOTENCY_KEY",
            message: "Idempotency-Key is required",
        })
}

fn if_match(headers: &HeaderMap) -> Result<u64, ApiError> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError {
            status: StatusCode::PRECONDITION_REQUIRED,
            code: "IF_MATCH_REQUIRED",
            message: "If-Match is required",
        })?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    value.parse().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_IF_MATCH",
        message: "If-Match must contain a numeric revision",
    })
}

fn mutation_context(
    actor_id: &str,
    _headers: &HeaderMap,
    method: &str,
    path: &str,
    key: String,
    resource: &ControlResourceV1,
) -> Result<MutationContext, ApiError> {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(path.as_bytes());
    hasher.update(serde_json::to_vec(resource).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "INVALID_REQUEST",
        message: "request cannot be serialized",
    })?);
    Ok(MutationContext {
        actor_id: actor_id.into(),
        idempotency_key: key,
        request_method: method.into(),
        request_path: path.into(),
        request_hash: hasher.finalize().into(),
        idempotency_replay_until: Utc::now() + Duration::hours(24),
    })
}

fn idempotent_resource_id(tenant_id: Uuid, actor_id: &str, key: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(actor_id.as_bytes());
    hasher.update(key.as_bytes());
    let mut bytes: [u8; 16] = hasher.finalize()[..16]
        .try_into()
        .expect("digest slice length");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn mutation_response(outcome: MutationOutcome, status: StatusCode) -> Response {
    let (replayed, resource) = match outcome {
        MutationOutcome::Applied(resource) => (false, resource),
        MutationOutcome::Replayed(resource) => (true, resource),
    };
    (
        if replayed { StatusCode::OK } else { status },
        Json(MutationResponse {
            schema_version: CONTROL_SCHEMA_V1,
            replayed,
            resource,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_match_accepts_numeric_etag_and_rejects_missing_or_weak_values() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            if_match(&headers),
            Err(ApiError {
                status: StatusCode::PRECONDITION_REQUIRED,
                ..
            })
        ));
        headers.insert(header::IF_MATCH, "\"7\"".parse().unwrap());
        assert_eq!(if_match(&headers).unwrap(), 7);
        headers.insert(header::IF_MATCH, "W/\"7\"".parse().unwrap());
        assert!(if_match(&headers).is_err());
    }

    #[test]
    fn resource_id_is_stable_for_idempotent_replay_and_actor_scoped() {
        let tenant = Uuid::new_v4();
        assert_eq!(
            idempotent_resource_id(tenant, "actor-a", "request-1"),
            idempotent_resource_id(tenant, "actor-a", "request-1")
        );
        assert_ne!(
            idempotent_resource_id(tenant, "actor-a", "request-1"),
            idempotent_resource_id(tenant, "actor-b", "request-1")
        );
    }
}
