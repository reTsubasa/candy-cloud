import { clearSession, loadRefreshToken, loadSession, saveIdentitySession } from './session';
import type {
  ApiErrorBody,
  ControlResource,
  EndpointHealth,
  MutationResponse,
  ResourceListResponse,
  ResourceSpec,
  IdentitySessionResponse,
  IdentityRegistrationResponse,
  IdentityMessageResponse,
  HumanSession,
  IdentityMembership,
  OrganizationMember,
  EnrollmentActivation,
  EnrollmentActivationSecret,
  RuntimeActivationReadiness,
  RuntimeConfigurationStatusResponse,
  AuditEventResponse,
  RuntimeTelemetryResponse,
  CloudVersionInfo,
  ResourceReferenceListResponse,
} from './types';

export class CloudApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly details?: ApiErrorBody,
  ) {
    super(message);
  }
}

export async function fetchCloudVersion(): Promise<CloudVersionInfo> {
  const response = await fetch('/api/version', {
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw await responseError(response);
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
    throw new CloudApiError('无法读取产品版本信息', response.status, 'INVALID_RESPONSE_FORMAT');
  }
  return response.json() as Promise<CloudVersionInfo>;
}

async function identityRequest<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`/identity${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...init.headers },
  });
  if (!response.ok) throw await responseError(response);
  if (response.status === 204) return undefined as T;
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
    throw new CloudApiError('服务返回格式异常，请稍后重试并查看系统状态', response.status, 'INVALID_RESPONSE_FORMAT');
  }
  return response.json() as Promise<T>;
}

export function registerAccount(input: {
  email: string;
  password: string;
  display_name: string;
  organization_name: string;
}): Promise<IdentityRegistrationResponse> {
  return identityRequest('/v1/auth/register', { method: 'POST', body: JSON.stringify(input) });
}

export function loginAccount(email: string, password: string): Promise<IdentitySessionResponse> {
  return identityRequest('/v1/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
}

export function verifyAccountEmail(token: string): Promise<IdentitySessionResponse> {
  return identityRequest('/v1/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) });
}

export function requestEmailVerification(email: string, password: string): Promise<IdentityMessageResponse> {
  return identityRequest('/v1/auth/request-email-verification', { method: 'POST', body: JSON.stringify({ email, password }) });
}

export function requestPasswordReset(email: string): Promise<IdentityMessageResponse> {
  return identityRequest('/v1/auth/request-password-reset', { method: 'POST', body: JSON.stringify({ email }) });
}

export function resetAccountPassword(token: string, password: string): Promise<IdentityMessageResponse> {
  return identityRequest('/v1/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) });
}

export function refreshAccountSession(refresh_token: string): Promise<IdentitySessionResponse> {
  return identityRequest('/v1/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token }) });
}

export function logoutAccount(accessToken: string): Promise<void> {
  return authenticatedIdentityRequest<unknown>('/v1/auth/logout', accessToken, {
    method: 'POST',
  }).then(() => undefined);
}

export function listAccountSessions(accessToken: string): Promise<HumanSession[]> {
  return authenticatedIdentityRequest('/v1/auth/sessions', accessToken);
}

export function revokeAccountSession(accessToken: string, sessionId: string): Promise<void> {
  return authenticatedIdentityRequest<unknown>(`/v1/auth/sessions/${encodeURIComponent(sessionId)}`, accessToken, {
    method: 'DELETE',
  }).then(() => undefined);
}

export function listAccountMemberships(accessToken: string): Promise<IdentityMembership[]> {
  return authenticatedIdentityRequest('/v1/auth/memberships', accessToken);
}

export function switchAccountContext(accessToken: string, organizationId: string): Promise<IdentitySessionResponse> {
  return authenticatedIdentityRequest('/v1/auth/switch-context', accessToken, {
    method: 'POST',
    body: JSON.stringify({ organization_id: organizationId }),
  });
}

export function acceptOrganizationInvitation(accessToken: string, token: string): Promise<IdentityMessageResponse> {
  return authenticatedIdentityRequest('/v1/auth/invitations/accept', accessToken, {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
}

export function registerFromOrganizationInvitation(token: string, displayName: string, password: string): Promise<IdentitySessionResponse> {
  return identityRequest('/v1/auth/invitations/register', {
    method: 'POST',
    body: JSON.stringify({ token, display_name: displayName, password }),
  });
}

export function listOrganizationMembers(accessToken: string): Promise<OrganizationMember[]> {
  return authenticatedIdentityRequest('/v1/organization/members', accessToken);
}

export function inviteOrganizationMember(accessToken: string, email: string, role: string): Promise<IdentityMessageResponse> {
  return authenticatedIdentityRequest('/v1/organization/members', accessToken, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export function updateOrganizationMemberRole(accessToken: string, memberId: string, role: string): Promise<void> {
  return authenticatedIdentityRequest<unknown>(`/v1/organization/members/${encodeURIComponent(memberId)}/role`, accessToken, {
    method: 'PUT',
    body: JSON.stringify({ role }),
  }).then(() => undefined);
}

export function updateOrganizationMemberStatus(accessToken: string, memberId: string, active: boolean): Promise<void> {
  return authenticatedIdentityRequest<unknown>(`/v1/organization/members/${encodeURIComponent(memberId)}/status`, accessToken, {
    method: 'PUT',
    body: JSON.stringify({ active }),
  }).then(() => undefined);
}

export function removeOrganizationMember(accessToken: string, memberId: string): Promise<void> {
  return authenticatedIdentityRequest<unknown>(`/v1/organization/members/${encodeURIComponent(memberId)}`, accessToken, {
    method: 'DELETE',
  }).then(() => undefined);
}

export function transferOrganizationOwnership(accessToken: string, userId: string): Promise<void> {
  return authenticatedIdentityRequest<unknown>('/v1/organization/ownership', accessToken, {
    method: 'POST',
    body: JSON.stringify({ user_id: userId }),
  }).then(() => undefined);
}

async function authenticatedIdentityRequest<T>(path: string, accessToken: string, init: RequestInit = {}): Promise<T> {
  try {
    const currentToken = loadSession()?.token ?? accessToken;
    return await identityRequest(path, { ...init, headers: { Authorization: `Bearer ${currentToken}`, ...init.headers } });
  } catch (error) {
    if (!(error instanceof CloudApiError) || error.status !== 401) throw error;
    const refreshed = await refreshStoredSession();
    if (!refreshed) throw error;
    return identityRequest(path, { ...init, headers: { Authorization: `Bearer ${refreshed}`, ...init.headers } });
  }
}

async function responseError(response: Response): Promise<CloudApiError> {
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    const body = (await response.json().catch(() => ({}))) as ApiErrorBody;
    return new CloudApiError(body.message ?? `请求失败 (${response.status})`, response.status, body.code, body);
  }
  const text = await response.text().catch(() => '');
  return new CloudApiError(text || `请求失败 (${response.status})`, response.status);
}

async function requestJson<T>(path: string, token: string, init: RequestInit = {}, timeoutMs = 15_000): Promise<T> {
  const controller = init.signal ? null : new AbortController();
  const timeout = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  const perform = (accessToken: string) => fetch(`/api${path}`, {
    ...init,
    credentials: 'same-origin',
    signal: init.signal ?? controller?.signal,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
      ...init.headers,
    },
  });
  try {
    let response = await perform(token);
    if (response.status === 401) {
      const refreshed = await refreshStoredSession();
      if (refreshed) response = await perform(refreshed);
    }
    if (!response.ok) throw await responseError(response);
    if (response.status === 204) return undefined as T;
    if (!(response.headers.get('content-type') ?? '').includes('application/json')) {
      throw new CloudApiError('服务返回格式异常，请稍后重试并查看系统状态', response.status, 'INVALID_RESPONSE_FORMAT');
    }
    return response.json() as Promise<T>;
  } catch (reason) {
    if (reason instanceof DOMException && reason.name === 'AbortError') {
      throw new CloudApiError('请求超时，Cloud 暂时没有响应。请稍后重试。', 504, 'REQUEST_TIMEOUT');
    }
    throw reason;
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

let refreshInFlight: Promise<string | null> | null = null;

export function refreshStoredSession(): Promise<string | null> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    const refresh = loadRefreshToken();
    if (!refresh) return null;
    try {
      return saveIdentitySession(await refreshAccountSession(refresh)).token;
    } catch {
      clearSession();
      return null;
    }
  })().finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}

export async function fetchHealth(endpoint: 'live' | 'ready' | 'degraded'): Promise<EndpointHealth> {
  const checkedAt = Date.now();
  try {
    const response = await fetch(`/api/health/${endpoint}`, {
      credentials: 'same-origin',
      headers: { Accept: 'text/plain' },
    });
    return {
      status: response.status,
      text: (await response.text()) || response.statusText,
      loading: false,
      checkedAt,
    };
  } catch (error) {
    return {
      status: null,
      text: error instanceof Error ? error.message : '网络请求失败',
      loading: false,
      checkedAt,
    };
  }
}

function collectionPath(tenantId: string, collection: string): string {
  return `/v1/tenants/${encodeURIComponent(tenantId)}/${encodeURIComponent(collection)}`;
}

export function listResources(
  token: string,
  tenantId: string,
  collection: string,
  after?: string | null,
): Promise<ResourceListResponse> {
  return requestJson(collectionPath(tenantId, collection), token, {
    headers: {
      'X-Page-Size': '200',
      ...(after ? { 'X-Page-After': after } : {}),
    },
  });
}

export async function listAllResources(
  token: string,
  tenantId: string,
  collection: string,
  maximum = 4096,
): Promise<ControlResource[]> {
  const items: ControlResource[] = [];
  const cursors = new Set<string>();
  const maximumPages = Math.ceil(maximum / 200) + 1;
  let pageCount = 0;
  let after: string | null = null;
  do {
    pageCount += 1;
    if (pageCount > maximumPages) {
      throw new CloudApiError('资源分页超过运营视图的安全上限', 502, 'RESOURCE_PAGE_LIMIT_EXCEEDED');
    }
    const page = await listResources(token, tenantId, collection, after);
    items.push(...page.items);
    if (items.length > maximum) {
      throw new CloudApiError('资源数量超过运营视图的安全上限', 422, 'RESOURCE_INVENTORY_LIMIT_EXCEEDED');
    }
    after = page.next_cursor;
    if (after && cursors.has(after)) {
      throw new CloudApiError('资源分页游标重复，无法生成完整拓扑', 502, 'INVALID_PAGE_CURSOR_LOOP');
    }
    if (after) cursors.add(after);
  } while (after);
  return items;
}

export function fetchRuntimeActivationReadiness(
  token: string,
  tenantId: string,
  segmentId: string,
): Promise<RuntimeActivationReadiness> {
  return requestJson(
    `/v1/tenants/${encodeURIComponent(tenantId)}/runtime-activation-readiness?segment_id=${encodeURIComponent(segmentId)}`,
    token,
    {},
    8_000,
  );
}

export function fetchRuntimeConfigurationStatuses(
  token: string,
  tenantId: string,
): Promise<RuntimeConfigurationStatusResponse> {
  return requestJson(`/v1/tenants/${encodeURIComponent(tenantId)}/runtime-configuration-status`, token);
}

export async function fetchRuntimeTelemetry(
  token: string,
  tenantId: string,
): Promise<RuntimeTelemetryResponse> {
  const response = await requestJson<RuntimeTelemetryResponse>(
    `/v1/tenants/${encodeURIComponent(tenantId)}/runtime-telemetry`,
    token,
  );
  return {
    ...response,
    items: response.items.map((item) => ({
      ...item,
      paths: item.paths ?? [],
      local_networks: item.local_networks ?? [],
    })),
  };
}

export function listAuditEvents(token: string, tenantId: string, limit = 500): Promise<AuditEventResponse> {
  return requestJson(`/v1/tenants/${encodeURIComponent(tenantId)}/audit-events?limit=${limit}&include_routine=false`, token);
}

export function getResource(token: string, tenantId: string, collection: string, id: string): Promise<ControlResource> {
  return requestJson(`${collectionPath(tenantId, collection)}/${encodeURIComponent(id)}`, token);
}

export function createResource(
  token: string,
  tenantId: string,
  collection: string,
  resource: ResourceSpec,
): Promise<MutationResponse> {
  return requestJson(collectionPath(tenantId, collection), token, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': crypto.randomUUID(),
    },
    body: JSON.stringify({ resource }),
  });
}

export function replaceResource(
  token: string,
  tenantId: string,
  collection: string,
  id: string,
  revision: number,
  resource: ResourceSpec,
): Promise<MutationResponse> {
  return requestJson(`${collectionPath(tenantId, collection)}/${encodeURIComponent(id)}`, token, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': crypto.randomUUID(),
      'If-Match': String(revision),
    },
    body: JSON.stringify({ resource }),
  });
}

export function deleteResource(
  token: string,
  tenantId: string,
  collection: string,
  id: string,
  revision: number,
): Promise<MutationResponse> {
  return requestJson(`${collectionPath(tenantId, collection)}/${encodeURIComponent(id)}`, token, {
    method: 'DELETE',
    headers: {
      'Idempotency-Key': crypto.randomUUID(),
      'If-Match': String(revision),
    },
  });
}

export function listResourceReferences(
  token: string,
  tenantId: string,
  collection: string,
  id: string,
): Promise<ResourceReferenceListResponse> {
  return requestJson(`${collectionPath(tenantId, collection)}/${encodeURIComponent(id)}/references`, token);
}

export function listNodeJoinCodes(token: string, tenantId: string): Promise<EnrollmentActivation[]> {
  return requestJson(`/v1/tenants/${encodeURIComponent(tenantId)}/enrollment/activations`, token);
}

export function createNodeJoinCode(
  token: string,
  tenantId: string,
  expiresInSeconds = 600,
  intent?: { site_id: string; display_name: string; platform: 'OPEN_WRT' | 'LINUX'; architecture: string; replace_node_id?: string },
): Promise<EnrollmentActivationSecret> {
  return requestJson(`/v1/tenants/${encodeURIComponent(tenantId)}/enrollment/activations`, token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ expires_in_seconds: expiresInSeconds, ...intent }),
  });
}

export function revokeNodeJoinCode(token: string, tenantId: string, activationId: string): Promise<void> {
  return requestJson<unknown>(
    `/v1/tenants/${encodeURIComponent(tenantId)}/enrollment/activations/${encodeURIComponent(activationId)}`,
    token,
    { method: 'DELETE' },
  ).then(() => undefined);
}
