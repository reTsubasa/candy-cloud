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
} from './types';

export class CloudApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message);
  }
}

async function identityRequest<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(`/identity${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...init.headers },
  });
  if (!response.ok) throw await responseError(response);
  if (response.status === 204) return undefined as T;
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
    return new CloudApiError(body.message ?? `请求失败 (${response.status})`, response.status, body.code);
  }
  const text = await response.text().catch(() => '');
  return new CloudApiError(text || `请求失败 (${response.status})`, response.status);
}

async function requestJson<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const perform = (accessToken: string) => fetch(`/api${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
      ...init.headers,
    },
  });
  let response = await perform(token);
  if (response.status === 401) {
    const refreshed = await refreshStoredSession();
    if (refreshed) response = await perform(refreshed);
  }
  if (!response.ok) throw await responseError(response);
  return response.json() as Promise<T>;
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
