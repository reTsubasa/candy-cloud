import type {
  ApiErrorBody,
  ControlResource,
  EndpointHealth,
  MutationResponse,
  ResourceListResponse,
  ResourceSpec,
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
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
      ...init.headers,
    },
  });
  if (!response.ok) throw await responseError(response);
  return response.json() as Promise<T>;
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
