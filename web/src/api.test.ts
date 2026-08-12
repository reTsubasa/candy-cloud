import { afterEach, describe, expect, it, vi } from 'vitest';
import { createResource, fetchHealth, listResources, replaceResource } from './api';

describe('same-origin Cloud API client', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses the /api management path with bearer and pagination headers', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ schema_version: 1, items: [], next_cursor: null }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await listResources('jwt-token', 'tenant-id', 'sites');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/tenants/tenant-id/sites', expect.objectContaining({
      credentials: 'same-origin',
      headers: expect.objectContaining({ Authorization: 'Bearer jwt-token', 'X-Page-Size': '200' }),
    }));
  });

  it('adds idempotency and revision headers for writes', async () => {
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('00000000-0000-4000-8000-000000000001');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ schema_version: 1, replayed: false, resource: {} }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await createResource('token', 'tenant', 'sites', { kind: 'SITE', spec: { name: 'A', kind: 'EDGE' } });
    await replaceResource('token', 'tenant', 'sites', 'site-id', 7, { kind: 'SITE', spec: { name: 'B', kind: 'EDGE' } });
    expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'Idempotency-Key': '00000000-0000-4000-8000-000000000001' }) }));
    expect(fetchMock.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'PUT', headers: expect.objectContaining({ 'If-Match': '7' }) }));
  });

  it('reports real health response status and body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('database schema unavailable', { status: 503 }));
    const state = await fetchHealth('ready');
    expect(state.status).toBe(503);
    expect(state.text).toBe('database schema unavailable');
  });
});
