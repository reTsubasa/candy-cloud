import { afterEach, describe, expect, it, vi } from 'vitest';
import { createNodeJoinCode, createResource, fetchHealth, listAccountSessions, listResources, requestEmailVerification, requestPasswordReset, resetAccountPassword, replaceResource, revokeAccountSession, verifyAccountEmail } from './api';
import { saveIdentitySession } from './session';

describe('same-origin Cloud API client', () => {
  afterEach(() => { vi.restoreAllMocks(); sessionStorage.clear(); });

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

  it('creates a single-use node join code with a ten-minute lifetime', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      id: 'join-code-id', credential: 'A'.repeat(43), expires_at: new Date().toISOString(),
    }), { status: 201, headers: { 'content-type': 'application/json' } }));
    await createNodeJoinCode('token', 'tenant');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/tenants/tenant/enrollment/activations', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ expires_in_seconds: 600 }),
    }));
  });

  it('reports real health response status and body', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('database schema unavailable', { status: 503 }));
    const state = await fetchHealth('ready');
    expect(state.status).toBe(503);
    expect(state.text).toBe('database schema unavailable');
  });

  it('consumes email verification through the same-origin identity path', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } }));
    await verifyAccountEmail('one-time-token');
    expect(fetchMock).toHaveBeenCalledWith('/identity/v1/auth/verify-email', expect.objectContaining({ method: 'POST', body: JSON.stringify({ token: 'one-time-token' }) }));
  });

  it('uses non-enumerating identity recovery endpoints', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ message: 'if_account_exists_email_sent' }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await requestEmailVerification('name@example.test', 'long-enough-password');
    await requestPasswordReset('name@example.test');
    await resetAccountPassword('reset-token', 'new-long-enough-password');
    expect(fetchMock.mock.calls[0][0]).toBe('/identity/v1/auth/request-email-verification');
    expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({ body: JSON.stringify({ email: 'name@example.test', password: 'long-enough-password' }) }));
    expect(fetchMock.mock.calls[1][0]).toBe('/identity/v1/auth/request-password-reset');
    expect(fetchMock.mock.calls[2][0]).toBe('/identity/v1/auth/reset-password');
  });

  it('lists and revokes account sessions with bearer authorization', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await listAccountSessions('access-token');
    await revokeAccountSession('access-token', 'session/id');
    expect(fetchMock.mock.calls[0]).toEqual(['/identity/v1/auth/sessions', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer access-token' }) })]);
    expect(fetchMock.mock.calls[1]).toEqual(['/identity/v1/auth/sessions/session%2Fid', expect.objectContaining({ method: 'DELETE', headers: expect.objectContaining({ Authorization: 'Bearer access-token' }) })]);
  });

  it('rotates a stored session once then retries a rejected management request', async () => {
    const encode = (value: unknown) => btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const token = (claims: Record<string, unknown>) => `${encode({ alg: 'EdDSA' })}.${encode(claims)}.signature`;
    saveIdentitySession({
      access_token: token({ tenant_id: 'tenant', exp: Math.floor(Date.now() / 1000) + 60 }), refresh_token: 'old-refresh-token', token_type: 'Bearer', expires_in: 60,
      user: { id: 'user', email: 'user@example.test', display_name: 'User', email_verified: true },
      membership: { organization_id: 'org', organization_name: 'Org', tenant_id: 'tenant', tenant_name: 'Tenant', role: 'TENANT_ADMIN' },
    });
    const fresh = token({ tenant_id: 'tenant', exp: Math.floor(Date.now() / 1000) + 900 });
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ code: 'unauthenticated' }), { status: 401, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: fresh, refresh_token: 'new-refresh-token', token_type: 'Bearer', expires_in: 900, user: { id: 'user', email: 'user@example.test', display_name: 'User', email_verified: true }, membership: { organization_id: 'org', organization_name: 'Org', tenant_id: 'tenant', tenant_name: 'Tenant', role: 'TENANT_ADMIN' } }), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ schema_version: 1, items: [], next_cursor: null }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await listResources('expired-access-token', 'tenant', 'sites');
    expect(fetchMock.mock.calls).toHaveLength(3);
    expect(fetchMock.mock.calls[2][1]).toEqual(expect.objectContaining({ headers: expect.objectContaining({ Authorization: `Bearer ${fresh}` }) }));
  });
});
