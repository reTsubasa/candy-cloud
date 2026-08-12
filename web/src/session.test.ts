import { beforeEach, describe, expect, it } from 'vitest';
import { clearSession, createSession, loadSession, parseJwtClaims, saveSession, SESSION_KEY } from './session';

function encode(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function token(claims: Record<string, unknown>): string {
  return `${encode({ alg: 'EdDSA', typ: 'JWT' })}.${encode(claims)}.signature`;
}

describe('management session', () => {
  beforeEach(() => sessionStorage.clear());

  it('parses display claims without treating them as authorization', () => {
    const claims = parseJwtClaims(token({ sub: 'operator-1', tenant_id: 'tenant-1', role: 'TENANT_ADMIN' }));
    expect(claims.sub).toBe('operator-1');
    expect(claims.tenant_id).toBe('tenant-1');
    expect(claims.role).toBe('TENANT_ADMIN');
  });

  it('persists the token only in sessionStorage', () => {
    const session = createSession(token({ tenant_id: 'tenant-1' }));
    saveSession(session);
    expect(sessionStorage.getItem(SESSION_KEY)).toBe(session.token);
    expect(localStorage.getItem(SESSION_KEY)).toBeNull();
    expect(loadSession()?.token).toBe(session.token);
    clearSession();
    expect(loadSession()).toBeNull();
  });

  it('rejects malformed JWT values', () => {
    expect(() => createSession('not-a-jwt')).toThrow(/JWT/);
  });
});
