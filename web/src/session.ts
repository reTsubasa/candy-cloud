import type { Session, SessionClaims } from './types';

export const SESSION_KEY = 'candy.cloud.management.session.v1';

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  const bytes = Uint8Array.from(atob(normalized + padding), (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function parseJwtClaims(token: string): SessionClaims {
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new Error('JWT 必须包含 header、payload 和 signature 三部分');
  }
  try {
    const claims = JSON.parse(decodeBase64Url(parts[1])) as unknown;
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
      throw new Error('payload 不是对象');
    }
    return claims as SessionClaims;
  } catch {
    throw new Error('JWT payload 无法解析');
  }
}

export function createSession(token: string): Session {
  const normalized = token.trim();
  if (!normalized) throw new Error('请输入管理 JWT');
  return { token: normalized, claims: parseJwtClaims(normalized) };
}

export function loadSession(): Session | null {
  const token = sessionStorage.getItem(SESSION_KEY);
  if (!token) return null;
  try {
    return createSession(token);
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function saveSession(session: Session): void {
  sessionStorage.setItem(SESSION_KEY, session.token);
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
}

export function isSessionExpired(session: Session): boolean {
  return typeof session.claims.exp === 'number' && session.claims.exp * 1000 <= Date.now();
}
