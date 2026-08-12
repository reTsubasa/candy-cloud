import type { IdentitySessionResponse, Session, SessionClaims } from './types';

export const SESSION_KEY = 'candy.cloud.management.session.v1';
export const REFRESH_SESSION_KEY = 'candy.cloud.management.refresh.v1';
export const IDENTITY_CONTEXT_KEY = 'candy.cloud.management.identity.v1';

type IdentityContext = Pick<IdentitySessionResponse, 'user' | 'membership'>;

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
    const session = createSession(token);
    const encodedContext = sessionStorage.getItem(IDENTITY_CONTEXT_KEY);
    if (!encodedContext) return session;
    const context = JSON.parse(encodedContext) as IdentityContext;
    return { ...session, user: context.user, membership: context.membership };
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(IDENTITY_CONTEXT_KEY);
    return null;
  }
}

export function saveSession(session: Session): void {
  sessionStorage.setItem(SESSION_KEY, session.token);
}

export function saveIdentitySession(session: IdentitySessionResponse): Session {
  const management = { ...createSession(session.access_token), user: session.user, membership: session.membership };
  sessionStorage.setItem(SESSION_KEY, management.token);
  sessionStorage.setItem(REFRESH_SESSION_KEY, session.refresh_token);
  sessionStorage.setItem(IDENTITY_CONTEXT_KEY, JSON.stringify({ user: session.user, membership: session.membership }));
  return management;
}

export function loadRefreshToken(): string | null {
  return sessionStorage.getItem(REFRESH_SESSION_KEY);
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(REFRESH_SESSION_KEY);
  sessionStorage.removeItem(IDENTITY_CONTEXT_KEY);
}

export function isSessionExpired(session: Session): boolean {
  return typeof session.claims.exp === 'number' && session.claims.exp * 1000 <= Date.now();
}

export function isSessionExpiringSoon(session: Session, skewMs = 60_000): boolean {
  return typeof session.claims.exp === 'number' && session.claims.exp * 1000 <= Date.now() + skewMs;
}
