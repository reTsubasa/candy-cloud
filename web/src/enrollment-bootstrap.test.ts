import { describe, expect, it } from 'vitest';
import { buildEnrollmentBootstrap, buildEnrollmentInstallCommand, enrollmentExpired, validCloudAddress } from './enrollment-bootstrap';

const secret = {
  id: '00000000-0000-4000-8000-000000000001',
  credential: 'one-time-credential',
  expires_at: '2026-08-14T12:00:00Z',
};

describe('enrollment bootstrap', () => {
  it('contains only the bootstrap exchange inputs', () => {
    const document = JSON.parse(buildEnrollmentBootstrap({
      secret,
      cloudAddress: 'https://cloud.example.com/',
    }));
    expect(document).toEqual({ schema_version: 1, cloud_address: 'https://cloud.example.com', bootstrap_code: 'one-time-credential', expires_at: secret.expires_at });
    expect(document).not.toHaveProperty('site_id');
    expect(document).not.toHaveProperty('activation_credential');
  });

  it('only allows HTTPS except for local development', () => {
    expect(validCloudAddress('https://cloud.example.com')).toBe(true);
    expect(validCloudAddress('http://localhost:8088')).toBe(false);
    expect(validCloudAddress('http://cloud.example.com')).toBe(false);
    expect(validCloudAddress('not-a-url')).toBe(false);
  });

  it('recognizes expired and malformed enrollment deadlines', () => {
    expect(enrollmentExpired('2026-08-14T12:00:00Z', Date.parse('2026-08-14T11:59:59Z'))).toBe(false);
    expect(enrollmentExpired('2026-08-14T12:00:00Z', Date.parse('2026-08-14T12:00:00Z'))).toBe(true);
    expect(enrollmentExpired('not-a-date', Date.now())).toBe(true);
  });

  it('builds a single install command without piping a network response into a shell', () => {
    const command = buildEnrollmentInstallCommand({
      cloudAddress: 'https://cloud.example.test',
      secret: {
        id: 'activation-1',
        credential: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        expires_at: '2030-01-01T00:00:00Z',
      },
    });

    expect(command).toContain("https://cloud.example.test/install/candy-node.sh");
    expect(command).toContain("--proto '=https'");
    expect(command).toContain("--proto-redir '=https'");
    expect(command).toContain('--bootstrap-base64-stdin');
    expect(command).toContain('mktemp');
    expect(command).not.toMatch(/curl[^&|]*\|\s*(sudo\s+)?sh/);
    expect(command).not.toContain('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  });
});
