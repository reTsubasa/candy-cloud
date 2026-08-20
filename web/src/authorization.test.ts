import { describe, expect, it } from 'vitest';
import { capabilitiesForRole, roleLabel } from './authorization';

describe('web authorization capabilities', () => {
  it('keeps configuration mutation aligned with the Cloud API role matrix', () => {
    expect(capabilitiesForRole('ORGANIZATION_OWNER').writeConfiguration).toBe(true);
    expect(capabilitiesForRole('TENANT_ADMIN').writeConfiguration).toBe(true);
    expect(capabilitiesForRole('OPERATOR').writeConfiguration).toBe(true);
    expect(capabilitiesForRole('BILLING_VIEWER').writeConfiguration).toBe(false);
    expect(capabilitiesForRole('AUDITOR').writeConfiguration).toBe(false);
  });

  it('limits membership management to the organization owner', () => {
    expect(capabilitiesForRole('ORGANIZATION_OWNER').manageMembers).toBe(true);
    expect(capabilitiesForRole('TENANT_ADMIN').manageMembers).toBe(false);
    expect(capabilitiesForRole('AUDITOR').readMembers).toBe(true);
  });

  it('fails closed for missing or unknown roles', () => {
    expect(capabilitiesForRole(undefined)).toEqual(expect.objectContaining({
      readConfiguration: false,
      writeConfiguration: false,
      manageDevices: false,
    }));
    expect(roleLabel('AUDITOR')).toBe('审计员');
  });
});
