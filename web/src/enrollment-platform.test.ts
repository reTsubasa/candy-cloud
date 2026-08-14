import { describe, expect, it } from 'vitest';
import {
  compatibleEnrollmentArchitecture,
  defaultEnrollmentArchitecture,
  enrollmentArchitectureOptions,
} from './enrollment-platform';

describe('enrollment platform architecture support', () => {
  it('only exposes architectures backed by current OpenWrt releases', () => {
    expect(enrollmentArchitectureOptions('OPEN_WRT').map((item) => item.value)).toEqual(['x86_64', 'armv7']);
  });

  it('only exposes architectures backed by current Linux bundles', () => {
    expect(enrollmentArchitectureOptions('LINUX_SERVER').map((item) => item.value)).toEqual(['x86_64', 'aarch64']);
  });

  it('replaces an incompatible architecture after platform changes', () => {
    expect(compatibleEnrollmentArchitecture('OPEN_WRT', 'aarch64')).toBe(defaultEnrollmentArchitecture('OPEN_WRT'));
    expect(compatibleEnrollmentArchitecture('LINUX_SERVER', 'armv7')).toBe(defaultEnrollmentArchitecture('LINUX_SERVER'));
  });
});
