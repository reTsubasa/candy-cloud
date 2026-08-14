export type EnrollmentPlatform = 'OPEN_WRT' | 'LINUX_SERVER';

const openWrtArchitectures = [
  { label: 'x86-64', value: 'x86_64' },
  { label: 'ARMv7 / IPQ40xx', value: 'armv7' },
];

const linuxArchitectures = [
  { label: 'x86-64', value: 'x86_64' },
  { label: 'ARM64 / aarch64', value: 'aarch64' },
];

export function enrollmentArchitectureOptions(platform: EnrollmentPlatform) {
  return platform === 'OPEN_WRT' ? openWrtArchitectures : linuxArchitectures;
}

export function defaultEnrollmentArchitecture(platform: EnrollmentPlatform): string {
  return enrollmentArchitectureOptions(platform)[0].value;
}

export function compatibleEnrollmentArchitecture(platform: EnrollmentPlatform, architecture: string): string {
  const available = enrollmentArchitectureOptions(platform);
  return available.some((option) => option.value === architecture) ? architecture : available[0].value;
}
