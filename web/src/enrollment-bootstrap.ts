import type { EnrollmentActivationSecret } from './types';

type BootstrapDownload = {
  secret: EnrollmentActivationSecret;
  cloudAddress: string;
};

export function validCloudAddress(value: string): boolean {
  try {
    const url = new URL(value.trim());
    return url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function enrollmentExpired(expiresAt: string, now = Date.now()): boolean {
  const expiry = Date.parse(expiresAt);
  return !Number.isFinite(expiry) || expiry <= now;
}

export function buildEnrollmentBootstrap(input: BootstrapDownload): string {
  return JSON.stringify({
    schema_version: 1,
    cloud_address: input.cloudAddress.trim().replace(/\/$/, ''),
    bootstrap_code: input.secret.credential,
    expires_at: input.secret.expires_at,
  }, null, 2) + '\n';
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function base64Utf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

export function buildEnrollmentInstallCommand(input: BootstrapDownload): string {
  const installerUrl = new URL('/install/candy-node.sh', input.cloudAddress).toString();
  const bootstrap = base64Utf8(buildEnrollmentBootstrap(input));
  return `candy_installer="$(mktemp)" && trap 'rm -f "$candy_installer"' EXIT && curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 ${shellQuote(installerUrl)} -o "$candy_installer" && chmod 0700 "$candy_installer" && printf '%s' ${shellQuote(bootstrap)} | sudo "$candy_installer" --bootstrap-base64-stdin`;
}

export function downloadEnrollmentBootstrap(input: BootstrapDownload): void {
  const blob = new Blob([buildEnrollmentBootstrap(input)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'candy-node-bootstrap.json';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
