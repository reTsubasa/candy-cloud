# Device certificate recovery

Device certificates last seven days. Runtime attempts renewal during the final
72 hours. Ordinary device routes require an active, currently valid certificate.
Only `/auth/v1/device-certificates/renew` accepts an otherwise active certificate
less than twelve hours expired. Revoked, future and older certificates are rejected.
Renewal reuses the operational key and atomically supersedes the old certificate;
a lost response may replay the same request for twelve hours.

## Web console

Open **节点 → 修复身份**, confirm the existing node and choose **生成修复文件**.
The one-time file expires in ten minutes. On an installed Linux server, run
`sudo candy-server bootstrap candy-node-bootstrap.json`; on OpenWrt, import the
file in **Candy → SD-WAN**. After issuance, return to the node list and verify
Cloud synchronization and data-plane health. Certificate issuance alone is not
proof that the data plane is online.

Recovery is explicitly bound to the existing node. It preserves the site,
attachments, segments, paths, egress, policy and Profile; it rotates credentials.
Use an authenticated tenant administrator; do not modify identity database rows
or remove local operational keys to bypass enrollment.

## TLS edge and deployment

The TLS edge must request a client certificate, prove possession during TLS and
forward its DER using an overwritten trusted header. Cloud-auth checks exact DER
against stored issued certificates and checks device/key/tenant status and time.
The auth service must remain inaccessible outside the internal network. Client
headers must never substitute for the TLS certificate placeholder.

The public HTTPS server certificate is a separate trust plane: use the deployment's
public certificate or persistent ACME storage. Do not mount the Device CA as the
HTTPS leaf certificate. Preserve deployment-specific Caddy hostnames, ACME storage
and certificate mounts when applying the client-auth change. The Cloud image
release does not itself update host-mounted Caddy configuration.

## Verification

Run the certificate renewal and enrollment completion integration tests with an
explicit disposable `DATABASE_URL`; without it those integration tests skip.
Coverage includes valid renewal, expired renewal, exact expiry grace boundary,
revoked/future/stale rejection, ordinary-route rejection, replay and atomic rollback.
The console tests/build must pass. Validate the effective Caddy configuration and
verify public HTTPS trust before triggering a node's sync service.
