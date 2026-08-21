-- Private TUN Grants require an explicit, complete quota. Older demo and
-- manually provisioned tenants used `{}`, which is correctly rejected by
-- cloud-auth as an invalid authorization snapshot and surfaced as HTTP 403.
-- Repair only empty/incomplete private TUN entitlements; never overwrite a
-- deliberately configured quota.
UPDATE entitlements
SET quota_json = JSON_OBJECT(
    'allowed_features', 1025,
    'max_outer_connections_per_node', 2,
    'max_outer_connections_per_pool', 4,
    'max_active_sessions_per_connection', 128,
    'max_udp_flows_per_connection', 256,
    'max_pending_opens', 32,
    'max_speculative_streams', 8,
    'max_datagram_record', 1200,
    'upload_rate_bps', 10000000,
    'download_rate_bps', 20000000
)
WHERE service_permission = 'private.tun.connect'
  AND status = 'ACTIVE'
  AND (
      JSON_LENGTH(quota_json) = 0
      OR JSON_EXTRACT(quota_json, '$.max_datagram_record') IS NULL
      OR JSON_EXTRACT(quota_json, '$.allowed_features') IS NULL
  );
