CREATE TEMPORARY TABLE sdwan_trial_datagram_refresh_segments (
    tenant_id BINARY(16) NOT NULL,
    segment_id BINARY(16) NOT NULL,
    desired_revision BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (tenant_id, segment_id)
) ENGINE=InnoDB;

INSERT INTO sdwan_trial_datagram_refresh_segments (tenant_id, segment_id, desired_revision)
SELECT DISTINCT head.tenant_id, head.segment_id, head.desired_revision + 1
FROM segment_generation_heads head
JOIN segments segment
  ON segment.tenant_id = head.tenant_id
 AND segment.id = head.segment_id
 AND segment.state = 'ACTIVE'
JOIN subscriptions subscription
  ON subscription.tenant_id = head.tenant_id
 AND subscription.plan_code = 'sdwan-trial'
 AND subscription.status IN ('TRIAL', 'ACTIVE')
JOIN entitlements entitlement
  ON entitlement.tenant_id = subscription.tenant_id
 AND entitlement.subscription_id = subscription.id
 AND entitlement.node_pool_id = segment.hub_node_pool_id
 AND entitlement.service_permission = 'private.tun.connect'
 AND entitlement.status = 'ACTIVE'
WHERE CAST(JSON_UNQUOTE(JSON_EXTRACT(entitlement.quota_json, '$.max_datagram_record')) AS UNSIGNED) = 1200;

-- A 1,300-byte production inner MTU needs up to 50 bytes for the complete Candy IP-packet
-- record when every variable-length field uses its worst-case encoding.
UPDATE entitlements entitlement
JOIN subscriptions subscription
  ON subscription.id = entitlement.subscription_id
 AND subscription.tenant_id = entitlement.tenant_id
SET entitlement.quota_json = JSON_SET(
    entitlement.quota_json,
    '$.max_datagram_record', 1350
)
WHERE subscription.plan_code = 'sdwan-trial'
  AND subscription.status IN ('TRIAL', 'ACTIVE')
  AND entitlement.service_permission = 'private.tun.connect'
  AND entitlement.status = 'ACTIVE'
  AND CAST(JSON_UNQUOTE(JSON_EXTRACT(entitlement.quota_json, '$.max_datagram_record')) AS UNSIGNED) = 1200;

UPDATE segment_generation_heads head
JOIN sdwan_trial_datagram_refresh_segments refresh
  ON refresh.tenant_id = head.tenant_id
 AND refresh.segment_id = head.segment_id
SET head.desired_revision = refresh.desired_revision;

INSERT INTO segment_generation_jobs (
    id,
    tenant_id,
    segment_id,
    desired_revision,
    idempotency_hash
)
SELECT
    UUID_TO_BIN(UUID()),
    refresh.tenant_id,
    refresh.segment_id,
    refresh.desired_revision,
    UNHEX(SHA2(CONCAT(
        'candy/sdwan-trial-datagram-capacity-v1/',
        HEX(refresh.tenant_id),
        '/',
        HEX(refresh.segment_id),
        '/',
        refresh.desired_revision
    ), 256))
FROM sdwan_trial_datagram_refresh_segments refresh;

DROP TEMPORARY TABLE sdwan_trial_datagram_refresh_segments;
