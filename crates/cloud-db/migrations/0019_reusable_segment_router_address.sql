-- Revoked attachments are immutable publication history, not owners of a
-- current overlay address. Keep database-level uniqueness for attachments
-- that can own routes while allowing a replacement to reuse a revoked address.
ALTER TABLE segment_attachments
    DROP INDEX uq_segment_router_address,
    ADD COLUMN active_overlay_router_ipv4 BINARY(4)
        GENERATED ALWAYS AS (
            CASE
                WHEN state IN ('ACTIVE', 'STANDBY') THEN overlay_router_ipv4
                ELSE NULL
            END
        ) STORED AFTER overlay_router_ipv4,
    ADD UNIQUE KEY uq_active_segment_router_address
        (tenant_id, segment_id, active_overlay_router_ipv4),
    ADD INDEX idx_segment_router_address
        (tenant_id, segment_id, overlay_router_ipv4);
